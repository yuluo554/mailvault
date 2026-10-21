"""DKIM 验签（M3）：规范化、零依赖 RSA、五类失败、多签名不短路、`undecidable` 语义。

测试分四层，每层回答一个不同的问题：

1. **RFC 原文给定的期望值**（§3.4.5 的三个规范化示例、§3.4.3/§3.4.4 的空正文哈希）。
   这类断言不依赖任何实现——RFC 原文就是真值。它们锁的是"规范化写对了"。
2. **fixture 逐条对账**（`fixtures/dkim/*/expected.json`）。锁的是"输入 → 结论"这条链路。
3. **参照实现对账**（`cryptography`，仅测试期）。锁的是"零依赖 RSA 与成熟实现一致"。
4. **反自证 / 结构性断言**。锁的是"这套测试自己不会永远绿"：正样本必须存在、
   多签名必须逐条、运行时不许 import 参照实现。

第 4 层不是形式主义：**只有负样本的 fixture 集会放过一个永远返回 fail 的实现**，
而第 2 层若只断言 fail 类样本，恰好就是那种 fixture 集。
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
from pathlib import Path

import pytest

from mailvault import eml
from mailvault.constants import DKIM_MIN_KEY_BITS, RESULTS
from mailvault.crypto.der import ENCODING_RSAPUBLICKEY, ENCODING_SPKI, DerError, \
    parse_rsa_public_key
from mailvault.crypto.rsa import (
    SignatureMismatch,
    digest_info,
    emsa_pkcs1_v15_encode,
    verify_pkcs1_v15,
)
from mailvault.modules.dkim import (
    canonicalize_body,
    canonicalize_header,
    parse_tag_list,
    verify_message,
)
from mailvault.snapshot import from_dict, load_snapshot

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_ROOT = REPO_ROOT / "fixtures" / "dkim"


# ── 夹具小工具 ──────────────────────────────────────────────────────────


def _snapshot(queries):
    return from_dict({
        "schema_version": 1,
        "fetched_at": "2026-10-19T18:35:00Z",
        "resolver": "synthetic",
        "psl_version": "2026-10-20_08-40-56_UTC",
        "psl_date": "2026-10-20",
        "queries": queries,
    })


def _q(qname, answer, *, qtype="TXT", rcode="NOERROR"):
    return {"qname": qname, "qtype": qtype, "rcode": rcode,
            "answer": list(answer), "ttl": 300}


def _fixture_cases():
    return sorted(
        path for path in FIXTURE_ROOT.iterdir()
        if path.is_dir() and (path / "expected.json").is_file()
    )


def _run_fixture(directory: Path):
    raw = (directory / "message.eml").read_bytes()
    snap = load_snapshot(directory / "snap.json")
    message = eml.parse(raw)
    return message, snap, verify_message(message, snap)


# ═══ 第 1 层：RFC 原文给定的期望值 ═══════════════════════════════════════


def test_rfc6376_empty_body_hashes_match_published_vectors():
    """RFC 6376 §3.4.3 / §3.4.4 各自给出了空正文的基准哈希。

    这两个值不对称（simple 是 2 字节 CRLF，relaxed 是 0 字节），
    所以它们能同时证明两条规范化路径**没有互相抄**。
    """
    simple = canonicalize_body(b"", "simple")
    relaxed = canonicalize_body(b"", "relaxed")

    assert simple == b"\r\n"
    assert relaxed == b""

    assert base64.b64encode(hashlib.sha256(simple).digest()).decode() == \
        "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="
    assert base64.b64encode(hashlib.sha256(relaxed).digest()).decode() == \
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="


RFC_345_EXAMPLE = (
    b"A: X\r\n"
    b"B : Y\t\r\n"
    b"\tZ  \r\n"
    b"\r\n"
    b" C \r\n"
    b"D \t E \r\n"
    b"\r\n"
    b"\r\n"
)


def test_rfc6376_3_4_5_example1_relaxed_both():
    """RFC 6376 §3.4.5 Example 1：relaxed 头 + relaxed 正文。

    头期望 ``a:X <CRLF>`` / ``b:Y <SP> Z <CRLF>``；
    正文期望 ``<SP> C <CRLF>`` / ``D<SP>E <CRLF>``。
    """
    message = eml.parse(RFC_345_EXAMPLE)
    fields = message.header_fields()

    headers = [canonicalize_header(name, value, "relaxed") for name, value in fields]
    assert headers == [b"a:X\r\n", b"b:Y Z\r\n"]

    assert canonicalize_body(message.body_crlf, "relaxed") == b" C\r\nD E\r\n"


def test_rfc6376_3_4_5_example2_simple_both():
    """§3.4.5 Example 2：simple 头**一个字节都不改**（含大小写与折行）。"""
    message = eml.parse(RFC_345_EXAMPLE)
    fields = message.header_fields()

    headers = [canonicalize_header(name, value, "simple") for name, value in fields]
    assert headers == [
        b"A: X\r\n",
        b"B : Y\t\r\n\tZ  \r\n",
    ]
    assert canonicalize_body(message.body_crlf, "simple") == b" C \r\nD \t E \r\n"


def test_rfc6376_3_4_5_example3_relaxed_header_simple_body():
    """§3.4.5 Example 3：relaxed 头 + simple 正文（两种组合可以混用）。"""
    message = eml.parse(RFC_345_EXAMPLE)
    fields = message.header_fields()

    assert [canonicalize_header(n, v, "relaxed") for n, v in fields] == \
        [b"a:X\r\n", b"b:Y Z\r\n"]
    assert canonicalize_body(message.body_crlf, "simple") == b" C \r\nD \t E \r\n"


def test_simple_body_adds_crlf_when_body_lacks_it():
    """§3.4.3：正文没有以 CRLF 结尾 → 补一个。"""
    assert canonicalize_body(b"abc", "simple") == b"abc\r\n"
    assert canonicalize_body(b"abc\r\n\r\n\r\n", "simple") == b"abc\r\n"


def test_relaxed_body_reduces_wsp_and_keeps_leading_space():
    """§3.4.4：行内 WSP 压成单空格、行尾删掉，但**行首空白保留**。"""
    assert canonicalize_body(b"a   b \t\r\n  c\r\n", "relaxed") == b"a b\r\n c\r\n"


def test_unknown_canonicalization_algorithm_raises():
    with pytest.raises(ValueError):
        canonicalize_body(b"x", "bogus")
    with pytest.raises(ValueError):
        canonicalize_header(b"A", b" b", "bogus")


# ═══ 第 2 层：fixture 逐条对账 ═══════════════════════════════════════════


def test_fixture_set_covers_the_five_required_failure_classes():
    """五类失败各有 fixture（`plan/05` M3 DoD 第 1 条）。

    断言的是**目录存在 + 期望结论**，不是"文件名像"——重命名会红。
    """
    expected_kinds = {
        "d1-body-modified",           # body 被改
        "d2-header-modified",         # header 被改
        "d3-length-truncated",        # l= 截断
        "d4a-key-not-queried",        # key 缺失（数据缺口）
        "d4b-key-nxdomain",           # key 缺失（真的没有）
        "d5-key-weak-512",            # RSA-512（过短）
    }
    present = {path.name for path in _fixture_cases()}
    assert expected_kinds <= present, "缺 fixture：%s" % sorted(expected_kinds - present)


def test_fixture_set_contains_a_positive_sample():
    """**反自证**：没有正样本，"永远返回 fail"也能通过全部负样本。

    这条断言是本文件里最重要的一条——它把"测试集能不能证明实现是对的"
    变成了一条会变红的检查。
    """
    results = {}
    for directory in _fixture_cases():
        expected = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
        results[directory.name] = expected["expect"].get("dkim.result")
    positives = [name for name, result in results.items() if result == "pass"]
    assert positives, "fixture 集里没有任何期望 pass 的样本（负样本集无法证明实现正确）"


@pytest.mark.parametrize("directory", _fixture_cases(), ids=lambda path: path.name)
def test_fixture_matches_expected(directory):
    """逐条跑 fixture，逐字段比对 ``expected.json``（全量，不抽样）。"""
    expected_path = directory / "expected.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    assert expected.get("why"), "%s 缺 why（`plan/04` §2.1：没有 why 的真值条目无效）"

    message, snapshot, outcome = _run_fixture(directory)
    entries = outcome.to_check_entries()
    expect = expected["expect"]

    # 单签名结论：dkim.result
    if "dkim.result" in expect:
        assert [entry["result"] for entry in entries] == [expect["dkim.result"]], \
            "结论不符：%r" % ([entry["result"] for entry in entries],)

    # 多签名：dkim.result[i]
    for index in range(len(entries)):
        key = "dkim.result[%d]" % index
        if key in expect:
            assert entries[index]["result"] == expect[key], \
                "%s 期望 %r，实得 %r" % (key, expect[key], entries[index]["result"])

    if "dkim.signatures_total" in expect:
        # 报文里**签名条数**（与"账本条目数"不同：未签名报文出一条 none 条目，签名 0 条）。
        assert entries[0]["subject"]["signatures_total"] == expect["dkim.signatures_total"]
        if expect["dkim.signatures_total"]:
            assert len(entries) == expect["dkim.signatures_total"]

    if "dkim.bh_matches" in expect and "subject" not in expect:
        assert entries[0]["subject"]["bh_matches"] == expect["dkim.bh_matches"]

    if "dkim.key_status" in expect:
        assert entries[0]["subject"]["key_status"] == expect["dkim.key_status"]

    if "dkim.key_bits" in expect:
        assert entries[0]["subject"]["key_bits"] == expect["dkim.key_bits"]

    if "dkim.failure_at" in expect:
        assert entries[0]["subject"]["failure_at"] == expect["dkim.failure_at"]

    if "dkim.failure_at.kind" in expect:
        failure_at = entries[0]["subject"]["failure_at"]
        assert failure_at is not None, "期望 failure_at 有值，实得 None"
        assert failure_at["kind"] == expect["dkim.failure_at.kind"]

    if "dkim.data_gap" in expect:
        gap = expect["dkim.data_gap"]
        if gap is None:
            assert outcome.data_gaps == ()
        else:
            assert list(outcome.data_gaps[0]) == gap
            # 数据缺口必须同时是一等结论 undecidable，不得折叠成 fail（K13）。
            assert entries[0]["result"] == "undecidable"


def test_every_fixture_entry_carries_evidence_and_trace():
    """每条 fixture 的账本条目都必须带条款、轨迹、且 ``tree`` 键存在（M3 无树）。"""
    for directory in _fixture_cases():
        _message, _snapshot, outcome = _run_fixture(directory)
        for entry in outcome.to_check_entries():
            assert entry["evidence_ref"], "%s 缺 evidence_ref" % directory.name
            assert entry["trace"], "%s 缺 trace" % directory.name
            assert "tree" in entry, "%s 缺 tree 键" % directory.name
            assert entry["tree"] is None
            assert entry["result"] in RESULTS


def test_fixture_generator_is_idempotent():
    """`plan/04` §2.5：生成器 `--check` 必须逐字节比对。

    这条测试跑的是**真实的生成器**，不是"我手动比对过一次"。
    """
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "gen_dkim_fixtures.py"), "--check"],
        cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    assert result.returncode == 0, result.stdout.decode("utf-8", "replace")


# ═══ 第 3 层：结构性断言（不短路 / undecidable / 边界） ═════════════════


def test_multi_signature_evaluates_every_signature_without_short_circuit():
    """多签名逐个出结果（`plan/03` §3.3）。断言"第一条失败没有吞掉第二条"。"""
    message, snapshot, outcome = _run_fixture(FIXTURE_ROOT / "d7-multi-signature")
    assert len(outcome.signatures) == 2
    assert outcome.results == ["fail", "pass"], \
        "多签名必须逐条求值且不短路，实得 %r" % (outcome.results,)


def test_multi_signature_order_is_physical_order():
    """物理顺序（先出现的在前），不按结论排序——顺序本身是诊断信息。"""
    message, snapshot, outcome = _run_fixture(FIXTURE_ROOT / "d7-multi-signature")
    assert [item.index for item in outcome.signatures] == [0, 1]
    # 第 1 条是 relaxed（bh 不符），第 2 条是 simple（通过）。
    assert outcome.signatures[0].canonicalization == "relaxed/relaxed"
    assert outcome.signatures[1].canonicalization == "simple/simple"


def test_missing_key_is_undecidable_not_fail():
    """M3 验收 2 的**原话**断言：无快照 key → ``undecidable``，**不是** ``fail``。"""
    message, snapshot, outcome = _run_fixture(FIXTURE_ROOT / "d4a-key-not-queried")
    assert outcome.results == ["undecidable"]
    assert "fail" not in outcome.results


def test_data_gap_is_reported_as_pending_input():
    """K13：数据缺口要能指认"缺哪一条查询"，否则用户不知道该补抓什么。"""
    message, snapshot, outcome = _run_fixture(FIXTURE_ROOT / "d4a-key-not-queried")
    qname, qtype = outcome.data_gaps[0]
    assert qname.endswith("._domainkey.example.com")
    assert qtype == "TXT"


def test_nxdomain_key_is_permerror_without_data_gap():
    """与上一条成对：**问过了没有** ≠ **没问过**。前者是结论，后者是待补输入。"""
    message, snapshot, outcome = _run_fixture(FIXTURE_ROOT / "d4b-key-nxdomain")
    assert outcome.results == ["permerror"]
    assert outcome.data_gaps == ()


def test_weak_key_is_fail_not_undecidable():
    """RFC 8301 §3.2 是 MUST：过短密钥判 ``fail``，不是灰区。"""
    message, snapshot, outcome = _run_fixture(FIXTURE_ROOT / "d5-key-weak-512")
    assert outcome.results == ["fail"]
    assert outcome.signatures[0].key_status == "weak"
    assert outcome.signatures[0].key_bits < DKIM_MIN_KEY_BITS


def test_length_exceeding_body_is_permerror():
    """§3.5 的 "MUST NOT be larger" + §6.1.1 的 "inconsistent values → PERMFAIL"。

    这条与参照实现 dkimpy 有意不同（它静默取全量）。口径差异登记在
    `plan/06` 缺口表与本文件的模块 docstring 里。
    """
    message, snapshot, outcome = _run_fixture(FIXTURE_ROOT / "d3b-length-exceeds-body")
    assert outcome.results == ["permerror"]
    failure = outcome.signatures[0].failure_at
    assert failure["kind"] == "length_exceeds_body"
    assert failure["limit"] > failure["canonical_length"]


def test_length_boundary_at_exact_body_length_is_accepted():
    """``l=`` 恰好等于规范化正文长度**不是**超限（边界两侧都要断言）。"""
    message, snapshot, outcome = _run_fixture(FIXTURE_ROOT / "d3-length-truncated")
    assert outcome.results == ["pass"]
    failure = outcome.signatures[0].failure_at
    assert failure is None
    # 尾部被 `l=` 排除，本工具必须告警指出"第几行起未受保护"（可判定的定位）。
    warnings = " ".join(outcome.signatures[0].warnings)
    assert "未受签名保护" in warnings


def test_unsigned_message_is_none_not_fail():
    """未签名 → ``none``。判成 fail 会让账本对所有普通邮件报错。"""
    message, snapshot, outcome = _run_fixture(FIXTURE_ROOT / "d8-unsigned")
    assert outcome.results == []
    entries = outcome.to_check_entries()
    assert len(entries) == 1
    assert entries[0]["result"] == "none"


def test_failure_at_for_body_hash_does_not_invent_a_line():
    """正文哈希失败时 ``body_line`` 必须是 ``None`` + 给出 basis。

    编一个行号比不说更糟：用户会照着错的方向去查。这是"不可判定就如实说"的具体落地。
    """
    message, snapshot, outcome = _run_fixture(FIXTURE_ROOT / "d1-body-modified")
    failure = outcome.signatures[0].failure_at
    assert failure["kind"] == "body_hash"
    assert failure["body_line"] is None
    assert failure["basis"]


def test_failure_at_for_header_hash_does_not_invent_a_name():
    """头部验签失败同理：给 kind + basis，不编造"是哪个头被改"。"""
    message, snapshot, outcome = _run_fixture(FIXTURE_ROOT / "d2-header-modified")
    failure = outcome.signatures[0].failure_at
    assert failure["kind"] == "header_hash"
    assert failure["header"] is None
    assert failure["basis"]


def test_tag_syntax_error_is_permerror_with_offset():
    """缺必需标签 → ``permerror`` 且 ``failure_at`` 能定位（§6.1.1）。"""
    message, snapshot, outcome = _run_fixture(FIXTURE_ROOT / "d9-missing-tag")
    assert outcome.results == ["permerror"]
    failure = outcome.signatures[0].failure_at
    assert failure["kind"] == "missing_tag"
    assert "d" in failure["tags"]


# ── 算法门（RFC 8301 §3.1） ─────────────────────────────────────────────


def _signature_header(**overrides):
    tags = {
        "v": "1", "a": "rsa-sha256", "c": "relaxed/relaxed", "d": "example.com",
        "s": "sel1", "h": "from:subject", "bh": base64.b64encode(b"x" * 32).decode(),
        "b": base64.b64encode(b"y" * 32).decode(),
    }
    tags.update(overrides)
    return "; ".join("%s=%s" % (key, value) for key, value in tags.items() if value is not None)


def _message_with_signature(signature: str, *, body: bytes = b"body\r\n") -> bytes:
    return (b"From: a@example.com\r\n"
            b"Subject: s\r\n"
            b"DKIM-Signature: " + signature.encode() + b"\r\n"
            b"\r\n" + body)


def test_ed25519_is_undecidable_with_explicit_warning():
    """``a=ed25519-sha256`` → ``undecidable`` + 告警「本工具不支持该算法」，**不判 fail**。"""
    raw = _message_with_signature(_signature_header(a="ed25519-sha256"))
    outcome = verify_message(eml.parse(raw), _snapshot([]))
    assert outcome.results == ["undecidable"]
    assert any("不支持" in warning for warning in outcome.signatures[0].warnings)


def test_rsa_sha1_is_permerror_per_rfc8301():
    """RFC 8301 §3.1 把 rsa-sha1 从"必须支持"改成"不得用于验签"→ ``permerror``。"""
    raw = _message_with_signature(_signature_header(a="rsa-sha1"))
    outcome = verify_message(eml.parse(raw), _snapshot([]))
    assert outcome.results == ["permerror"]
    assert "RFC8301#3.1" in outcome.signatures[0].evidence_ref


def test_unknown_algorithm_is_undecidable_not_fail():
    raw = _message_with_signature(_signature_header(a="rsa-sha512"))
    outcome = verify_message(eml.parse(raw), _snapshot([]))
    assert outcome.results == ["undecidable"]


def test_from_must_be_signed():
    """§6.1.1：``h=`` 不含 From → PERMFAIL (From field not signed)。"""
    raw = _message_with_signature(_signature_header(h="subject:to"))
    outcome = verify_message(eml.parse(raw), _snapshot([]))
    assert outcome.results == ["permerror"]
    assert outcome.signatures[0].failure_at["kind"] == "from_not_signed"


def test_version_must_be_one():
    raw = _message_with_signature(_signature_header(v="2"))
    outcome = verify_message(eml.parse(raw), _snapshot([]))
    assert outcome.results == ["permerror"]


def test_identity_domain_must_be_under_d():
    """§6.1.1：``i=`` 的域必须是 ``d=`` 或其后代。"""
    raw = _message_with_signature(_signature_header(i="@other.example.net"))
    outcome = verify_message(eml.parse(raw), _snapshot([]))
    assert outcome.results == ["permerror"]
    assert outcome.signatures[0].failure_at["kind"] == "domain_mismatch"


def test_default_identity_is_at_sign_d():
    """§6.1.1：无 ``i=`` 时按 ``@d`` 处理（不是报错）。"""
    raw = _message_with_signature(_signature_header())
    outcome = verify_message(eml.parse(raw), _snapshot([]))
    assert outcome.signatures[0].identity == "@example.com"


def test_expiration_tag_is_not_silently_ignored():
    """判定路径零时钟（K7）：``x=`` 不校验，但必须告警——静默跳过会让人以为查过了。"""
    raw = _message_with_signature(_signature_header(x="1000000000"))
    outcome = verify_message(eml.parse(raw), _snapshot([]))
    warnings = " ".join(outcome.signatures[0].warnings)
    assert "x=" in warnings and "K7" in warnings


# ── 密钥记录语义（RFC 6376 §3.6.1 / §6.1.2） ────────────────────────────


def _key_record(*, p: str = "AAAA", extra: str = "v=DKIM1; k=rsa") -> str:
    return "%s; p=%s" % (extra, p)


def _verify_with_key_record(record: str, *, signature: str | None = None) -> list[str]:
    raw = _message_with_signature(signature or _signature_header())
    snap = _snapshot([_q("sel1._domainkey.example.com", [record])])
    return verify_message(eml.parse(raw), snap).results


def test_empty_p_means_revoked():
    """§3.6.1："An empty value means that this public key has been revoked." → permerror。"""
    results = _verify_with_key_record(_key_record(p=""))
    assert results == ["permerror"]


def test_non_dkim1_version_record_is_discarded():
    assert _verify_with_key_record(_key_record(extra="v=DKIM2; k=rsa")) == ["permerror"]


def test_non_rsa_key_type_is_ignored():
    assert _verify_with_key_record(_key_record(extra="v=DKIM1; k=ed25519")) == ["permerror"]


def test_service_type_without_email_is_ignored():
    """§3.6.1：``s=`` 不含 email 或星号 → 记录必须被忽略。"""
    assert _verify_with_key_record(_key_record(extra="v=DKIM1; k=rsa; s=tlsrpt")) == ["permerror"]


def test_key_h_restriction_excluding_our_hash_is_permerror():
    """§6.1.2 第 6 步：``h=`` 不含签名的哈希算法 → PERMFAIL (inappropriate hash algorithm)。"""
    assert _verify_with_key_record(_key_record(extra="v=DKIM1; k=rsa; h=sha1")) == ["permerror"]


def test_multiple_txt_records_picks_the_usable_one():
    """多条 TXT 时取第一条能解析的（§3.6.2 说结果未定义，但"能查"必须留在 trace 里）。"""
    good = (FIXTURE_ROOT / "d6-valid" / "snap.json").read_text(encoding="utf-8")
    snap_data = json.loads(good)
    answer = snap_data["queries"][0]["answer"]
    snap_data["queries"][0]["answer"] = ["v=DKIM1; k=rsa; p=!!notbase64!!"] + answer
    raw = (FIXTURE_ROOT / "d6-valid" / "message.eml").read_bytes()
    outcome = verify_message(eml.parse(raw), from_dict(snap_data))
    assert outcome.results == ["pass"]
    assert any("第 2 条 TXT" in node.get("note", "") for node in outcome.trace)


def test_parse_tag_list_rejects_duplicates():
    with pytest.raises(ValueError):
        parse_tag_list(b"v=1; v=1", where="t")


def test_parse_tag_list_rejects_missing_equals():
    with pytest.raises(ValueError):
        parse_tag_list(b"v=1; oops", where="t")


def test_parse_tag_list_allows_trailing_semicolon():
    tags = parse_tag_list(b"v=1; a=rsa-sha256;", where="t")
    assert tags["v"] == "1" and tags["a"] == "rsa-sha256"


# ═══ 第 4 层：零依赖 RSA 与参照实现对账 ═════════════════════════════════


def _reference_key_and_signature(digest: bytes, *, hash_name: str = "sha256", bits: int = 2048):
    """用 ``cryptography``（测试期依赖）独立签一份摘要。"""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, utils

    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    hash_alg = hashes.SHA256() if hash_name == "sha256" else hashes.SHA1()
    signature = key.sign(digest, padding.PKCS1v15(), utils.Prehashed(hash_alg))
    public = key.public_key().public_numbers()
    return public.n, public.e, signature


def _der_public(n: int, e: int, *, spki: bool) -> bytes:
    """构造 SPKI 或裸 RSAPublicKey（与生成器同一思路，但独立写一遍以便互相校验）。"""

    def tlv(tag: int, content: bytes) -> bytes:
        length = len(content)
        if length < 0x80:
            size = bytes([length])
        else:
            body = length.to_bytes((length.bit_length() + 7) // 8, "big")
            size = bytes([0x80 | len(body)]) + body
        return bytes([tag]) + size + content

    def integer(value: int) -> bytes:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw and raw[0] & 0x80:
            raw = b"\x00" + raw
        return tlv(0x02, raw)

    pkcs1 = tlv(0x30, integer(n) + integer(e))
    if not spki:
        return pkcs1
    algorithm = tlv(0x30, tlv(0x06, bytes.fromhex("2a864886f70d010101")) + tlv(0x05, b""))
    return tlv(0x30, algorithm + tlv(0x03, b"\x00" + pkcs1))


@pytest.mark.parametrize("hash_name", ["sha256", "sha1"])
def test_zero_dep_rsa_agrees_with_reference_implementation(hash_name):
    """零依赖 RSA 与 ``cryptography`` 逐条一致（`plan/04` §2.2 的"独立复算"）。

    覆盖：SPKI 与裸 PKCS#1 两种编码、两个摘要算法、以及"改一个字节就不通过"。
    """
    digest = hashlib.new(hash_name, b"mailvault dkim reconciliation").digest()
    n, e, signature = _reference_key_and_signature(digest, hash_name=hash_name)

    for spki in (True, False):
        key = parse_rsa_public_key(_der_public(n, e, spki=spki))
        assert key.encoding == (ENCODING_SPKI if spki else ENCODING_RSAPUBLICKEY)
        outcome = verify_pkcs1_v15(key, signature, hash_name=hash_name, digest=digest)
        assert outcome.ok, "零依赖 RSA 应与参照实现一致（%s/%s）" % (
            hash_name, "spki" if spki else "pkcs1")

        # 阴性对照：同一把钥匙、改一个摘要字节 → 必须不通过。
        bad = bytearray(digest)
        bad[0] ^= 0x01
        assert not verify_pkcs1_v15(key, signature, hash_name=hash_name,
                                    digest=bytes(bad)).ok


def test_reference_signed_fixture_verifies_with_zero_dep_rsa():
    """正样本的签名由 ``cryptography`` 签出、由零依赖实现验过——两侧不共享代码路径。"""
    message, snapshot, outcome = _run_fixture(FIXTURE_ROOT / "d6-valid")
    assert outcome.results == ["pass"]


def test_signature_length_mismatch_is_reported_separately():
    """签名长度 ≠ 模数长度 → 单独的原因（否则会被读成"填充不符"，误导排查方向）。"""
    n, e, signature = _reference_key_and_signature(hashlib.sha256(b"x").digest())
    key = parse_rsa_public_key(_der_public(n, e, spki=True))
    outcome = verify_pkcs1_v15(key, signature[:-1], hash_name="sha256",
                               digest=hashlib.sha256(b"x").digest())
    assert not outcome.ok
    assert "长度" in outcome.reason


def test_key_too_small_for_digest_is_reported_as_key_problem():
    """模数装不下 DigestInfo → 原因必须指向**密钥**而不是报文。

    注意边界：SHA-256 的 DigestInfo 是 51 字节，加最少 8 字节填充与 3 字节头
    需要 ≥ 62 字节模数，所以 **512 位（64 字节）装得下**——D5 里 RSA-512 判 fail
    纯粹是 RFC 8301 §3.2 的位数政策，不是数学上装不下。这里刻意用更小的模数
    来触发"装不下"这条独立分支。
    """
    # 62 字节是 SHA-256 的下限；61 字节必然装不下。
    assert len(digest_info("sha256", b"\x00" * 32)) == 51
    with pytest.raises(SignatureMismatch) as exc:
        emsa_pkcs1_v15_encode("sha256", b"\x00" * 32, 61)
    assert "密钥" in str(exc.value)

    # 边界另一侧：62 字节可以（padding 恰好 8 字节）。
    encoded = emsa_pkcs1_v15_encode("sha256", b"\x00" * 32, 62)
    assert len(encoded) == 62 and encoded.startswith(b"\x00\x01")


def test_rsa512_can_still_hold_sha256_digest():
    """反上一类断言的对照：512 位密钥**不是**数学上不够用。

    这条存在的理由：若把 D5 的 fail 归因于"密钥装不下摘要"，排查方向会完全错。
    真正的依据是 RFC 8301 §3.2 的位数门槛（策略），不是 PKCS#1 的容量（数学）。
    """
    encoded = emsa_pkcs1_v15_encode("sha256", b"\x00" * 32, 64)
    assert len(encoded) == 64


def test_digest_info_prefix_matches_rfc8017():
    """DigestInfo 前缀是验签的信任根，必须与 RFC 8017 §9.2 的编码逐字节相同。"""
    assert digest_info("sha256", b"").hex() == "3031300d060960864801650304020105000420"
    assert digest_info("sha1", b"").hex() == "3021300906052b0e03021a05000414"


# ── DER 解析的拒绝面 ────────────────────────────────────────────────────


def test_der_rejects_empty_input():
    with pytest.raises(DerError):
        parse_rsa_public_key(b"")


def test_der_rejects_trailing_garbage():
    n, e, _ = _reference_key_and_signature(hashlib.sha256(b"x").digest())
    good = _der_public(n, e, spki=True)
    with pytest.raises(DerError):
        parse_rsa_public_key(good + b"\x00")


def test_der_rejects_truncated_length():
    n, e, _ = _reference_key_and_signature(hashlib.sha256(b"x").digest())
    good = _der_public(n, e, spki=True)
    with pytest.raises(DerError):
        parse_rsa_public_key(good[:-8])


def test_der_rejects_wrong_tag():
    with pytest.raises(DerError):
        parse_rsa_public_key(b"\x31\x00")


def test_der_error_never_escapes_into_ledger():
    """``p=`` 是坏 DER 时，结论是 ``permerror``（密钥不可用），不是异常穿透。"""
    results = _verify_with_key_record(_key_record(p=base64.b64encode(b"\x30\x00").decode()))
    assert results == ["permerror"]


def test_fixture_hygiene_catches_domain_in_json_value(tmp_path):
    """fixture 卫生门的**阳性对照**：JSON 的**值**里出现真实域名必须报红。

    为什么必须有这条：M3 把卫生门改成"JSON 只扫值、不扫键"（键是 schema 字段名，
    `plan/04` §2.1 的点路径与域名同形，扫键会假红）。改判据就必须证明它没被改瘫——
    一个"同样只看值、但什么都不报"的实现也能让真实 fixture 全绿。

    这里直接调门的 :func:`scan`，构造两份对照：
    - 违规放进**值**（`qname`）→ 必须红；
    - 同形串放进**键**（模拟点路径）→ 必须绿（这是判据的设计意图）。
    """
    import sys

    sys.path.insert(0, str(REPO_ROOT / "tools"))
    from check_fixture_hygiene import scan as hygiene_scan

    fixtures = tmp_path / "fixtures" / "probe"
    fixtures.mkdir(parents=True)

    (fixtures / "bad.json").write_text(
        '{"queries": [{"qname": "ops@mail.google.com", "qtype": "TXT"}]}',
        encoding="utf-8")
    violations, scanned, _exempt = hygiene_scan(tmp_path)
    assert scanned == 1
    assert violations, "JSON 值里的真实域名必须被卫生门抓到"
    assert any("mail.google.com" in item for item in violations)

    # 阴性对照：同一串只出现在**键**位置 → 不该报（键是 schema 字段名）。
    (fixtures / "bad.json").unlink()
    (fixtures / "ok.json").write_text(
        '{"expect": {"dkim.mail.google.com": "pass"}}', encoding="utf-8")
    violations, scanned, _exempt = hygiene_scan(tmp_path)
    assert scanned == 1
    assert violations == [], "键位置的点路径不应被当成域名（否则每加一个字段就要改白名单）"


# ── 反自证：运行时不得 import 参照实现 ──────────────────────────────────


def test_runtime_does_not_import_reference_implementation():
    """``mailvault/`` 不得 import ``cryptography`` / ``dkim`` / ``dkimpy``（`plan/04` §2.2）。

    为什么单列一条：开发期我用 ``cryptography`` 签样本、用 ``dkimpy`` 对账。
    若它们悄悄进了运行时，零依赖承诺与"离线自足"两件事同时作废。
    """
    forbidden = {"cryptography", "dkim", "dkimpy", "nacl", "Crypto", "Cryptodome"}
    offenders = []
    for path in sorted((REPO_ROOT / "mailvault").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in forbidden:
                        offenders.append("%s:%d" % (path.name, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] in forbidden and not node.level:
                    offenders.append("%s:%d" % (path.name, node.lineno))
    assert offenders == [], "运行时 import 了参照实现：%r" % (offenders,)


def test_dkim_module_imports_only_allowed_layers():
    """L3 只许 import L1/L2（`plan/03` §0）。AST 断言，不靠"我记得"。"""
    allowed_roots = {
        "__future__", "mailvault", "base64", "binascii", "hashlib", "hmac", "re",
        "dataclasses", "typing",
    }
    path = REPO_ROOT / "mailvault" / "modules" / "dkim.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    offenders = []
    for node in ast.walk(tree):
        roots: list[str] = []
        if isinstance(node, ast.Import):
            roots = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue
            roots = [(node.module or "").split(".")[0]]
        for root in roots:
            if root and root not in allowed_roots:
                offenders.append("%s:%d %r" % (path.name, node.lineno, root))
    assert offenders == [], "dkim.py 引入了不允许的层/依赖：%r" % (offenders,)
