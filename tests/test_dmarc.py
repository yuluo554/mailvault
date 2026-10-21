"""DMARC（M4）：tree walk、双算对齐、处置、旧标签告警、`undecidable` 语义。

测试分四层，每层回答一个不同的问题（与 `tests/test_dkim.py` 同构）：

1. **RFC 原文给定的期望值**。Appendix B.4.1–B.4.3 的**逐跳查询序列**是原文写死的
   （"query `_dmarc.g.h.i.j.k.example.com` (skipping the intermediate names)"），
   §4.10.2 的三个 Organizational Domain 选择例子也是原文写死的。这类断言不依赖任何
   实现——RFC 原文就是真值。它们锁的是"走查写对了"。
2. **fixture 逐条对账**（`fixtures/dmarc/*/expected.json`）。锁的是"输入 → 结论"这条链路。
3. **手算对账**（`plan/04` §2.2 指定的 DMARC 独立复算方式）：relaxed = 取 Organizational
   Domain 比对；strict = 逐字比对。这里用一份**不经过 `dmarc.py`** 的独立实现算同一批
   域对，再与模块输出逐条比对——同源实现不算对账。
4. **反自证 / 结构性断言**。锁的是"这套测试自己不会永远绿"：正样本与 fail 样本都必须
   存在、`psd=y` 与 `psd=n` 必须给出**不同**结果、`np=` 与 `sp=` 必须能区分、
   数据缺口必须判 `undecidable` 而不是 `none`。

第 4 层不是形式主义：**只有"逐跳全空 → none"的样本会放过一个永远返回 none 的实现**，
而第 2 层若只断言 none 类样本，恰好就是那种 fixture 集。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mailvault import eml
from mailvault.constants import DMARC_DISPOSITIONS, RESULTS
from mailvault.modules.dkim import verify_message
from mailvault.modules.dmarc import (
    DmarcResult,
    align,
    evaluate,
    from_domains,
    parse_record,
    select_organizational_domain,
    walk,
)
from mailvault.modules.spf import Budget, evaluate as spf_evaluate
from mailvault.query import from_dict as query_from_dict
from mailvault.snapshot import from_dict, load_snapshot

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_ROOT = REPO_ROOT / "fixtures" / "dmarc"

#: 缺 p= 时的兜底记录（多处复用，避免措辞漂移）。
_REMOVED = "已被 RFC 9989 删除"


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


def _q(qname, answer=(), *, qtype="TXT", rcode="NOERROR"):
    return {"qname": qname, "qtype": qtype, "rcode": rcode,
            "answer": list(answer), "ttl": 300}


def _nx(qname, *, qtype="TXT"):
    return _q(qname, [], qtype=qtype, rcode="NXDOMAIN")


def _query(mail_from="alice@example.com", *, helo="mail.example.com"):
    return query_from_dict({
        "mail_from": mail_from,
        "client_ip": "192.0.2.10",
        "helo": helo,
    }, source="<test>")


def _message(from_value="alice@example.com"):
    return eml.parse(("From: <%s>\r\nSubject: t\r\n\r\nbody\r\n" % from_value).encode())


def _fixture_cases():
    return sorted(
        path for path in FIXTURE_ROOT.iterdir()
        if path.is_dir() and (path / "expected.json").is_file()
    )


def _run_fixture(directory: Path):
    message = eml.parse((directory / "message.eml").read_bytes())
    snap = load_snapshot(directory / "snap.json")
    context = query_from_dict(
        json.loads((directory / "query.json").read_text(encoding="utf-8")))
    trace = []
    spf = spf_evaluate(snap, context, budget=Budget(), trace=trace)
    dkim = verify_message(message, snap, trace=trace)
    return message, snap, context, spf, dkim, evaluate(
        snap, message, context, spf=spf, dkim=dkim, trace=trace)


def _evaluate(snap, context, message=None, *, spf=None, trace=None):
    """跑一次 DMARC：SPF 按需真算，DKIM 用**真实的"没签名"结论**。

    为什么不用 ``dkim=None``：``None`` 表示"没算过"，DMARC 会因此判 ``undecidable``
    （不猜），处置字段永远是 ``None``——那样"处置算对了没"就永远测不到。
    ``verify_message()`` 对未签名报文返回 ``signatures == ()``，那是 §5.3.3 的真实
    输入形态。``dkim=None`` 的语义由
    :func:`test_missing_spf_or_dkim_is_undecidable_not_pass` 单独覆盖。
    """
    message = message if message is not None else _message()
    if spf is None:
        spf = spf_evaluate(snap, context, budget=Budget(), trace=trace or [])
    dkim = verify_message(message, snap)
    return evaluate(snap, message, context, spf=spf, dkim=dkim, trace=trace)


# ═══ 第 1 层：RFC 原文向量 ══════════════════════════════════════════════


def test_rfc9989_b41_walk_is_author_then_tld():
    """Appendix B.4.1：'query "_dmarc.example.com" and "_dmarc.com"'。

    原文只给两跳——`example.com` 之上就是 `com`。断言**逐跳 qname 序列**，
    不是"最后结果对上了"。
    """
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=reject"]),
        _nx("_dmarc.com"),
    ])
    result = walk(snap, "example.com")
    assert [hop.qname for hop in result.hops] == [
        "_dmarc.example.com", "_dmarc.com"]
    assert [hop.status for hop in result.hops] == ["record", "nxdomain"]


def test_rfc9989_b42_walk_skips_intermediate_labels():
    """Appendix B.4.2：13 标签 Author → **第 2 跳直接跳到 7 标签处**。

    原文："query "_dmarc.a.b.c.d.e.f.g.h.i.j.k.example.com"; then query
    "_dmarc.g.h.i.j.k.example.com" (skipping the intermediate names); then query
    "_dmarc.h.i.j.k.example.com", ..., and "_dmarc.com"" —— 共 8 次查询。

    这条锁的是 §4.10 步骤 4 的跳步：**x >= 8 时一次删到只剩 7 个标签**。
    漏掉跳步的实现会逐级爬，第一条断言当场变红。
    """
    author = "a.b.c.d.e.f.g.h.i.j.k.example.com"
    snap = _snapshot([_nx("_dmarc." + author)] + [
        _nx("_dmarc.%s.example.com" % ".".join(labels))
        for labels in (
            ("g", "h", "i", "j", "k"), ("h", "i", "j", "k"), ("i", "j", "k"),
            ("j", "k"), ("k",),
        )
    ] + [
        _q("_dmarc.example.com", ["v=DMARC1; p=reject"]),
        _nx("_dmarc.com"),
    ])
    result = walk(snap, author)
    assert [hop.qname for hop in result.hops] == [
        "_dmarc." + author,
        "_dmarc.g.h.i.j.k.example.com",   # 跳步：h/i/j 层在这两跳里不查
        "_dmarc.h.i.j.k.example.com",
        "_dmarc.i.j.k.example.com",
        "_dmarc.j.k.example.com",
        "_dmarc.k.example.com",
        "_dmarc.example.com",
        "_dmarc.com",
    ]
    assert len(result.hops) == 8, "§4.10 的反滥用上限是 8 次查询"


def test_rfc9989_4_10_2_example_picks_fewest_labels():
    """§4.10.2 的第一个原文例子。

    'given the starting domain "a.mail.example.com" ... If there are DMARC Policy
    Records published at "_dmarc.mail.example.com" and "_dmarc.example.com", but
    not at "_dmarc.a.mail.example.com" or "_dmarc.com", then the Organizational
    Domain for this domain would be "example.com".'
    """
    snap = _snapshot([
        _nx("_dmarc.a.mail.example.com"),
        _q("_dmarc.mail.example.com", ["v=DMARC1; p=none"]),
        _q("_dmarc.example.com", ["v=DMARC1; p=none"]),
        _nx("_dmarc.com"),
    ])
    assert select_organizational_domain(walk(snap, "a.mail.example.com")) == "example.com"


def test_rfc9989_4_10_2_example_psd_n_stops_at_that_domain():
    """§4.10.2 的第二个原文例子。

    'given the starting domain "a.mail.example.com", if a search for the
    Organizational Domain yields a DMARC Policy Record at "_dmarc.mail.example.com"
    with the "psd" tag set to "n", then the Organizational Domain for this domain
    would be "mail.example.com".'
    """
    snap = _snapshot([
        _nx("_dmarc.a.mail.example.com"),
        _q("_dmarc.mail.example.com", ["v=DMARC1; p=none; psd=n"]),
        _q("_dmarc.example.com", ["v=DMARC1; p=none"]),
        _nx("_dmarc.com"),
    ])
    result = walk(snap, "a.mail.example.com")
    assert result.stopped_by == "psd", "psd=n 必须让走查就地停（§4.10 步骤 6）"
    assert select_organizational_domain(result) == "mail.example.com"


def test_rfc9989_4_10_2_example_psd_y_picks_one_label_below():
    """§4.10.2 的第三个原文例子。

    'given the starting domain "a.mail.example.com", if a search for the
    Organizational Domain only yields a DMARC Policy Record at "_dmarc.com" and
    that record contains the tag "psd=y", then the Organizational Domain for this
    domain would be "example.com".'
    """
    snap = _snapshot([
        _nx("_dmarc.a.mail.example.com"),
        _nx("_dmarc.mail.example.com"),
        _nx("_dmarc.example.com"),
        _q("_dmarc.com", ["v=DMARC1; p=none; psd=y"]),
    ])
    result = walk(snap, "a.mail.example.com")
    assert select_organizational_domain(result) == "example.com", \
        "psd=y 记录的 Organizational Domain 是它**下面一层**，不是它自己"


def test_rfc9989_4_10_1_own_record_uses_p_not_sp():
    """§4.10.1：'If the DMARC Policy Record to be applied is that of the Author
    Domain, then the Domain Owner Assessment Policy is taken from the "p" tag'。

    `sp=` 在 Author 自己的记录上**不适用**：本样本让 p 与 sp 取不同值，
    用错了标签会立刻体现在 disposition 上。
    """
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=none; sp=reject"]),
        _nx("_dmarc.com"),
        _q("example.com", ["192.0.2.10"], qtype="A"),
        _q("other.example.net", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _nx("_dmarc.other.example.net"),
        _nx("_dmarc.example.net"),
    ])
    outcome = _evaluate(snap, _query("alice@other.example.net"))
    assert outcome.result == "fail"
    assert outcome.policy_tag == "p"
    assert outcome.disposition == "none", "Author 自己的记录必须取 p=，不是 sp="


def test_rfc9989_4_7_missing_p_is_treated_as_none():
    """§4.7：'If this tag is not present in an otherwise syntactically valid DMARC
    Policy Record, then the record is treated as if it included "p=none"'。"""
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; rua=mailto:dmarc@example.com"]),
        _nx("_dmarc.com"),
        _q("example.com", ["192.0.2.10"], qtype="A"),
        _q("other.example.net", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _nx("_dmarc.other.example.net"),
        _nx("_dmarc.example.net"),
    ])
    outcome = _evaluate(snap, _query("alice@other.example.net"))
    assert outcome.result == "fail"
    assert outcome.disposition == "none"
    assert any("按 p=none 处理" in warning for warning in outcome.warnings), \
        "缺 p= 必须明说'按 p=none 处理'，不能静默"


def test_rfc9989_4_7_v_must_be_first_and_exact():
    """§4.7：'If the tag is not the first in the list, the tag is absent, or the
    value is not "DMARC1", then the entire record MUST be ignored.'

    四条逐条断言（顺序 / 缺失 / 标签名大小写 / **值**大小写）——
    只测其中一条会放过另外三条。
    """
    assert parse_record("v=DMARC1; p=none") is not None
    assert parse_record("p=none; v=DMARC1") is None, "v 不是第一个标签 → 整条忽略"
    assert parse_record("p=none") is None, "没有 v 标签 → 整条忽略"
    assert parse_record("V=DMARC1; p=none") is not None, "标签名大小写不敏感"
    assert parse_record("v=dmarc1; p=none") is None, \
        "**值**大小写敏感（原文 'The tag value is case sensitive'）"
    assert parse_record("v=DMARC1") is not None, "只有 v 也是合法记录"


def test_rfc9989_alignment_table_one():
    """**手算对账**（`plan/04` §2.2）：不经过 `dmarc.py` 的独立实现。

    relaxed = 两者 Organizational Domain 相同（§3.2.10.1）；
    strict = 逐字相同（§3.2.10.2）。
    Organizational Domain 用一份**独立写的**走查（自写 min-by-labels）算出，
    再与模块输出逐条比对——同源实现不算对账。
    """
    # §4.4 Table 1 的三行 + B.4.1 / B.4.2 的域对
    pairs = [
        ("foo.example.com", "news.example.com", True, False),    # Table 1 第 1 行
        ("news.example.com", "news.example.com", True, True),     # Table 1 第 2 行
        ("news.example.com", "foo.example.net", False, False),    # Table 1 第 3 行
        ("example.com", "example.com", True, True),               # B.4.1 RFC5321 侧
        ("example.com", "signing.example.com", True, False),      # B.4.1 DKIM 侧
    ]
    records = {
        "example.com": "v=DMARC1; p=none",
        "signing.example.com": "v=DMARC1; p=none",
        "foo.example.com": "v=DMARC1; p=none",
        "news.example.com": "v=DMARC1; p=none",
        "foo.example.net": "v=DMARC1; p=none",
    }

    def independent_org(domain: str) -> str | None:
        labels = domain.split(".")
        hits = [".".join(labels[len(labels) - size:])
                for size in range(len(labels), 0, -1)
                if ".".join(labels[len(labels) - size:]) in records]
        return min(hits, key=lambda name: (len(name.split(".")), name)) if hits else None

    snap = _snapshot([_q("_dmarc.%s" % name, [text])
                      for name, text in sorted(records.items())]
                     + [_nx("_dmarc.com"), _nx("_dmarc.net")])

    for author, identifier, expect_relaxed, expect_strict in pairs:
        author_org = independent_org(author)
        identifier_org = independent_org(identifier)
        independent_relaxed = author_org is not None and author_org == identifier_org
        independent_strict = author == identifier

        computed = align(author, author_org, identifier, source="probe",
                         walk_cache={}, snap=snap, psl=None, trace=None)
        assert computed.relaxed == independent_relaxed == expect_relaxed, \
            "relaxed 不符：%s vs %s" % (author, identifier)
        assert computed.strict == independent_strict == expect_strict, \
            "strict 不符：%s vs %s" % (author, identifier)
        assert computed.organizational_domain == identifier_org


# ═══ 第 2 层：fixture 逐条对账 ═════════════════════════════════════════


def test_fixture_set_covers_the_required_forms():
    """`plan/05` M4 DoD 与题面 M3 验收：B.4.1–B.4.3 + `psd` + `np` + 旧标签各一份。"""
    required = {"b41", "b42", "b43", "psd-n", "np", "pct"}
    present = {path.name for path in _fixture_cases()}
    assert required <= present, "缺 fixture：%s" % sorted(required - present)


def test_fixture_set_contains_both_pass_and_fail_samples():
    """**反自证**：只有负样本会放过"永远 fail"，只有正样本会放过"永远 pass"。

    两个方向各断言一次——这是本文件里最重要的一条。
    """
    results = {}
    for directory in _fixture_cases():
        expected = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
        results[directory.name] = expected["expect"].get("dmarc.result")
    assert "pass" in results.values(), \
        "fixture 集里没有期望 pass 的样本（无法排除'永远 fail'）"
    assert "fail" in results.values(), \
        "fixture 集里没有期望 fail 的样本（无法排除'永远 pass'）"


def test_fixture_set_has_distinct_dispositions():
    """处置不能全是同一个值——否则"处置算对了"这句话没有证据。"""
    dispositions = {}
    for directory in _fixture_cases():
        expected = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
        value = expected["expect"].get("dmarc.disposition")
        if value is not None:
            dispositions[directory.name] = value
    assert len(set(dispositions.values())) >= 2, \
        "至少要有两个不同的处置值，实得 %r" % (dispositions,)
    assert set(dispositions.values()) <= set(DMARC_DISPOSITIONS)


@pytest.mark.parametrize("directory", _fixture_cases(), ids=lambda path: path.name)
def test_fixture_matches_expected(directory):
    """逐条跑 fixture，逐字段比对 ``expected.json``（全量，不抽样）。"""
    expected = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
    assert expected.get("why"), "%s 缺 why（`plan/04` §2.1：没有 why 的真值条目无效）"

    *_rest, outcome = _run_fixture(directory)
    subject = outcome.default_subject()

    for key, value in expected["expect"].items():
        assert key.startswith("dmarc."), "未知的期望点路径：%r" % (key,)
        path = key[len("dmarc."):]

        if path.startswith("walk["):
            head, _, field = path.partition("]")
            index = int(head[len("walk["):])
            field = field.lstrip(".")
            assert outcome.walk is not None, "%s 期望有走查，实得 None" % directory.name
            assert index < len(outcome.walk.hops), \
                "%s 期望 walk[%d]，实得只有 %d 跳" % (
                    directory.name, index, len(outcome.walk.hops))
            actual = outcome.walk.hops[index].to_dict()[field]
        elif path.startswith("warning_contains."):
            needle = path[len("warning_contains."):]
            assert any(needle in warning for warning in outcome.warnings), \
                "%s：warnings 里没有含 %r 的条目，实得 %r" % (
                    directory.name, needle, list(outcome.warnings))
            continue
        elif path.startswith("spf_align."):
            actual = outcome.spf_align[path[len("spf_align."):]]
        elif path.startswith("dkim_align."):
            actual = outcome.dkim_align[path[len("dkim_align."):]]
        elif path == "result":
            actual = outcome.result      # 账本条目的顶层字段，不在 subject 里
        else:
            assert path in subject, "%s：subject 里没有 %r（实得键：%s）" % (
                directory.name, path, sorted(subject))
            actual = subject[path]

        assert actual == value, "%s：%s 期望 %r，实得 %r" % (
            directory.name, key, value, actual)


def test_every_fixture_entry_carries_evidence_and_trace():
    """条目必须带条款、轨迹，且 ``tree`` 键存在（DMARC 无判定树）。"""
    for directory in _fixture_cases():
        *_rest, outcome = _run_fixture(directory)
        entry = outcome.to_check_entry()
        assert entry["evidence_ref"], "%s 缺 evidence_ref" % directory.name
        assert entry["trace"], "%s 缺 trace" % directory.name
        assert "tree" in entry and entry["tree"] is None
        assert entry["result"] in RESULTS
        assert entry["check_id"] == "dmarc.evaluate"
        assert entry["module"] == "M4"


def test_every_fixture_walk_hop_has_a_known_status():
    for directory in _fixture_cases():
        *_rest, outcome = _run_fixture(directory)
        assert outcome.walk is not None
        for hop in outcome.walk.hops:
            assert hop.status in (
                "record", "no_record", "nxdomain", "multiple_records",
                "invalid_record", "dns_error", "not_queried"), \
                "%s：未知跳状态 %r" % (directory.name, hop.status)


def test_fixture_generator_is_idempotent():
    """`plan/04` §2.5：生成器 `--check` 必须逐字节比对（跑真实生成器）。"""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "gen_dmarc_fixtures.py"), "--check"],
        cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    assert result.returncode == 0, result.stdout.decode("utf-8", "replace")


# ═══ 第 3 层：结构性断言（K13 / 双算 / psd / np / 旧标签） ══════════════


def test_data_gap_is_undecidable_not_none():
    """**K13 的 DMARC 侧**：tree walk 某跳在快照里没查过 → `undecidable` + `data_gaps`。

    与 `test_spf.py::test_data_gap_is_not_treated_as_no_record`、
    `test_dkim.py::test_data_gap_is_reported_as_pending_input` 同源。
    把"没抓"读成"没有记录"，这里会静默变成 `none`——账本变假绿。
    """
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=reject"]),
        # `_dmarc.com` **没有查询**（不是 NXDOMAIN）
    ])
    outcome = _evaluate(snap, _query())
    assert outcome.result == "undecidable"
    assert outcome.data_gaps == (("_dmarc.com", "TXT"),)
    assert any(hop.status == "not_queried" for hop in outcome.walk.hops)


def test_nxdomain_everywhere_is_none_not_undecidable():
    """逐跳全空（NXDOMAIN）→ `none`，不是 `fail`，也不是 `undecidable`。"""
    snap = _snapshot([_nx("_dmarc.example.com"), _nx("_dmarc.com")])
    outcome = _evaluate(snap, _query())
    assert outcome.result == "none"
    assert outcome.data_gaps == ()
    assert outcome.disposition is None
    assert outcome.disposition_status == "not_applicable"


def test_dns_error_is_undecidable_not_none():
    """§5.3.6：DNS 错误时报文 'cannot be considered to pass or fail'。

    `SERVFAIL` 不是 `none`，也不是 `fail`——"没问到"不能当成"没有"（与 TIMEOUT 同源）。
    """
    snap = _snapshot([
        _q("_dmarc.example.com", [], rcode="SERVFAIL"),
        _nx("_dmarc.com"),
    ])
    outcome = _evaluate(snap, _query())
    assert outcome.result == "undecidable"
    assert "DNS 错误" in outcome.reason


def test_multiple_records_at_one_target_are_all_discarded():
    """§4.10 步骤 2：'If multiple DMARC Policy Records are returned for a single
    target, they are all discarded.' ——两条都合法也必须全丢，不是"取第一条"。"""
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=reject", "v=DMARC1; p=none"]),
        _nx("_dmarc.com"),
    ])
    result = walk(snap, "example.com")
    assert result.hops[0].status == "multiple_records"
    assert result.records == (), "多条记录必须全部丢弃，不得取第一条"


def test_invalid_record_is_discarded_but_walk_continues():
    """`v=` 不合格的记录整条忽略，走查继续往上找（§4.7 + §4.10 步骤 6）。"""
    snap = _snapshot([
        _q("_dmarc.mail.example.com", ["v=spf1 -all"]),   # 不是 DMARC
        _q("_dmarc.example.com", ["v=DMARC1; p=reject"]),
        _nx("_dmarc.com"),
    ])
    result = walk(snap, "mail.example.com")
    assert result.hops[0].status == "invalid_record"
    assert result.hops[1].status == "record"
    assert select_organizational_domain(result) == "example.com"


def test_spf_alignment_is_computed_for_both_modes_without_merging():
    """`constants.ALIGN_MODES`：两种模式各出一个布尔值，**不合并**。

    Author = example.com，SPF 检查的域 = mail.example.com → relaxed 真、strict 假。
    若实现只算一个值，两个键里必有一个是错的。
    """
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=reject"]),
        _nx("_dmarc.com"),
        _nx("_dmarc.mail.example.com"),
        _q("mail.example.com", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _q("example.com", ["192.0.2.10"], qtype="A"),
    ])
    outcome = _evaluate(snap, _query("alice@mail.example.com"))
    assert outcome.spf_align == {"relaxed": True, "strict": False}


def test_adkim_strict_requires_strict_alignment():
    """`adkim=s` 时必须用 strict 那一侧：relaxed 对齐不足以判 pass。"""
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=reject; adkim=s; aspf=s"]),
        _nx("_dmarc.com"),
        _nx("_dmarc.mail.example.com"),
        _q("mail.example.com", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _q("example.com", ["192.0.2.10"], qtype="A"),
    ])
    outcome = _evaluate(snap, _query("alice@mail.example.com"))
    assert outcome.spf_align["relaxed"] is True
    assert outcome.spf_align["strict"] is False
    assert outcome.result == "fail", "aspf=s 时 relaxed 对齐不足以免 fail"


def test_alignment_is_reported_for_both_modes_even_when_not_needed():
    """两种对齐都算、都进 subject——诊断"为什么 strict 不过"要能直接看到。"""
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=none"]),
        _nx("_dmarc.com"),
    ])
    subject = _evaluate(snap, _query()).default_subject()
    for key in ("spf_align_relaxed", "spf_align_strict",
                "dkim_align_relaxed", "dkim_align_strict"):
        assert key in subject, "subject 缺 %r" % key
        assert isinstance(subject[key], bool)


def test_psd_y_and_psd_n_produce_different_organizational_domains():
    """**反自证**：`psd=y` 与 `psd=n` 必须给出**不同**的 Organizational Domain。

    B.4.3 的形态：`_dmarc.bank.example.com` 带 `psd=y` → Organizational Domain 是它
    下面一层；`psd=n` → Organizational Domain 就是记录所在的域。
    """
    psd_y = _snapshot([
        _nx("_dmarc.giant.bank.example.com"),
        _q("_dmarc.bank.example.com", ["v=DMARC1; p=none; psd=y"]),
    ])
    psd_n = _snapshot([
        _nx("_dmarc.giant.bank.example.com"),
        _q("_dmarc.bank.example.com", ["v=DMARC1; p=none; psd=n"]),
    ])
    org_y = select_organizational_domain(walk(psd_y, "giant.bank.example.com"))
    org_n = select_organizational_domain(walk(psd_n, "giant.bank.example.com"))
    assert org_y == "giant.bank.example.com"
    assert org_n == "bank.example.com"
    assert org_y != org_n, "psd=y 与 psd=n 被当成同一件事了"


def test_np_and_sp_differ_only_when_author_domain_is_absent():
    """**反自证**：`np=` 与 `sp=` 必须按"Author 域是否存在"分别选中。

    同一份 `_dmarc` 记录、同一份 SPF 结论，只有 Author 域存在性不同 → 处置不同。
    永远取 `sp=`（或永远取 `np=`）的实现会在这里红。
    """

    def run(exists: bool):
        queries = [
            _nx("_dmarc.nosuch.example.com"),
            _q("_dmarc.example.com",
               ["v=DMARC1; p=none; sp=reject; np=quarantine"]),
            _nx("_dmarc.com"),
            _q("other.example.net", ["v=spf1 ip4:192.0.2.0/24 -all"]),
            _nx("_dmarc.other.example.net"),
            _nx("_dmarc.example.net"),
            _q("nosuch.example.com", ["192.0.2.10"], qtype="A") if exists
            else _nx("nosuch.example.com", qtype="A"),
        ]
        return _evaluate(_snapshot(queries), _query("alice@other.example.net"),
                         _message("alice@nosuch.example.com"))

    absent = run(exists=False)
    present = run(exists=True)
    assert (absent.policy_tag, absent.disposition) == ("np", "quarantine")
    assert (present.policy_tag, present.disposition) == ("sp", "reject")
    assert absent.disposition != present.disposition


def test_np_with_unknown_existence_is_undecidable_not_guessed():
    """**K13 的近亲**：带 `np=` 但缺 Author 域存在性证据 → 不猜。

    用 `sp=` 顶上会给出一个"看着确定"的错答案（`sp=` 与 `np=` 不同值时必然错一个）。
    """
    snap = _snapshot([
        _nx("_dmarc.nosuch.example.com"),
        _q("_dmarc.example.com",
           ["v=DMARC1; p=none; sp=reject; np=quarantine"]),
        _nx("_dmarc.com"),
        _q("other.example.net", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _nx("_dmarc.other.example.net"),
        _nx("_dmarc.example.net"),
        # 刻意**不**给 `nosuch.example.com` 的任何查询
    ])
    outcome = _evaluate(snap, _query("alice@other.example.net"),
                        _message("alice@nosuch.example.com"))
    assert outcome.disposition is None
    assert outcome.disposition_status == "undecidable"
    assert any("np=" in warning for warning in outcome.warnings)


def test_np_with_unknown_existence_but_same_outcome_still_decides():
    """`sp=` 与 `np=` 给出**同一个**处置时不算歧义——结论一样，如实说明即可。"""
    snap = _snapshot([
        _nx("_dmarc.nosuch.example.com"),
        _q("_dmarc.example.com",
           ["v=DMARC1; p=none; sp=quarantine; np=quarantine"]),
        _nx("_dmarc.com"),
        _q("other.example.net", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _nx("_dmarc.other.example.net"),
        _nx("_dmarc.example.net"),
    ])
    outcome = _evaluate(snap, _query("alice@other.example.net"),
                        _message("alice@nosuch.example.com"))
    assert outcome.disposition == "quarantine"
    assert outcome.disposition_status == "determined"


def test_removed_tags_are_warned_not_silently_ignored():
    """题面 M3 验收 2：`pct=` 出现即告警，**不得静默忽略**。

    `rf` / `ri` 同属 Appendix C.5.2 的删除清单，逐条断言。
    且 `pct=0` 的语义**不**被采纳：`p=reject` 照常施加。
    """
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=reject; pct=0; rf=afrf; ri=3600"]),
        _nx("_dmarc.com"),
        _q("example.com", ["192.0.2.10"], qtype="A"),
        _q("other.example.net", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _nx("_dmarc.other.example.net"),
        _nx("_dmarc.example.net"),
    ])
    outcome = _evaluate(snap, _query("alice@other.example.net"))
    text = "\n".join(outcome.warnings)
    for tag in ("pct", "rf", "ri"):
        assert "%s=" % tag in text, "%s= 没有进 warnings" % tag
    assert text.count(_REMOVED) >= 3, "三个标签都应各有一条'已被删除'告警"
    assert outcome.disposition == "reject", \
        "pct=0 不得让策略变成 none（那正是'静默采纳已删除语义'）"


def test_test_mode_lowers_policy_one_level():
    """§4.7 的 `t=y`：`reject`→`quarantine`、`quarantine`→`none`、`none` 不变。"""
    base = [
        _nx("_dmarc.com"),
        _q("example.com", ["192.0.2.10"], qtype="A"),
        _q("other.example.net", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _nx("_dmarc.other.example.net"),
        _nx("_dmarc.example.net"),
    ]
    expectations = {
        "v=DMARC1; p=reject; t=y": "quarantine",
        "v=DMARC1; p=quarantine; t=y": "none",
        "v=DMARC1; p=none; t=y": "none",
        "v=DMARC1; p=reject; t=n": "reject",
        "v=DMARC1; p=reject": "reject",
    }
    for record, expected in expectations.items():
        snap = _snapshot([_q("_dmarc.example.com", [record])] + base)
        outcome = _evaluate(snap, _query("alice@other.example.net"))
        assert outcome.disposition == expected, "%r 期望处置 %r，实得 %r" % (
            record, expected, outcome.disposition)


def test_test_mode_is_reported_in_warnings():
    """`t=y` 的降级必须留痕——否则读者看到的处置与记录里的 p= 对不上。"""
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=reject; t=y"]),
        _nx("_dmarc.com"),
        _q("example.com", ["192.0.2.10"], qtype="A"),
        _q("other.example.net", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _nx("_dmarc.other.example.net"),
        _nx("_dmarc.example.net"),
    ])
    outcome = _evaluate(snap, _query("alice@other.example.net"))
    assert outcome.test_mode is True
    assert any("t=y" in warning for warning in outcome.warnings)


def test_author_domain_must_be_extractable_and_unique():
    """§5.3.1：零个或多于一个域 → 判定不成立。两条分别断言，且**不猜**。"""
    snap = _snapshot([_nx("_dmarc.example.com"), _nx("_dmarc.com")])

    no_from = eml.parse(b"Subject: no from\r\n\r\nbody\r\n")
    outcome = evaluate(snap, no_from, _query(), spf=None, dkim=None)
    assert outcome.result == "none"
    assert outcome.author_domain is None

    two_domains = eml.parse(b"From: <a@example.com>, <b@example.net>\r\n\r\nbody\r\n")
    outcome = evaluate(snap, two_domains, _query(), spf=None, dkim=None)
    assert outcome.result == "undecidable"
    assert outcome.author_domain is None, "多域时不得挑一个当 Author Domain"


def test_from_domains_handles_display_name_and_multiple_headers():
    assert from_domains(_message("alice@example.com"))[0] == ["example.com"]

    raw = b"From: Alice <alice@example.com>\r\n\r\nbody\r\n"
    assert from_domains(eml.parse(raw))[0] == ["example.com"]

    raw = b"From: <a@example.com>\r\nFrom: <b@example.net>\r\n\r\nbody\r\n"
    domains, notes = from_domains(eml.parse(raw))
    assert domains == ["example.com", "example.net"]
    assert any("多于一个" in note or "不同" in note for note in notes)


def test_psl_version_and_date_come_from_the_snapshot():
    """题面 §2.5 灰区 3：输出必带 PSL 版本与日期，且来自**快照**（不是随包冻结件）。"""
    snap = from_dict({
        "schema_version": 1,
        "fetched_at": "2026-10-19T18:35:00Z",
        "resolver": "synthetic",
        "psl_version": "1999-01-01_00-00-00_UTC",
        "psl_date": "1999-01-01",
        "queries": [
            _q("_dmarc.example.com", ["v=DMARC1; p=none"]),
            _nx("_dmarc.com"),
        ],
    })
    outcome = _evaluate(snap, _query())
    assert outcome.psl_version == "1999-01-01_00-00-00_UTC"
    assert outcome.psl_date == "1999-01-01"
    subject = outcome.default_subject()
    assert subject["psl_version"] == "1999-01-01_00-00-00_UTC"
    assert subject["psl_date"] == "1999-01-01"
    assert any("PSL 版本" in warning for warning in outcome.warnings), \
        "与随包冻结件版本不同时必须告警（跨版本差异不是 bug，但要能看见）"


def test_psl_organizational_domain_is_reference_only():
    """PSL 值**不**参与判定：B.4.3 形态下两者给出不同答案。

    `giant.bank.example.com` 在 PSL 下 Organizational Domain 是 `example.com`，
    但 §4.10.2 因 `psd=y` 判为 `giant.bank.example.com`。两者必须**分开存**。
    """
    snap = _snapshot([
        _q("_dmarc.giant.bank.example.com", ["v=DMARC1; p=none"]),
        _q("_dmarc.bank.example.com", ["v=DMARC1; p=none; psd=y"]),
    ])
    outcome = _evaluate(snap, _query("alice@giant.bank.example.com"),
                        _message("alice@giant.bank.example.com"))
    assert outcome.organizational_domain == "giant.bank.example.com"
    assert outcome.psl_organizational_domain == "example.com"
    assert outcome.organizational_domain != outcome.psl_organizational_domain, \
        "若两者相等，这条样本就证明不了'PSL 不参与判定'"


def test_alignment_double_computation_is_reported_in_trace():
    """两种模式的对齐都要进 trace（K12 的可指认性）。"""
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=none"]),
        _nx("_dmarc.com"),
        _q("example.com", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _q("example.com", ["192.0.2.10"], qtype="A"),
    ])
    trace: list = []
    _evaluate(snap, _query(), trace=trace)
    notes = [node["note"] for node in trace if node["node"] == "align.spf"]
    assert notes, "SPF 对齐没有进 trace"
    assert "relaxed=" in notes[0] and "strict=" in notes[0]


def test_walk_trace_ids_are_unique_across_multiple_walks():
    """**K12**：一次评估会做多次走查（Author 一次、每个 Identifier 各一次）。

    若所有走查都用 `walk.0` / `walk.1`，trace 里就会撞 id，"这条属于哪次走查"
    变成猜的。节点 id 必须**只由路径决定**——这里的"路径"包含起点域名。
    """
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=none"]),
        _nx("_dmarc.com"),
        # SPF 的标识域是别的子域，会触发第二次走查
        _q("mail.example.com", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _nx("_dmarc.mail.example.com"),
        _q("example.com", ["192.0.2.10"], qtype="A"),
    ])
    trace: list = []
    _evaluate(snap, _query("alice@mail.example.com"), trace=trace)
    walk_ids = [node["node"] for node in trace if node["node"].startswith("walk.")]
    assert len(walk_ids) >= 4, "至少两次走查 × 两跳"
    assert len(walk_ids) == len(set(walk_ids)), \
        "trace 里的 walk 节点 id 撞了：%r" % (walk_ids,)
    # id 里应能看到起点域名，便于肉眼分辨
    assert any("walk.example.com." in node for node in walk_ids)
    assert any("walk.mail.example.com." in node for node in walk_ids)


def test_missing_spf_or_dkim_is_undecidable_not_pass():
    """缺任一基础结论（``None`` = 没算过）→ `undecidable`，**不猜**。"""
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=reject"]),
        _nx("_dmarc.com"),
    ])
    message = _message()
    context = _query()
    spf = spf_evaluate(snap, context, budget=Budget(), trace=[])
    for kwargs in ({"spf": None, "dkim": None},
                   {"spf": spf, "dkim": None},
                   {"spf": None, "dkim": verify_message(message, snap)}):
        outcome = evaluate(snap, message, context, **kwargs)
        assert outcome.result == "undecidable"
        assert "缺少" in outcome.reason
        assert outcome.disposition is None, "缺基础结论时不得给出处置（那是猜）"


def test_invalid_policy_with_valid_rua_falls_back_to_none():
    """§4.10.1：`p` 非法但有有效 `rua` → 按 `p=none` 继续，而不是"不处理"。"""
    snap = _snapshot([
        _q("_dmarc.example.com",
           ["v=DMARC1; p=bogus; rua=mailto:dmarc@example.com"]),
        _nx("_dmarc.com"),
        _q("example.com", ["192.0.2.10"], qtype="A"),
        _q("other.example.net", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _nx("_dmarc.other.example.net"),
        _nx("_dmarc.example.net"),
    ])
    outcome = _evaluate(snap, _query("alice@other.example.net"))
    assert outcome.disposition == "none"
    assert outcome.disposition_status == "determined"


def test_invalid_policy_without_rua_applies_no_processing():
    """§4.10.1：`p` 非法且没有可用 `rua` → 不施加处理（处置为 None，不是 none）。"""
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=bogus"]),
        _nx("_dmarc.com"),
        _q("example.com", ["192.0.2.10"], qtype="A"),
        _q("other.example.net", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _nx("_dmarc.other.example.net"),
        _nx("_dmarc.example.net"),
    ])
    outcome = _evaluate(snap, _query("alice@other.example.net"))
    assert outcome.disposition is None
    assert outcome.disposition_status == "not_applicable"


def test_null_reverse_path_uses_helo_as_spf_domain():
    """空反向路径 → SPF 域是 **HELO 域**，不是"没有身份"。

    §3.2.4 把 SPF 域定义为 "an SPF-validated MAIL FROM identity"，并指向 RFC 7208 §2.4：
    "When the reverse-path is null, this document defines the 'MAIL FROM' identity to be
    the mailbox composed of the local-part 'postmaster' and the 'HELO' identity"。

    所以 `MAIL FROM:<>` + `HELO: mail.example.com` 时，SPF 域是 `mail.example.com`，
    与 Author `example.com` **relaxed 对齐**。
    """
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=reject"]),
        _nx("_dmarc.com"),
        _q("example.com", ["192.0.2.10"], qtype="A"),
        _nx("_dmarc.mail.example.com"),
        _q("mail.example.com", ["v=spf1 ip4:192.0.2.0/24 -all"]),
    ])
    outcome = _evaluate(snap, _query("", helo="mail.example.com"))
    assert outcome.spf_align == {"relaxed": True, "strict": False}
    assert any("RFC 7208 §2.4" in warning for warning in outcome.warnings), \
        "必须写明'空反向路径的身份取 HELO'的依据"
    assert outcome.result == "pass"


def test_null_reverse_path_without_helo_has_no_spf_identifier():
    """空反向路径**且**没有 HELO → 身份无从确定（RFC 7208 §2.4 拼不出 postmaster@…）。"""
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=reject"]),
        _nx("_dmarc.com"),
        _q("example.com", ["192.0.2.10"], qtype="A"),
    ])
    outcome = _evaluate(snap, _query("", helo=None))
    assert outcome.spf_align == {"relaxed": False, "strict": False}
    assert any("没有 HELO" in warning for warning in outcome.warnings)


def test_check_entry_shape_matches_ledger_contract():
    """账本契约：`subject` 只含标量，`tree` 恒为 None（`docs/ledger-format.md` §3.2）。"""
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=none"]),
        _nx("_dmarc.com"),
    ])
    outcome = _evaluate(snap, _query())
    entry = outcome.to_check_entry()
    assert set(entry) == {
        "check_id", "module", "subject", "result", "reason",
        "evidence_ref", "trace", "budget", "tree", "warnings",
    }
    assert entry["budget"] is None
    for key, value in entry["subject"].items():
        assert isinstance(value, (str, int, bool, type(None))), \
            "subject['%s'] 不是标量（渲染层会显示成 repr）：%r" % (key, value)
    assert isinstance(outcome, DmarcResult)


def test_result_is_always_a_known_enum_value():
    """所有路径的 `result` 都必须在 `constants.RESULTS` 里（K4）。"""
    cases = [
        _snapshot([_nx("_dmarc.example.com"), _nx("_dmarc.com")]),
        _snapshot([_q("_dmarc.example.com", ["v=DMARC1; p=reject"]), _nx("_dmarc.com")]),
        _snapshot([_q("_dmarc.example.com", [], rcode="SERVFAIL"), _nx("_dmarc.com")]),
    ]
    for snap in cases:
        assert _evaluate(snap, _query()).result in RESULTS


def test_disposition_never_leaks_outside_the_enum():
    """所有路径产出的处置都必须落在 `constants.DMARC_DISPOSITIONS` 里（或 None）。"""
    snap = _snapshot([
        _q("_dmarc.example.com", ["v=DMARC1; p=bogus; rua=mailto:d@example.com"]),
        _nx("_dmarc.com"),
        _q("example.com", ["192.0.2.10"], qtype="A"),
        _q("other.example.net", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _nx("_dmarc.other.example.net"),
        _nx("_dmarc.example.net"),
    ])
    outcome = _evaluate(snap, _query("alice@other.example.net"))
    assert outcome.disposition in DMARC_DISPOSITIONS or outcome.disposition is None


# ═══ 第 4 层：模块边界（层约束 / 零第三方） ════════════════════════════


def test_dmarc_module_imports_only_allowed_layers():
    """`modules/dmarc.py` 只许 import L1/L2 与 `ledger.check_entry`（`plan/03` §0）。

    L3 模块不得 import 网络层；`ledger.check_entry` 是账本装配的唯一入口，
    `dkim.py` 与 `spf.py` 同样用它。
    """
    import ast

    source = (REPO_ROOT / "mailvault" / "modules" / "dmarc.py").read_text(encoding="utf-8")
    allowed = (
        "__future__", "dataclasses", "typing",
        "mailvault.constants", "mailvault.exits", "mailvault.canonical",
        "mailvault.snapshot", "mailvault.query", "mailvault.eml", "mailvault.psl",
        "mailvault.ledger",
    )
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                # 相对 import（`from ..constants import x`）：把层级折成 `mailvault.` 前缀
                # 再判，否则 level>0 的每一行都会被当成"未知模块"。
                assert node.level == 2, \
                    "dmarc.py 在 mailvault/modules/ 下，只应向上两级 import"
                module = "mailvault." + (node.module or "")
                assert module.startswith(allowed), \
                    "dmarc.py 不得 import %r" % (module,)
            elif node.module:
                assert node.module.startswith(allowed), \
                    "dmarc.py 不得 import %r" % (node.module,)
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in ("__future__", "dataclasses", "typing"), \
                    "dmarc.py 不得 import %r" % (alias.name,)


def test_runtime_does_not_import_reference_implementation():
    """DMARC 侧同样不许 import 第三方（`plan/04` §2.2 的运行时零依赖）。"""
    import ast

    source = (REPO_ROOT / "mailvault" / "modules" / "dmarc.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in (
                    "cryptography", "dkim", "dkimpy", "checkdmarc", "mailauth",
                ), "运行时不得 import %r" % (alias.name,)
        if isinstance(node, ast.ImportFrom) and node.module:
            assert not node.module.startswith(("cryptography", "dkim", "dkimpy")), \
                "运行时不得 import %r" % (node.module,)
