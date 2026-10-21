"""三方对账（M5）：`Authentication-Results` 解析、三分类、双解释、Received 链、strict 自检。

测试分四层，每层回答一个不同的问题（与 `tests/test_dmarc.py` 同构）：

1. **RFC 原文给定的语法**。RFC 8601 §2.2 的 `authserv-id [version] ; method=result
   (reason) ptype.property=value` 形态逐条钉死；`method` 后不带 `=` 时 result 默认
   `none` 也是原文写死的。
2. **fixture 逐条对账**（`fixtures/reconcile/*/expected.json`）：`expect` 用**点路径 →
   值**，全部由这里解析并断言——fixture 里写了没测的键会被"未消费键"断言抓住。
3. **独立复算**：三分类的判定逻辑用一份**不经过 `reconcile.py`** 的手算实现算同一批
   (claimed, recomputed) 对，再与模块分类逐条比对；Received 链的单调性也独立手算。
4. **反自证 / 结构性断言**：至少各有一个 `consistent` 与 `contradiction` 样本（只测一侧会
   放过"永远返回同一分类"的实现）；矛盾必须 ≥2 解释且每条带 verify；不可信 authserv-id
   与空可信列表必须 fail-closed；矛盾**不得**折成 `fail`；禁词自检位必须能真的变 false。

第 4 层不是形式主义：一个"永远判 contradiction 且给两条模板解释"的实现能通过第 1–3 层，
只有"必须存在一致样本 + 分类要与手算一致"这两条能把它按住。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from mailvault import eml
from mailvault.constants import RECONCILE_CLASSES, RECONCILE_MIN_EXPLANATIONS
from mailvault.exits import ExitCode
from mailvault.modules.dkim import verify_message
from mailvault.modules.dmarc import evaluate as dmarc_evaluate
from mailvault.modules.reconcile import (
    Claim,
    evaluate,
    parse_authentication_results,
    received_chain,
)
from mailvault.modules.spf import Budget, evaluate as spf_evaluate
from mailvault.query import from_dict as query_from_dict
from mailvault.snapshot import from_dict, load_snapshot

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_ROOT = REPO_ROOT / "fixtures" / "reconcile"

CONTRADICTION = "contradiction"
CONSISTENT = "consistent"
UNDECIDABLE = "undecidable"


# ── 夹具小工具 ──────────────────────────────────────────────────────────


def _fixture_cases() -> list[Path]:
    if not FIXTURE_ROOT.is_dir():
        return []
    return sorted(path for path in FIXTURE_ROOT.iterdir()
                  if path.is_dir() and (path / "expected.json").is_file())


def _pipeline(directory: Path, *, query_data: dict | None = None):
    """跑一遍 SPF → DKIM → DMARC → 对账（**不经过 CLI**，直接调模块）。"""
    snapshot = load_snapshot(directory / "snap.json")
    message = eml.load_eml(directory / "message.eml")
    if query_data is None:
        query = query_from_dict(
            json.loads((directory / "query.json").read_text(encoding="utf-8")),
            source=str(directory / "query.json"))
    else:
        query = query_from_dict(query_data, source="<inline>")

    spf = spf_evaluate(snapshot, query, budget=Budget(), trace=[])
    dkim = verify_message(message, snapshot, trace=[])
    dmarc = dmarc_evaluate(snapshot, message, query, spf=spf, dkim=dkim, trace=[])
    outcome = evaluate(message, spf=spf, dkim=dkim, dmarc=dmarc, query=query,
                       author_domain=dmarc.author_domain)
    return snapshot, message, query, spf, dkim, dmarc, outcome


def _message_from(headers: list[tuple[str, str]], body: bytes = b"body\r\n") -> eml.Message:
    raw = b"".join(("%s: %s\r\n" % pair).encode("utf-8") for pair in headers)
    return eml.parse(raw + b"\r\n" + body)


def _snapshot(queries) -> object:
    return from_dict({
        "schema_version": 1,
        "fetched_at": "2026-10-19T18:35:00Z",
        "resolver": "synthetic",
        "psl_version": "2026-10-20_08-40-56_UTC",
        "psl_date": "2026-10-20",
        "queries": queries,
    })


def _built_message(headers: list[tuple[bytes, bytes]], body: bytes) -> bytes:
    out = b""
    for name, value in headers:
        out += name + b":" + value + b"\r\n"
    return out + b"\r\n" + body


# ── 第 1 层：RFC 8601 §2.2 的语法 ───────────────────────────────────────


def test_authserv_id_and_methods_parsed():
    message = _message_from([
        ("Authentication-Results",
         "mx.example.com; spf=pass smtp.mailfrom=alice@example.com; dkim=pass header.d=example.com"),
    ])
    claims = parse_authentication_results(message)
    assert [item.method for item in claims] == ["spf", "dkim"]
    assert {item.authserv_id for item in claims} == {"mx.example.com"}
    assert [item.result for item in claims] == ["pass", "pass"]
    assert claims[0].property("smtp.mailfrom") == "alice@example.com"
    assert claims[1].property("header.d") == "example.com"


def test_authserv_version_token_is_parsed_separately():
    """RFC 8601 §2.2：`authserv-id` 之后可跟一个整数版本号——它**不是** authserv-id 的一部分。"""
    message = _message_from([("Authentication-Results", "mx.example.com 1; spf=pass")])
    claim = parse_authentication_results(message)[0]
    assert claim.authserv_id == "mx.example.com"
    assert claim.authserv_version == "1"


def test_method_without_value_defaults_to_none():
    """RFC 8601 §2.2：`method` 后不带 `=` 时 result-value 默认 `none`（不是"没解析出来"）。"""
    message = _message_from([("Authentication-Results", "mx.example.com; dkim")])
    claim = parse_authentication_results(message)[0]
    assert claim.method == "dkim"
    assert claim.result == "none"
    assert claim.parsed


def test_reason_in_parentheses_is_captured_and_does_not_break_segments():
    """`(reason)` 里可以出现 `;`——按顶层分号切分的实现会在这里切错段。"""
    message = _message_from([
        ("Authentication-Results", "mx.example.com; spf=fail (a; b) smtp.mailfrom=a@example.com"),
    ])
    claim = parse_authentication_results(message)[0]
    assert claim.result == "fail"
    assert claim.reason == "a; b"
    assert claim.property("smtp.mailfrom") == "a@example.com"


def test_explicit_none_segment_yields_no_claim():
    """`; none` 是 RFC 8601 §2.2 的显式"没有结论"，不是一条 method 声明。"""
    message = _message_from([("Authentication-Results", "mx.example.com; none")])
    claims = parse_authentication_results(message)
    assert len(claims) == 1
    assert claims[0].result is None
    assert claims[0].parse_note, "显式 none 必须说清『这里没有 method 声明』"


def test_unparseable_authserv_id_gets_a_parse_note():
    message = _message_from([("Authentication-Results", "mx.example.com extra token; spf=pass")])
    claim = parse_authentication_results(message)[0]
    assert not claim.parsed
    assert claim.parse_note


def test_empty_header_is_reported_not_crashed():
    message = _message_from([("Authentication-Results", "")])
    claims = parse_authentication_results(message)
    assert len(claims) == 1
    assert not claims[0].parsed


def test_no_authentication_results_yields_no_claims():
    assert parse_authentication_results(_message_from([("From", "a@example.com")])) == []


# ── 第 2 层：fixture 逐条对账（点路径 → 值）─────────────────────────────


_INDEX = re.compile(r"\[(\d+)\]")


def _lookup(root, path: str):
    """解析 `a.b[0].c[1][2]` 形态的点路径（下标可连写）。"""
    node = root
    for part in path.split("."):
        indices = [int(match.group(1)) for match in _INDEX.finditer(part)]
        name = _INDEX.sub("", part)
        if name:
            node = node[name]
        for index in indices:
            node = node[index]
    return node


def _observation(directory: Path) -> dict:
    """把一次对账结论摊成与 `expected.json` 的**点路径同构**的嵌套字典。"""
    _snap, _message, _query, _spf, dkim, _dmarc, outcome = _pipeline(directory)
    return {
        "reconcile": {
            "entries": len(outcome.entries),
            "class": [item.klass for item in outcome.entries],
            "claimed": [item.claimed for item in outcome.entries],
            "recomputed": [item.recomputed for item in outcome.entries],
            "received": outcome.received_chain,
            "trusted_authserv_ids": list(outcome.trusted_authserv_ids),
            "warning": [warning for item in outcome.entries for warning in item.warnings],
            "min_explanations": min(
                (len(item.explanations) for item in outcome.entries), default=0),
            "explanation": [list(item.explanations) for item in outcome.entries],
            "dkim": {"failure_at_kind": _first_failure_kind(dkim)},
        },
        "recon": {"cross_check": outcome.to_check_entry()},
    }


def _first_failure_kind(dkim) -> str | None:
    for signature in dkim.signatures:
        if signature.failure_at:
            return signature.failure_at.get("kind")
    return None


@pytest.mark.parametrize("directory", _fixture_cases(), ids=lambda path: path.name)
def test_fixture_expectations(directory: Path):
    """fixture 里的每个 `expect` 点路径都必须被解析并断言（fixture 全量消费）。"""
    expected = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
    observation = _observation(directory)
    problems: list[str] = []
    for key, want in sorted(expected["expect"].items()):
        try:
            got, ok = _check(observation, key, want)
        except (KeyError, IndexError, TypeError) as exc:
            problems.append("%s：点路径解析失败（%r）" % (key, exc))
            continue
        if not ok:
            problems.append("%s：期望 %r，实得 %r" % (key, want, got))
    assert problems == [], "%s：%s" % (directory.name, "；".join(problems))


def _flatten_dicts(node) -> list[dict]:
    """把"列表套列表套字典"摊平成字典列表（fixture 的点路径只用到这两层）。"""
    out: list[dict] = []
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            out.append(item)
        elif isinstance(item, list):
            stack.extend(item)
    return out


def _check(observation: dict, key: str, want):
    """支持 `expect` 里用到的几种断言形态，返回 `(实得值, 是否通过)`。"""
    if key.endswith(".hypothesis_contains"):
        node = _lookup(observation, key[: -len(".hypothesis_contains")])
        for explanation in _flatten_dicts(node):
            if want in explanation.get("hypothesis", ""):
                return explanation["hypothesis"], True
        return node, False
    if key.endswith(".verify_nonempty"):
        node = _lookup(observation, key[: -len(".verify_nonempty")])
        explanations = _flatten_dicts(node)
        if not explanations:
            return node, False
        for explanation in explanations:
            if not explanation.get("verify", "").strip():
                return explanation, False
        return "all-nonempty", True
    if key.endswith(".contains"):
        node = _lookup(observation, key[: -len(".contains")])
        if isinstance(node, str):
            return node, want in node
        if isinstance(node, dict):
            return node, want in str(node)
        return node, any(want in str(item) for item in node)
    if key.endswith("_gt"):
        got = _lookup(observation, key[: -len("_gt")])
        return got, got > want
    if key.endswith("_ge"):
        got = _lookup(observation, key[: -len("_ge")])
        return got, got >= want
    got = _lookup(observation, key)
    return got, got == want


def test_fixture_shapes_are_the_three_required_scenarios():
    """题面 §3 的 M4 验收三条各要一个样本，且**三分类都要出现**。

    `consistent` 那一侧不能省：只测矛盾会放过一个"永远判 contradiction"的实现。
    """
    assert sorted(path.name for path in _fixture_cases()) == [
        "r1-forwarded", "r2-gateway-body", "r3-untrusted-ar"]

    seen: dict[str, int] = {}
    for directory in _fixture_cases():
        outcome = _pipeline(directory)[-1]
        for entry in outcome.entries:
            seen[entry.klass] = seen.get(entry.klass, 0) + 1
    for klass in RECONCILE_CLASSES:
        assert seen.get(klass, 0) >= 1, "三分类里的 %r 没有任何样本" % klass


def test_every_contradiction_has_at_least_two_explanations_with_verify():
    """题面 M4 硬性要求：每条矛盾 ≥2 条解释，每条带 hypothesis + verify。"""
    total = 0
    for directory in _fixture_cases():
        for entry in _pipeline(directory)[-1].entries:
            if entry.klass != CONTRADICTION:
                continue
            total += 1
            assert len(entry.explanations) >= RECONCILE_MIN_EXPLANATIONS
            for explanation in entry.explanations:
                assert explanation["hypothesis"].strip()
                assert explanation["verify"].strip()
    assert total >= 1, "没有任何矛盾样本——这条断言没被证伪过"


# ── 第 3 层：独立复算 ───────────────────────────────────────────────────


def _hand_class(claimed: str | None, recomputed: str | None, *, trusted: bool) -> str:
    """**不经过 `reconcile.py`** 的手算分类（同样的规则，独立写一遍）。"""
    if not trusted:
        return UNDECIDABLE
    if claimed is None or recomputed is None:
        return UNDECIDABLE
    if recomputed == "undecidable":
        return UNDECIDABLE
    if claimed == "unknown":
        return UNDECIDABLE
    return CONSISTENT if claimed == recomputed else CONTRADICTION


@pytest.mark.parametrize("claimed,recomputed,trusted", [
    ("pass", "pass", True),
    ("fail", "fail", True),
    ("pass", "fail", True),
    ("fail", "pass", True),
    ("none", "none", True),
    ("pass", "pass", False),
    ("pass", "undecidable", True),
    ("unknown", "pass", True),
    ("pass", None, True),
])
def test_classification_matches_hand_computed_truth_table(claimed, recomputed, trusted):
    header = "mx.example.com; spf=%s" % (claimed if claimed is not None else "pass")
    if claimed is None:
        header = "mx.example.com; spf"
    message = _message_from([("Authentication-Results", header), ("From", "a@example.com")])
    spf_stub = _Stub(recomputed)
    query = query_from_dict({
        "mail_from": "alice@example.com", "client_ip": "192.0.2.10",
        "trusted_authserv_ids": ["mx.example.com"] if trusted else [],
    })
    outcome = evaluate(message, spf=spf_stub, dkim=None, dmarc=None, query=query)
    assert outcome.entries[0].klass == _hand_class(claimed, recomputed, trusted=trusted)


class _Stub:
    """只有 ``result`` 的最小求值结论替身（对账只吃结论，不吃内部结构）。"""

    def __init__(self, result: str | None) -> None:
        self.result = result


def test_hand_computed_received_chain_monotonicity():
    """Received 链单调性用独立手算（不调用 `received_chain`）比对。"""
    stamps = [
        "Thu, 1 Jan 2026 00:00:05 +0000",
        "Thu, 1 Jan 2026 00:00:03 +0000",
        "Thu, 1 Jan 2026 00:00:01 +0000",
    ]
    message = _message_from([
        ("Received", " from a.example.org by mx.example.com; " + stamps[0]),
        ("Received", " from b.example.org by a.example.org; " + stamps[1]),
        ("Received", " from c.example.org by b.example.org; " + stamps[2]),
    ])
    chain = received_chain(message)
    assert chain["hop_count"] == 3
    assert chain["monotonic"] is True
    assert chain["clock_regressions"] == []

    # 手算：沿链时间应不递增；把中间一跳改新 10 秒即产生一处回退。
    regressed = _message_from([
        ("Received", " from a.example.org by mx.example.com; Thu, 1 Jan 2026 00:00:05 +0000"),
        ("Received", " from b.example.org by a.example.org; Thu, 1 Jan 2026 00:00:09 +0000"),
    ])
    back = received_chain(regressed)
    assert back["monotonic"] is False
    assert len(back["clock_regressions"]) == 1
    assert back["clock_regressions"][0]["from_index"] == 0
    assert back["clock_regressions"][0]["to_index"] == 1


def test_received_chain_never_consults_the_system_clock():
    """K7：链上时间只做**相互**比较。断言的是"结果与系统时钟无关"——同一份输入
    无论何时跑，输出必须一致（这里用"两次调用逐字节相同"表达）。"""
    message = _message_from([
        ("Received", " from a.example.org by mx.example.com; Thu, 1 Jan 1990 00:00:00 +0000"),
    ])
    assert received_chain(message) == received_chain(message)
    # 1990 年的报文在"与系统时钟比较"的实现里必然被判成回退或过期；这里只按字面值判定。
    assert received_chain(message)["monotonic"] is True


def test_unparsed_received_date_makes_monotonic_undecidable_not_guessed():
    message = _message_from([
        ("Received", " from a.example.org by mx.example.com; not-a-date"),
        ("Received", " from b.example.org by a.example.org; Thu, 1 Jan 2026 00:00:00 +0000"),
    ])
    chain = received_chain(message)
    assert chain["monotonic"] is None, "时间戳解析不出时必须说判不了，不能猜成 True/False"
    assert chain["unparsed_dates"] == 1


# ── 第 4 层：反自证 / 结构性断言 ────────────────────────────────────────


def test_trusted_list_empty_is_not_all_trusted():
    """authres_status #86 的教训：空列表**不等于**全部可信。

    空 trusted_authserv_ids 时任何 AR 都不构成证据 → 全部 undecidable。
    把空理解成"全部可信"，正好把"没配置"变成"来者不拒"。
    """
    message = _message_from([
        ("Authentication-Results", "mx.example.com; spf=pass"),
        ("From", "a@example.com"),
    ])
    query = query_from_dict({
        "mail_from": "alice@example.com", "client_ip": "192.0.2.10",
        "trusted_authserv_ids": [],
    })
    outcome = evaluate(message, spf=_Stub("pass"), dkim=None, dmarc=None, query=query)
    assert outcome.entries[0].klass == UNDECIDABLE
    assert any("全部可信" in note for note in outcome.notes)


def test_untrusted_authserv_id_beats_matching_result():
    """重算结果与头里写的**恰好一致**，也不构成证据（一张不可信的头说什么都不算数）。"""
    message = _message_from([
        ("Authentication-Results", "relay.example.org; spf=pass"),
        ("From", "a@example.com"),
    ])
    query = query_from_dict({
        "mail_from": "alice@example.com", "client_ip": "192.0.2.10",
        "trusted_authserv_ids": ["mx.example.com"],
    })
    outcome = evaluate(message, spf=_Stub("pass"), dkim=None, dmarc=None, query=query)
    assert outcome.entries[0].klass == UNDECIDABLE


def test_method_outside_recompute_scope_is_undecidable():
    """本工具只重算 spf/dkim/dmarc；其它 method 判"不重算"而不是"通过"。"""
    message = _message_from([
        ("Authentication-Results", "mx.example.com; iprev=pass"),
        ("From", "a@example.com"),
    ])
    query = query_from_dict({
        "mail_from": "alice@example.com", "client_ip": "192.0.2.10",
        "trusted_authserv_ids": ["mx.example.com"],
    })
    outcome = evaluate(message, spf=_Stub("pass"), dkim=None, dmarc=None, query=query)
    assert outcome.entries[0].klass == UNDECIDABLE
    assert outcome.entries[0].recomputed["result"] is None


def test_claimed_dkim_with_unknown_domain_is_undecidable():
    """claimed 提到 d=<X>，而报文里没有 X 的签名 → 给不出可比结论（不是"通过"）。"""
    message = _message_from([
        ("Authentication-Results", "mx.example.com; dkim=pass header.d=other.example.com"),
        ("From", "a@example.com"),
    ])
    query = query_from_dict({
        "mail_from": "alice@example.com", "client_ip": "192.0.2.10",
        "trusted_authserv_ids": ["mx.example.com"],
    })
    outcome = evaluate(message, spf=_Stub("pass"), dkim=_DkimStub([]), dmarc=None, query=query)
    assert outcome.entries[0].klass == UNDECIDABLE
    assert outcome.entries[0].recomputed["result"] is None


class _SignatureStub:
    def __init__(self, domain: str, result: str, failure_at=None) -> None:
        self.domain = domain
        self.result = result
        self.failure_at = failure_at


class _DkimStub:
    def __init__(self, signatures) -> None:
        self.signatures = tuple(signatures)


def test_contradiction_is_never_reported_as_fail():
    """矛盾**不得**折成 `fail`：题面风险 ③ 明说这会被读成"你被黑了"。

    `reconcile.cross_check` 汇总条目的映射是：全一致 → pass；有矛盾/判不了 → undecidable。
    """
    message = _message_from([
        ("Authentication-Results", "mx.example.com; spf=pass"),
        ("From", "a@example.com"),
    ])
    query = query_from_dict({
        "mail_from": "alice@example.com", "client_ip": "192.0.2.10",
        "trusted_authserv_ids": ["mx.example.com"],
    })
    outcome = evaluate(message, spf=_Stub("fail"), dkim=None, dmarc=None, query=query)
    assert outcome.entries[0].klass == CONTRADICTION
    entry = outcome.to_check_entry()
    assert entry["result"] == "undecidable"
    assert entry["result"] != "fail"


def test_cross_check_maps_the_three_cases():
    """汇总条目三态：全一致 → pass；无 AR → none；有矛盾/判不了 → undecidable。"""
    query = query_from_dict({
        "mail_from": "alice@example.com", "client_ip": "192.0.2.10",
        "trusted_authserv_ids": ["mx.example.com"],
    })
    consistent = evaluate(
        _message_from([("Authentication-Results", "mx.example.com; spf=pass")]),
        spf=_Stub("pass"), query=query)
    assert consistent.to_check_entry()["result"] == "pass"

    none = evaluate(_message_from([("From", "a@example.com")]), spf=_Stub("pass"), query=query)
    assert none.to_check_entry()["result"] == "none"

    contradiction = evaluate(
        _message_from([("Authentication-Results", "mx.example.com; spf=pass")]),
        spf=_Stub("fail"), query=query)
    assert contradiction.to_check_entry()["result"] == "undecidable"


def test_strict_evidence_selfcheck_can_actually_fail():
    """反自证：禁词自检位必须**可能**为 false。

    只断言"干净样本的 strict_evidence_ok 为 true"是空的——一个 `return True` 的实现也能过。
    这里把禁词放进 claimed 的 `reason`（原样来自输入头），自检位必须变 false。
    """
    clean = evaluate(
        _message_from([("Authentication-Results", "mx.example.com; spf=pass (ok)")]),
        spf=_Stub("pass"),
        query=query_from_dict({
            "mail_from": "alice@example.com", "client_ip": "192.0.2.10",
            "trusted_authserv_ids": ["mx.example.com"]}))
    assert clean.strict_evidence_ok is True

    dirty = evaluate(
        _message_from([("Authentication-Results",
                        "mx.example.com; spf=pass (message was forged)")]),
        spf=_Stub("pass"),
        query=query_from_dict({
            "mail_from": "alice@example.com", "client_ip": "192.0.2.10",
            "trusted_authserv_ids": ["mx.example.com"]}))
    assert dirty.entries[0].strict_evidence_ok is False
    assert dirty.strict_evidence_ok is False


def test_reconcile_render_passes_strict_evidence_on_clean_fixtures(tmp_path):
    """干净 fixture 的对账解释在 `--strict-evidence` 下必须渲染通过（禁词扫描）。

    产物写到 `tmp_path`：**不许写进 `fixtures/`**——那会让卫生门去扫一份测试副产物，
    也会让 `--check` 的字节比对看到不该看到的文件。
    """
    from mailvault.cli import main

    for directory in _fixture_cases():
        code = main([
            "audit", "--snapshot", str(directory / "snap.json"),
            "--eml", str(directory / "message.eml"), "--query", str(directory / "query.json"),
            "--strict-evidence",
            "--json", str(tmp_path / ("%s.json" % directory.name)),
            "--md", str(tmp_path / ("%s.md" % directory.name)),
        ])
        assert code in (0, 1, 2), \
            "%s：strict 模式下不该落到输入错误（3），实得 %r" % (directory.name, code)
        assert (tmp_path / ("%s.md" % directory.name)).is_file()


def test_strict_evidence_rejects_a_forbidden_word_in_the_input_header(tmp_path):
    """`--strict-evidence` 的自检位为 false 时**非零退出**（题面 §3 的 M5 DoD）。

    这不是"渲染层顺带发现"的：对账模块在装配期就把带禁词的输入头挡下（exit 3）。
    换成非 strict 模式则允许描述性用词（账本仍可归档，只是不加这层约束）。
    """
    from mailvault.cli import main

    directory = tmp_path
    snapshot = {
        "schema_version": 1, "fetched_at": "2026-10-19T18:35:00Z",
        "resolver": "synthetic", "psl_version": "2026-10-20_08-40-56_UTC",
        "psl_date": "2026-10-20",
        "queries": [],
    }
    (directory / "snap.json").write_text(json.dumps(snapshot), encoding="utf-8")
    (directory / "query.json").write_text(json.dumps({
        "mail_from": "alice@example.com", "client_ip": "192.0.2.10",
        "trusted_authserv_ids": ["mx.example.com"],
    }), encoding="utf-8")
    (directory / "message.eml").write_bytes(_built_message(
        [(b"Authentication-Results",
          b" mx.example.com; spf=pass (the header looks forged)"),
         (b"From", b" alice@example.com")],
        b"body\r\n"))

    args = [
        "audit", "--snapshot", str(directory / "snap.json"),
        "--eml", str(directory / "message.eml"),
        "--query", str(directory / "query.json"),
        "--json", str(directory / "verdict.json"),
        "--md", str(directory / "verdict.md"),
    ]
    assert main(args + ["--strict-evidence"]) == int(ExitCode.INPUT_ERROR)
    assert main(args) in (0, 1, 2), "非 strict 模式下允许描述性用词"


def test_hygiene_gate_strips_ar_ptype_but_still_catches_a_real_domain(tmp_path):
    """卫生门的 M5 判据改动必须**可证伪**（改判据就要证明它没被改瘫）。

    M5 的对账 fixture 里出现 RFC 8601 的 ``smtp.mailfrom=`` —— 它的形态与两级域名
    无法区分（"TLD" 8 个字母），会被 DOMAIN 正则误判。门改成剥掉
    ``ptype.property=`` 前缀。这里给两份对照：

    - 保留域 + ``smtp.mailfrom=`` → 必须**绿**（剥的是协议关键字，不是数据）；
    - 同位置换上真实域名 → 必须**红**（`=` 右边的域名照旧被扫到）。

    只有第一条的话，一个"把整行都剥掉"的实现也能过——那才是真的放宽了判据。
    """
    import sys

    sys.path.insert(0, str(REPO_ROOT / "tools"))
    from check_fixture_hygiene import scan as hygiene_scan

    fixtures = tmp_path / "fixtures" / "probe"
    fixtures.mkdir(parents=True)
    target = fixtures / "message.eml"

    target.write_bytes(
        b"Authentication-Results: mx.example.com;\r\n"
        b"\tspf=fail smtp.mailfrom=alice@list.example.org\r\n")
    violations, scanned, _exempt = hygiene_scan(tmp_path)
    assert scanned == 1
    assert violations == [], "RFC 8601 的 ptype 关键字不该被判成域名：%r" % (violations,)

    target.write_bytes(
        b"Authentication-Results: mx.example.com;\r\n"
        b"\tspf=fail smtp.mailfrom=alice@mail.google.com\r\n")
    violations, _scanned, _exempt = hygiene_scan(tmp_path)
    assert violations, "ptype 前缀被剥掉之后，= 右边的真实域名必须照样报红"


def test_fixture_generator_is_idempotent():
    """`plan/04` §2.5：生成器 `--check` 必须逐字节比对（跑真实生成器）。"""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "gen_reconcile_fixtures.py"), "--check"],
        cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    assert result.returncode == 0, result.stdout.decode("utf-8", "replace")


def test_reconcile_module_imports_only_allowed_layers():
    """`modules/reconcile.py` 只许 import L1/L2 与 `ledger.check_entry`（`plan/03` §0）。"""
    import ast

    allowed = (
        "__future__", "re", "dataclasses", "typing", "email",
        "mailvault.constants", "mailvault.exits", "mailvault.canonical",
        "mailvault.snapshot", "mailvault.query", "mailvault.eml", "mailvault.psl",
        "mailvault.ledger",
    )
    source = (REPO_ROOT / "mailvault" / "modules" / "reconcile.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                assert node.level == 2, "reconcile.py 在 mailvault/modules/ 下，只应向上两级 import"
                assert ("mailvault." + (node.module or "")).startswith(allowed), \
                    "reconcile.py 不得 import %r" % (node.module,)
            elif node.module:
                assert node.module.startswith(allowed), "reconcile.py 不得 import %r" % node.module
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in ("__future__", "re", "dataclasses", "typing"), \
                    "reconcile.py 不得 import %r" % alias.name


def test_claim_dataclass_is_usable_standalone():
    """`Claim` 是公开的可构造值对象（测试与工具都要能直接造一条）。"""
    claim = Claim(index=0, source="Authentication-Results", authserv_id="mx.example.com",
                  authserv_version=None, method="spf", result="pass", reason=None,
                  properties=(("smtp.mailfrom", "a@example.com"),), raw="")
    assert claim.parsed
    assert claim.property("smtp.mailfrom") == "a@example.com"
    assert claim.to_dict()["method"] == "spf"


def test_snapshot_helper_is_used():
    """`_snapshot` 小工具（SPF/DMARC 侧共用形态）自检，避免它被改成永真。"""
    snap = _snapshot([{"qname": "example.com", "qtype": "TXT", "rcode": "NOERROR",
                       "answer": ["v=spf1 -all"], "ttl": 300}])
    assert snap.resolve("example.com", "TXT").answer == ("v=spf1 -all",)
