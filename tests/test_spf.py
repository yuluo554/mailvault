"""SPF 求值器（M2）：RFC 7208 测试集 + 预算账本 + include 树 + 宏 + 灰区。

断言分四层，越往下越难腐坏：

1. **测试集通过率**：203 条逐条跑，通过率 ≥ 95%（`plan/05` M2 DoD）。失败逐条
   登记在 `data/rfc7208-failures.md`，且**这份登记表本身被本文件断言**——
   "登记表写了"与"登记表与实跑一致"是两件事。
2. **预算逐格**：term / MX / PTR / void / depth 各自的上限与后果（MUST vs SHOULD）。
3. **include 树切点**：第 11 个 term 起 `receiver_would_stop_here`，且树**不截断**。
4. **灰区**：`%{p}` 缺 PTR → `undecidable`（不默认 fail）、void 超限 → `undecidable`。

另有一条**反自证**断言：`mailvault/` 里不得 import 参照实现（`spf` / `pyspf`）。
参照实现只在开发期用来核对语义，进了运行时依赖就等于把"零依赖"承诺作废。
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import rfc7208_suite as suite_mod
from mailvault import canonical
from mailvault.constants import RESULTS, SPF_MAX_TERMS, SPF_MAX_VOID
from mailvault.exits import InputError
from mailvault.modules.spf import (
    Budget,
    SpfResult,
    check_host,
    evaluate,
)
from mailvault.snapshot import from_dict

REPO_ROOT = Path(__file__).resolve().parent.parent
FAILURES_DOC = REPO_ROOT / "data" / "rfc7208-failures.md"

#: DoD 门槛（`plan/05` M2）。
MIN_PASS_RATE = 0.95

#: 已知的口径差异：用例 id → 为什么本项目判得与上游不同。
#: 每一条都必须在 `data/rfc7208-failures.md` 里有对应小节（本文件会核对）。
KNOWN_DIVERGENCES = {
    "Processing limits/void-over-limit":
        "RFC 7208 §4.6.4 的 void 限制是 SHOULD；本项目按题面 §2.5 灰区 2 判 "
        "undecidable 而不是 permerror",
}


@pytest.fixture(scope="module")
def suite():
    return suite_mod.load_suite()


def _run(case):
    """按用例的信封发件人跑一次求值，必要时迭代补全快照（宏展开的名字）。"""
    local, _, domain = case.mailfrom.partition("@")

    def evaluator(snapshot):
        return check_host(
            snapshot, case.host, domain or case.helo, case.helo,
            local=local or None, sender=case.mailfrom or None)

    return suite_mod.run_case(case, evaluator)


def _snapshot(queries, *, psl_version="2026-10-20_08-40-56_UTC"):
    return from_dict({
        "schema_version": 1,
        "fetched_at": "2026-10-19T18:35:00Z",
        "resolver": "synthetic",
        "psl_version": psl_version,
        "psl_date": "2026-10-20",
        "queries": queries,
    })


def _q(qname, qtype, answer=(), rcode="NOERROR", ttl=300):
    return {"qname": qname, "qtype": qtype, "rcode": rcode,
            "answer": list(answer), "ttl": ttl}


# ── 1. RFC 7208 测试集通过率 ────────────────────────────────────────────


def test_suite_pass_rate_meets_dod(suite):
    """203 条逐条跑，通过率 ≥ 95%。抽样只能证明"抽到的那几条对"。"""
    failures = []
    for case in suite.cases:
        result = _run(case)
        if not case.accepts(result.result):
            failures.append((case.case_id, case.acceptable, result.result))

    passed = suite.case_count - len(failures)
    rate = passed / suite.case_count
    detail = "；".join("%s 期望 %s 实得 %s" % item for item in failures)
    assert rate >= MIN_PASS_RATE, (
        "RFC 7208 通过率 %.1f%%（%d/%d）低于 %.0f%%：%s"
        % (rate * 100, passed, suite.case_count, MIN_PASS_RATE * 100, detail))

    # 失败必须**全部**是已登记的口径差异；出现新的失败 = 登记表过期。
    unexpected = [item for item in failures if item[0] not in KNOWN_DIVERGENCES]
    assert unexpected == [], "出现未登记的口径差异：%r" % (unexpected,)


def test_every_known_divergence_actually_happens(suite):
    """登记表不能有"僵尸条目"：写了差异但实际已经一致，说明登记表在骗人。"""
    for case_id in KNOWN_DIVERGENCES:
        case = suite.find(case_id)
        result = _run(case)
        assert not case.accepts(result.result), (
            "%s 已登记为口径差异，但实际结果 %r 已被上游期望接受——"
            "请从 KNOWN_DIVERGENCES 与 data/rfc7208-failures.md 里删掉这一条"
            % (case_id, result.result))


def test_failures_doc_lists_every_divergence():
    """`data/rfc7208-failures.md` 必须逐条登记，且带上四要素。"""
    assert FAILURES_DOC.is_file(), "M2 DoD 要求失败逐条登记在 data/rfc7208-failures.md"
    text = FAILURES_DOC.read_text(encoding="utf-8")
    for case_id in KNOWN_DIVERGENCES:
        assert case_id in text, "登记表缺用例 %r" % (case_id,)
    # 四要素：用例 id / 期望 / 实际 / 原因（"是否口径差异"另算，见下）
    for needle in ("期望", "实际", "原因", "口径差异"):
        assert needle in text, "登记表缺列/字段：%r" % (needle,)


def test_failures_doc_records_pass_rate():
    """登记表要写清本次实跑的通过率——否则读者无法判断它是哪一版的快照。"""
    text = FAILURES_DOC.read_text(encoding="utf-8")
    assert "203" in text
    assert "202" in text or "99.5" in text


# ── 2. 预算账本逐格 ─────────────────────────────────────────────────────


def test_budget_shape_matches_ledger_format():
    """`budget` 五格，每格 `used` / `limit` / `ref`（`docs/ledger-format.md` §3）。"""
    snap = _snapshot([_q("example.com", "TXT", ["v=spf1 -all"])])
    result = check_host(snap, "192.0.2.1", "example.com", "mail.example.com")
    assert set(result.budget) == {"terms", "mx", "ptr", "void", "depth"}
    for cell in result.budget.values():
        assert {"used", "limit", "ref"} <= set(cell)
        assert cell["ref"].startswith("RFC7208#")
    assert result.budget["void"]["limit_kind"] == "SHOULD"


def test_budget_entries_record_kind_node_and_ref():
    """逐格明细：每条消耗都带 `(kind, node_id, ref)`（题面 M2 输出要求）。"""
    snap = _snapshot([
        _q("example.com", "TXT", ["v=spf1 a:mail.example.com -all"]),
        _q("mail.example.com", "A", ["192.0.2.1"]),
    ])
    result = check_host(snap, "192.0.2.1", "example.com", "mx.example.com")
    assert result.budget_entries
    for entry in result.budget_entries:
        assert entry["kind"] in ("terms", "mx", "ptr", "void", "depth")
        assert entry["node_id"]
        assert entry["ref"].startswith("RFC7208#")


def test_budget_object_is_mutable_and_never_raises_on_overflow():
    """`Budget` 超限**不抛异常**：只置 `limit_hit` 并记下是哪一格。"""
    budget = Budget()
    for _ in range(SPF_MAX_TERMS):
        assert budget.consume("terms", "n0") is True
    assert budget.limit_hit is False
    assert budget.consume("terms", "n0") is False
    assert budget.limit_hit is True
    assert budget.hits == ["terms"]
    # 再超一格不重复记录
    budget.consume("terms", "n0")
    assert budget.hits == ["terms"]


def test_term_limit_eleventh_is_permerror():
    """第 11 个 DNS 查询类 term → permerror（RFC 7208 §4.6.4 MUST）。"""
    queries = [_q("example.com", "TXT",
                  ["v=spf1 " + " ".join("a:m%d.example.com" % i for i in range(1, 12))])]
    for i in range(1, 12):
        queries.append(_q("m%d.example.com" % i, "A", ["192.0.2.%d" % i]))
    snap = _snapshot(queries)
    result = check_host(snap, "198.51.100.1", "example.com", "mx.example.com")
    assert result.result == "permerror"
    assert result.limit_hit is True
    assert result.cut_point is not None
    assert result.cut_point["term_ordinal"] == 11
    assert result.cut_point["receiver_would_stop_here"] is True
    assert "RFC7208#4.6.4" in result.evidence_ref


def test_ten_terms_are_allowed():
    """恰好 10 个 term 不算超限——边界两侧都要断言，否则"上限"可能写成"下限"。"""
    queries = [_q("example.com", "TXT",
                  ["v=spf1 " + " ".join("a:m%d.example.com" % i for i in range(1, 11))
                   + " -all"])]
    for i in range(1, 11):
        queries.append(_q("m%d.example.com" % i, "A", ["192.0.2.%d" % i]))
    snap = _snapshot(queries)
    result = check_host(snap, "198.51.100.1", "example.com", "mx.example.com")
    assert result.result == "fail"          # -all 命中
    assert result.limit_hit is False
    assert result.budget["terms"]["used"] == 10


def test_mx_limit_over_ten_is_permerror():
    """MX 记录超过 10 条 → permerror（MUST），不是"只取前 10 条"。"""
    queries = [_q("example.com", "TXT", ["v=spf1 mx -all"])]
    for i in range(12):
        queries.append(_q("example.com", "MX", ["%d mx%d.example.com" % (i, i)]))
    queries = [entry for entry in queries if not (entry["qname"] == "example.com"
                                                  and entry["qtype"] == "MX")]
    queries.append(_q("example.com", "MX",
                      ["%d mx%d.example.com" % (i, i) for i in range(12)]))
    snap = _snapshot(queries)
    result = check_host(snap, "198.51.100.1", "example.com", "mx.example.com")
    assert result.result == "permerror"
    assert "MX" in result.reason or "mx" in result.reason


def test_ptr_limit_truncates_instead_of_permerror():
    """PTR 超过 10 条 → **只取前 10 条**（RFC 7208 §4.6.4 原文），不是 permerror。

    这一条与 `plan/04` 早期表格里的写法不同，是本棒实测后的更正；
    上游用例 `ptr-limit` 期望 neutral/pass 亦佐证截断语义。
    """
    reverse = "1.2.0.192.in-addr.arpa"
    queries = [
        _q("example.com", "TXT", ["v=spf1 ptr -all"]),
        _q(reverse, "PTR", ["p%d.example.com" % i for i in range(12)]),
    ]
    for i in range(12):
        queries.append(_q("p%d.example.com" % i, "A", ["192.0.2.99"]))
    snap = _snapshot(queries)
    result = check_host(snap, "192.0.2.1", "example.com", "mx.example.com")
    assert result.result == "fail"          # ptr 不匹配 → -all
    assert any("只取前" in warning for warning in result.warnings)
    assert result.budget["ptr"]["used"] == 12


def test_void_limit_exceeded_is_undecidable_not_permerror():
    """void 超限 → undecidable + 告警（SHOULD 级限制，题面 §2.5 灰区 2）。"""
    snap = _snapshot([
        _q("example.com", "TXT", ["v=spf1 a:x1.example.com a:x2.example.com "
                                  "a:x3.example.com ?all"]),
        _q("x1.example.com", "A", [], rcode="NXDOMAIN"),
        _q("x2.example.com", "A", [], rcode="NXDOMAIN"),
        _q("x3.example.com", "A", [], rcode="NXDOMAIN"),
    ])
    result = check_host(snap, "192.0.2.1", "example.com", "mx.example.com")
    assert result.result == "undecidable"
    assert result.result != "fail", "undecidable 不得被折叠成 fail（K4）"
    assert result.budget["void"]["used"] > SPF_MAX_VOID
    assert any("SHOULD" in note for note in result.gray_areas)


def test_must_limit_wins_over_should_limit():
    """同一条记录同时踩 MUST 与 SHOULD 时，报 MUST（那条记录无论如何都是坏的）。"""
    queries = [_q("example.com", "TXT",
                  ["v=spf1 " + " ".join("a:v%d.example.com" % i for i in range(1, 13))
                   + " ?all"])]
    for i in range(1, 13):
        queries.append(_q("v%d.example.com" % i, "A", [], rcode="NXDOMAIN"))
    snap = _snapshot(queries)
    result = check_host(snap, "192.0.2.1", "example.com", "mx.example.com")
    assert result.result == "permerror", result.reason


# ── 3. include 树 ───────────────────────────────────────────────────────


def _chain_snapshot(count: int):
    """根域 include ``inc1..incN``，每个子域 ``-all``。"""
    queries = [_q("root.example.com", "TXT", [
        "v=spf1 " + " ".join("include:inc%d.example.com" % i for i in range(1, count + 1))
        + " -all"])]
    for i in range(1, count + 1):
        queries.append(_q("inc%d.example.com" % i, "TXT", ["v=spf1 -all"]))
    return _snapshot(queries)


def test_tree_is_complete_not_truncated_at_tenth_term():
    """include 树**完整展开**：13 个 include 全部进树，不只前 10 个。

    截断的树会把"后面还有 3 个 include"整件事藏起来——那正是用户想看的。
    """
    result = check_host(_chain_snapshot(13), "192.0.2.1",
                        "root.example.com", "mx.example.com")
    assert result.result == "permerror"
    children = result.tree["children"]
    assert len(children) == 13, "树被截断了：只有 %d 个节点" % len(children)
    assert [child["domain"] for child in children] == [
        "inc%d.example.com" % i for i in range(1, 14)]


def test_tree_marks_the_cut_point_from_eleventh():
    """第 11 个起 `receiver_would_stop_here` 为 true，前 10 个为 false。"""
    result = check_host(_chain_snapshot(13), "192.0.2.1",
                        "root.example.com", "mx.example.com")
    children = result.tree["children"]
    for index, child in enumerate(children, 1):
        assert child["receiver_would_stop_here"] is (index > SPF_MAX_TERMS), (
            "第 %d 个节点的切点标记错了" % index)
    assert children[10]["note"] and "permerror" in children[10]["note"]


def test_tree_root_and_child_ids_are_stable():
    """节点 id 规则：根 `n0`，第 i 个 include `n<i>`，嵌套 `n<i>.<j>`（K12）。"""
    snap = _snapshot([
        _q("root.example.com", "TXT", ["v=spf1 include:a.example.com -all"]),
        _q("a.example.com", "TXT", ["v=spf1 include:b.example.com -all"]),
        _q("b.example.com", "TXT", ["v=spf1 -all"]),
    ])
    result = check_host(snap, "192.0.2.1", "root.example.com", "mx.example.com")
    assert result.tree["node_id"] == "n0"
    assert result.tree["parent"] is None
    first = result.tree["children"][0]
    assert first["node_id"] == "n1"
    assert first["parent"] == "n0"
    assert first["children"][0]["node_id"] == "n1.1"
    assert first["children"][0]["parent"] == "n1"


def test_tree_nodes_carry_record_text_and_flags():
    """每个节点带：被引用域、记录文本、递归结果、是否计 term。"""
    result = check_host(_chain_snapshot(2), "192.0.2.1",
                        "root.example.com", "mx.example.com")
    child = result.tree["children"][0]
    assert child["domain"] == "inc1.example.com"
    assert child["record"] == "v=spf1 -all"
    assert child["consumes_term"] is True
    assert child["child_result"] == "fail"


def test_tree_does_not_affect_the_verdict():
    """树是诊断输出：有没有它，判定结果必须完全一致。

    实现用独立 shadow 上下文画树（独立预算、独立缓存），所以树里那些查询
    不会污染 void 计数与 term 预算。这条断言是那个设计的守门。
    """
    snap = _chain_snapshot(3)
    result = check_host(snap, "192.0.2.1", "root.example.com", "mx.example.com")
    assert result.tree is not None
    # 3 个 include 都是 -all，不匹配；根记录最后一个 -all 命中 → fail
    assert result.result == "fail"
    # 3 个 include 各计 1 term；`all` 不计 term（RFC 7208 §4.6.4 的清单不含 all）。
    assert result.budget["terms"]["used"] == 3


def test_tree_marks_cycle_and_stops():
    """成环的 include 在树上标出来并停止向下，不无限递归。"""
    snap = _snapshot([
        _q("a.example.com", "TXT", ["v=spf1 include:b.example.com -all"]),
        _q("b.example.com", "TXT", ["v=spf1 include:a.example.com -all"]),
    ])
    result = check_host(snap, "192.0.2.1", "a.example.com", "mx.example.com")
    assert result.result == "permerror"      # include 指向自己 → 语法错
    assert result.tree is not None


# ── 4. 宏 ───────────────────────────────────────────────────────────────


def _macro_snapshot(record, extra=()):
    queries = [_q("example.com", "TXT", [record])]
    queries.extend(extra)
    return _snapshot(queries)


@pytest.mark.parametrize("record,expected_answer", [
    # %{d} 当前域；%{o} 发件人域；%{l} 本地部分
    ("v=spf1 a:%{d} -all", "example.com"),
    ("v=spf1 a:%{o} -all", "example.com"),
    ("v=spf1 a:%{l}.example.com -all", "sender.example.com"),
    # %{i} IPv4 点分；%{v} 地址族；%{h} HELO
    ("v=spf1 a:%{i}.example.com -all", "192.0.2.10.example.com"),
    ("v=spf1 a:%{v}.example.com -all", "in-addr.example.com"),
    ("v=spf1 a:%{h} -all", "mail.example.com"),
])
def test_macro_letters_expand(record, expected_answer):
    """七个基础宏字母：展开结果要能被当成域名查（这里直接断言展开后的查询名）。"""
    snap = _macro_snapshot(record, [_q(expected_answer, "A", ["192.0.2.10"])])
    result = check_host(snap, "192.0.2.10", "example.com", "mail.example.com",
                        local="sender", sender="sender@example.com")
    assert result.result == "pass", result.reason


def test_macro_p_uses_validated_ptr():
    """``%{p}`` 有可验证 PTR 时展开成那个名字。"""
    reverse = "10.2.0.192.in-addr.arpa"
    snap = _macro_snapshot(
        "v=spf1 exists:%{p} -all",
        [
            _q(reverse, "PTR", ["mx.example.com"]),
            _q("mx.example.com", "A", ["192.0.2.10"]),
            _q("mx.example.com", "A", ["192.0.2.10"]),
        ])
    result = check_host(snap, "192.0.2.10", "example.com", "mail.example.com")
    # exists 查 A：mx.example.com 有 A → 匹配 → pass
    assert result.result == "pass", result.reason


def test_macro_p_without_ptr_is_undecidable_not_fail():
    """**灰区 4**：``%{p}`` 缺 PTR 时必须 undecidable，不得默认 fail。"""
    reverse = "10.2.0.192.in-addr.arpa"
    snap = _macro_snapshot(
        "v=spf1 exists:%{p}.should.example.com -all",
        [_q(reverse, "PTR", [], rcode="NXDOMAIN")])
    result = check_host(snap, "192.0.2.10", "example.com", "mail.example.com")
    assert result.result == "undecidable", (
        "%%{p} 缺 PTR 时判成了 %r——灰区 4 要求 undecidable" % (result.result,))
    assert result.result != "fail"
    assert any("灰区 4" in note for note in result.gray_areas)


def test_macro_t_is_reported_not_silently_wrong():
    """``%{t}``（时间戳）需要读系统时钟——判定路径零时钟（K7）。

    这不是"不支持"，是确定性的直接后果：判定的产物要能两次运行逐字节一致，
    就不能把墙钟写进去。做法是**报出来**并忽略解释文本（§6.2/4），
    判定结果不受影响——不是静默换成一个别的值。
    """
    snap = _macro_snapshot(
        "v=spf1 -all exp=why.example.com",
        [_q("why.example.com", "TXT", ["sent at %{t}"])])
    result = check_host(snap, "192.0.2.1", "example.com", "mail.example.com")
    assert result.result == "fail"          # 判定不受解释文本影响
    assert any("%{t}" in warning for warning in result.warnings)
    assert result.explanations == ()


def test_macro_p_in_exp_text_does_not_degrade_the_verdict():
    """只做诊断的 ``%{p}``（exp 文本里）**不**把结果降级成 undecidable。"""
    reverse = "10.2.0.192.in-addr.arpa"
    snap = _macro_snapshot(
        "v=spf1 -all exp=why.example.com",
        [
            _q(reverse, "PTR", [], rcode="NXDOMAIN"),
            _q("why.example.com", "TXT", ["connect from %{p}"]),
        ])
    result = check_host(snap, "192.0.2.10", "example.com", "mail.example.com")
    assert result.result == "fail"
    assert result.explanations
    assert result.explanations[0]["text"] == "connect from unknown"


@pytest.mark.parametrize("record", [
    "v=spf1 exists:foo%.example.com ?all",     # % 后面不是 { % - _
    "v=spf1 exists:foo%(ir).example.com ?all",  # 同上
    "v=spf1 exists:%{x}.example.com ?all",      # 未知宏字母
])
def test_invalid_macro_is_permerror(record):
    snap = _macro_snapshot(record)
    result = check_host(snap, "192.0.2.1", "example.com", "mail.example.com")
    assert result.result == "permerror", result.reason


def test_exp_only_macro_letter_outside_exp_is_permerror():
    """``c`` / ``r`` / ``t`` 只许出现在 exp **文本**里（§7.1/8）。"""
    snap = _macro_snapshot("v=spf1 -all exp=%{r}.example.com")
    result = check_host(snap, "192.0.2.1", "example.com", "mail.example.com")
    assert result.result == "permerror", result.reason


def test_uppercase_macro_is_url_escaped():
    """大写宏 = 展开后再 URL 转义（§7.1/26）。"""
    snap = _macro_snapshot(
        "v=spf1 a:%{H} -all",
        [_q("jumpin%27%20jupiter.example.com", "A", ["192.0.2.1"])])
    result = check_host(snap, "192.0.2.1", "example.com", "JUMPIN' JUPITER.example.com")
    assert result.result == "pass", result.reason
    # DNS 名字大小写不敏感：展开出的 `JUMPIN%27%20JUPITER.example.com`
    # 与快照里的 `jumpin%27%20jupiter.example.com` 是同一条查询。
    assert any("jumpin%27%20jupiter.example.com/A" in node["note"]
               for node in result.trace)


# ── 5. 判定语义（七值 + undecidable） ───────────────────────────────────


def test_all_results_are_from_the_single_enum():
    """任何出口的 ``result`` 都必须在 `constants.RESULTS` 里（K4）。"""
    snap = _snapshot([
        _q("pass.example.com", "TXT", ["v=spf1 +all"]),
        _q("fail.example.com", "TXT", ["v=spf1 -all"]),
        _q("soft.example.com", "TXT", ["v=spf1 ~all"]),
        _q("neutral.example.com", "TXT", ["v=spf1 ?all"]),
        _q("perm.example.com", "TXT", ["v=spf1 moo"]),
        _q("none.example.com", "TXT", []),
        _q("temp.example.com", "TXT", [], rcode="TIMEOUT"),
    ])
    observed = set()
    for domain in ("pass", "fail", "soft", "neutral", "perm", "none", "temp"):
        result = check_host(snap, "192.0.2.1", "%s.example.com" % domain,
                            "mx.example.com")
        assert result.result in RESULTS, result.result
        observed.add(result.result)
    assert {"pass", "fail", "softfail", "neutral", "permerror", "none",
            "temperror"} <= observed, "七值没有全覆盖：%r" % (observed,)


def test_data_gap_is_not_treated_as_no_record():
    """**`plan/04` §2.3**：快照里没查过 ≠ 没有记录。

    这条是整个数据纪律的核心断言：把"没抓"读成"没有"，账本会静默变成假绿。
    """
    snap = _snapshot([])     # 一条查询都没有
    result = check_host(snap, "192.0.2.1", "example.com", "mx.example.com")
    assert result.result == "undecidable", (
        "快照缺查询时判成了 %r——必须 undecidable，绝不能是 none" % (result.result,))
    assert result.data_gap == ("example.com", "TXT")


def test_nxdomain_is_a_real_none():
    """``rcode=NXDOMAIN`` 才是"查过、不存在" → none。与数据缺口必须可区分。"""
    snap = _snapshot([_q("example.com", "TXT", [], rcode="NXDOMAIN")])
    result = check_host(snap, "192.0.2.1", "example.com", "mx.example.com")
    assert result.result == "none"
    assert result.data_gap is None


def test_temperror_is_not_fail():
    """temperror 不算 fail（`constants.FAIL_RESULTS` 的口径）。"""
    snap = _snapshot([_q("example.com", "TXT", [], rcode="TIMEOUT")])
    result = check_host(snap, "192.0.2.1", "example.com", "mx.example.com")
    assert result.result == "temperror"


def test_invalid_ip_raises_input_error():
    snap = _snapshot([_q("example.com", "TXT", ["v=spf1 -all"])])
    with pytest.raises(InputError):
        check_host(snap, "not-an-ip", "example.com", "mx.example.com")


def test_ipv4_mapped_ipv6_is_treated_as_ipv4():
    """IPv4-mapped IPv6 按 IPv4 处理（§5/9/2）。"""
    snap = _snapshot([_q("example.com", "TXT", ["v=spf1 ip4:192.0.2.1 -all"])])
    result = check_host(snap, "::FFFF:192.0.2.1", "example.com", "mx.example.com")
    assert result.result == "pass"


def test_empty_sender_uses_helo_domain():
    """空发件人：被检查域取 HELO 域，本地部分取 postmaster（§4.3/2）。"""
    snap = _snapshot([_q("mail.example.com", "TXT", ["v=spf1 ip4:192.0.2.1 -all"])])
    result = check_host(snap, "192.0.2.1", "mail.example.com", "mail.example.com",
                        local=None, sender=None)
    assert result.result == "pass"


def test_evaluate_accepts_a_query_object():
    """``evaluate()`` 按 `query.json` 的语义取域与本地部分。"""
    from mailvault.query import Query

    snap = _snapshot([_q("example.com", "TXT", ["v=spf1 ip4:192.0.2.1 -all"])])
    query = Query(mail_from="someone@example.com", client_ip="192.0.2.1",
                  helo="mail.example.com")
    assert evaluate(snap, query).result == "pass"


# ── 6. 确定性 ───────────────────────────────────────────────────────────


def test_two_runs_are_byte_identical():
    """同一输入两次求值 → 规范化 JSON 逐字节一致（M2 DoD）。"""
    snap = _chain_snapshot(3)
    first = check_host(snap, "192.0.2.1", "root.example.com", "mx.example.com")
    second = check_host(snap, "192.0.2.1", "root.example.com", "mx.example.com")
    payload = lambda result: {                       # noqa: E731
        "result": result.result,
        "reason": result.reason,
        "refs": list(result.evidence_ref),
        "trace": list(result.trace),
        "budget": result.budget,
        "entries": list(result.budget_entries),
        "tree": result.tree,
        "warnings": list(result.warnings),
    }
    assert canonical.dumps(payload(first)) == canonical.dumps(payload(second))
    assert canonical.digest(payload(first)) == canonical.digest(payload(second))


def test_result_has_no_float_and_no_absolute_path():
    """账本内无裸浮点（K8）、无绝对路径（K9）。"""
    snap = _chain_snapshot(2)
    result = check_host(snap, "192.0.2.1", "root.example.com", "mx.example.com")
    payload = {"budget": result.budget, "trace": list(result.trace),
               "tree": result.tree}
    canonical.reject_floats(payload)          # 不抛即通过
    assert "\\" not in canonical.dumps(payload)


# ── 7. 反自证：参照实现不得进运行时 ─────────────────────────────────────


def test_runtime_does_not_import_reference_implementation():
    """`mailvault/` 不得 import pyspf / 任何 SPF 参照实现。

    为什么单列一条：开发期我用 pyspf 核对语义（`plan/04` §2.2 的"独立复算"）。
    若它悄悄进了运行时，零依赖承诺与"确定性可复算"两件事同时作废。
    """
    forbidden = {"spf", "pyspf", "pyspfquery", "spfquery"}
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


def test_spf_result_to_check_entry_carries_evidence():
    """转成账本条目时带条款、轨迹、预算、树；缺条款会被 ledger 降级（K5）。"""
    snap = _snapshot([_q("example.com", "TXT", ["v=spf1 -all"])])
    result = check_host(snap, "192.0.2.1", "example.com", "mx.example.com")
    entry = result.to_check_entry()
    assert entry["check_id"] == "spf.check_host"
    assert entry["result"] == "fail"
    assert entry["evidence_ref"]
    assert entry["budget"] is not None
    assert "tree" in entry


def test_spf_result_is_frozen():
    """结果对象不可变：判定发出去之后不许被下游改。"""
    snap = _snapshot([_q("example.com", "TXT", ["v=spf1 -all"])])
    result = check_host(snap, "192.0.2.1", "example.com", "mx.example.com")
    assert isinstance(result, SpfResult)
    with pytest.raises(Exception):
        result.result = "pass"  # type: ignore[misc]
