"""账本装配：把各模块的结论拼成 `verdict.json` 的结构，并在**构造期**做三条硬校验。

为什么校验收在构造期而不是调用方：

- 调用方校验 = 每个调用点都要记得写一遍，必然漏一处；
- 构造期校验 = 任何一条进账本的路径都经过这里，只有一条路要走。

三条校验：

1. **无 ``evidence_ref`` 的判定不允许进账本**（题面 §5 栏 3 / 扣分红线"无条款支撑的判定"）。
   缺条款时**降级**为 ``undecidable`` 并记 warnings，而不是丢弃条目——丢弃会让"没判定"
   长得像"通过了"。
2. ``result`` 必须是 :data:`mailvault.constants.RESULTS` 里的值。
3. 账本内不得出现裸浮点（由 :func:`mailvault.canonical.dumps` 兜底，这里再早一步报）。
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .canonical import digest
from .constants import LEDGER_SCHEMA_VERSION, RESULTS
from .exits import InternalError, exit_code_for


def check_entry(
    *,
    check_id: str,
    module: str,
    subject: dict[str, Any],
    result: str,
    reason: str,
    evidence_ref: list[str],
    trace: list[dict[str, Any]] | None = None,
    budget: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
    tree: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """构造一条 ``checks[]`` 条目，并做构造期校验。

    ``evidence_ref`` 为空时：结果降级为 ``undecidable``，reason 追加说明，
    warnings 追加一条——**不抛异常**（一条判定缺条款不该炸掉整份账本）。

    ``tree`` 是可选的判定树（`docs/ledger-format.md` §4），只有 SPF 这类
    "递归展开"的判定才有；为 ``None`` 时键仍然存在（值 ``null``），
    这样所有条目的字段集一致，渲染层不需要判"这个键有没有"。
    """
    if not check_id or "." not in check_id:
        raise InternalError("check_id 必须是 '<module>.<name>' 形态: %r" % (check_id,))
    if result not in RESULTS:
        raise InternalError("未知 result=%r（允许值见 constants.RESULTS）" % (result,))

    notes = list(warnings or [])
    refs = list(evidence_ref or [])

    if not refs:
        # 降级而非丢弃：读者必须能看见"这里本该有判定，但缺条款支撑"。
        if result != "undecidable":
            notes.append("缺 evidence_ref，结果已从 %r 降级为 undecidable" % (result,))
        result = "undecidable"
        if "缺条款支撑" not in reason:
            reason = (reason + "；缺条款支撑，判为不可判定").strip("；")

    return {
        "check_id": check_id,
        "module": module,
        "subject": subject,
        "result": result,
        "reason": reason,
        "evidence_ref": refs,
        "trace": list(trace or []),
        "budget": budget,
        "tree": tree,
        "warnings": notes,
    }


def assemble(
    *,
    snapshot_meta: dict[str, Any],
    query: dict[str, Any],
    checks: list[dict[str, Any]],
    reconcile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """装配完整账本。``summary.exit_code`` 由 ``checks`` 的结果集算出（优先级一处定义）。"""
    for entry in checks:
        if "result" not in entry or entry["result"] not in RESULTS:
            raise InternalError("账本条目缺合法 result: %r" % (entry.get("check_id"),))
        if not entry.get("evidence_ref"):
            raise InternalError("账本条目无 evidence_ref（应在 check_entry 里已降级）: %r"
                                % (entry.get("check_id"),))

    results = [entry["result"] for entry in checks]
    code = exit_code_for(results)

    ledger: dict[str, Any] = {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "ledger_id": "",
        "tool_version": __version__,
        "snapshot": snapshot_meta,
        "query": query,
        "checks": checks,
        "reconcile": reconcile or {},
        "summary": {
            "exit_code": int(code),
            "counts": {
                "pass": results.count("pass"),
                "fail": sum(1 for r in results if r in ("fail", "permerror", "softfail")),
                "undecidable": results.count("undecidable"),
            },
        },
    }
    # ledger_id 覆盖"规范化输入 + 判定结果 + 工具版本"：同输入同版本 → 同 id；
    # 先置空再算，避免自指。
    ledger["ledger_id"] = digest({k: v for k, v in ledger.items() if k != "ledger_id"})
    return ledger


def summarize(ledger: dict[str, Any]) -> dict[str, Any]:
    """取出渲染层需要的最小摘要（人读首屏用）。"""
    summary = ledger.get("summary", {})
    snapshot = ledger.get("snapshot", {})
    return {
        "exit_code": summary.get("exit_code", 0),
        "counts": summary.get("counts", {}),
        "ledger_id": ledger.get("ledger_id", ""),
        "fetched_at": snapshot.get("fetched_at", ""),
        "resolver": snapshot.get("resolver", ""),
        "psl_version": snapshot.get("psl_version", ""),
        "psl_date": snapshot.get("psl_date", ""),
    }
