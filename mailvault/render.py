"""`verdict.md` 渲染：**单向**、**零外链**、**逐字节确定**。

三条约束（题面 §5 栏 3 + 交付纪律）：

1. **单向**：`verdict.md` 只由 `verdict.json` 渲染，不含 JSON 里没有的信息。
2. **零外链**：不产生任何 `http(s)://` 链接、不引用外部图片/CSS。读者拿到文件即可读。
3. **确定**：同一份 `verdict.json` 两次渲染逐字节一致 → 不写时间戳、不写主机名、不写绝对路径。
"""

from __future__ import annotations

import re
from typing import Any

from .constants import SPF_MAX_TERMS, STRICT_FORBIDDEN
from .ledger import summarize

#: 禁词表（`--strict-evidence`）**唯一出处是 `constants.STRICT_FORBIDDEN`**：
#: 对账模块在装配期用它自检，渲染期在这里做最后一道闸。两处各写一份必然漂移。
#: 这里保留 `render.STRICT_FORBIDDEN` 这个名字（`tests/test_ledger.py` 与文档都引它）。
__all__ = ["STRICT_FORBIDDEN", "render", "render_diff", "find_forbidden"]

_ABSOLUTE_PATH = re.compile(r"(?:[A-Za-z]:[\\/]|\\\\|/home/|/Users/|/root/)")


def render(ledger: dict[str, Any], *, strict_evidence: bool = False) -> str:
    """渲染人读账本。返回值以 ``\\n`` 结尾，不含 ``\\r``。"""
    meta = summarize(ledger)
    lines: list[str] = []
    add = lines.append

    add("# mailvault 判定账本")
    add("")
    add("## 1 结论摘要")
    add("")
    add("| 项 | 值 |")
    add("| --- | --- |")
    add("| 退出码 | `%d` |" % meta["exit_code"])
    add("| pass | %d |" % meta["counts"].get("pass", 0))
    add("| fail | %d |" % meta["counts"].get("fail", 0))
    add("| undecidable | %d |" % meta["counts"].get("undecidable", 0))
    add("| 账本 id | `%s` |" % meta["ledger_id"])
    add("")

    add("## 2 快照口径")
    add("")
    add("| 项 | 值 |")
    add("| --- | --- |")
    add("| fetched_at（来自快照，非本机时钟） | `%s` |" % (meta["fetched_at"] or "（缺失）"))
    add("| resolver | `%s` |" % (meta["resolver"] or "（缺失）"))
    add("| PSL 版本 | `%s` |" % (meta["psl_version"] or "（缺失）"))
    add("| PSL 日期 | `%s` |" % (meta["psl_date"] or "（缺失）"))
    add("")

    checks = ledger.get("checks") or []
    add("## 3 逐检查条目")
    add("")
    if not checks:
        add("（本次没有可判定的检查项）")
        add("")
    for entry in checks:
        add("### `%s`" % entry.get("check_id", "?"))
        add("")
        add("- 结果：`%s`" % entry.get("result", "?"))
        add("- 理由：%s" % entry.get("reason", ""))
        refs = entry.get("evidence_ref") or []
        add("- 条款：%s" % ("、".join("`%s`" % r for r in refs) if refs else "（无）"))
        subject = entry.get("subject") or {}
        if subject:
            add("- 对象：%s" % "，".join("%s=`%s`" % (k, v) for k, v in sorted(subject.items())))
        trace = entry.get("trace") or []
        if trace:
            add("- 求值轨迹：")
            for node in trace:
                add("  - `%s` %s" % (node.get("node", "?"), node.get("note", "")))
        budget = entry.get("budget")
        if budget:
            add("- 预算账本：")
            add("")
            add("  | 项 | 已用 | 上限 | 条款 |")
            add("  | --- | --- | --- | --- |")
            for key in sorted(budget):
                cell = budget[key] or {}
                add("  | %s | %s | %s | `%s` |" % (
                    key, cell.get("used", "-"), cell.get("limit", "-"), cell.get("ref", "")))
            add("")
        tree = entry.get("tree")
        if tree:
            add("- include 树（完整展开；第 %d 个起的 DNS 查询类 term 标为切点）："
                % (_TREE_CUT_INDEX + 1))
            add("")
            for line in _tree_lines(tree):
                add("  " + line)
            add("")
        warnings = entry.get("warnings") or []
        if warnings:
            add("- 告警：")
            for warning in warnings:
                add("  - %s" % warning)
        add("")

    reconcile = ledger.get("reconcile") or {}
    add("## 4 对账")
    add("")
    entries = reconcile.get("entries") or []
    if not entries:
        add("（本次未做对账，或输入不含 `Authentication-Results`）")
    else:
        for item in entries:
            add("### `%s`" % item.get("class", "?"))
            add("")
            claimed = item.get("claimed") or {}
            recomputed = item.get("recomputed") or {}
            add("- 报文声称：`%s` = `%s`（来源 `%s`，authserv-id `%s`）" % (
                claimed.get("method", "?"), claimed.get("result", "?"),
                claimed.get("source", "?"), claimed.get("authserv_id", "?")))
            add("- 本工具重算：`%s`" % recomputed.get("result", "?"))
            explanations = item.get("explanations") or []
            if explanations:
                add("- 可能解释与验证方法：")
                for index, explanation in enumerate(explanations, 1):
                    add("  %d. **%s** → 验证：%s" % (
                        index, explanation.get("hypothesis", ""), explanation.get("verify", "")))
            warnings = item.get("warnings") or []
            if warnings:
                add("- 告警：")
                for warning in warnings:
                    add("  - %s" % warning)
            add("")
    _render_received_chain(reconcile.get("received_chain"), add)
    notes = reconcile.get("notes") or []
    if notes:
        add("")
        add("对账说明：")
        for note in notes:
            add("- %s" % note)
    add("")

    whatif = ledger.get("whatif")
    if whatif:
        _render_whatif(whatif, add)

    add("## %d 灰区声明" % (6 if whatif else 5))
    add("")
    add("以下结论属于**不可判定**，不表示通过也不表示失败：")
    add("")
    undecidable = [e for e in checks if e.get("result") == "undecidable"]
    if not undecidable:
        add("（本次无不可判定项）")
    for entry in undecidable:
        add("- `%s`：%s" % (entry.get("check_id", "?"), entry.get("reason", "")))
    add("")

    text = "\n".join(lines)
    text = _normalize(text)
    if strict_evidence:
        violations = find_forbidden(text)
        if violations:
            raise ValueError(
                "--strict-evidence 下出现禁词：%s（请改用『与重算不一致，可能解释为 A 或 B』这类措辞）"
                % "、".join(sorted(set(violations)))
            )
    _assert_no_absolute_path(text)
    return text


def find_forbidden(text: str) -> list[str]:
    """返回文本中出现的禁词（统一小写比对，中文原样）。"""
    lowered = text.lower()
    return [word for word in STRICT_FORBIDDEN if word.lower() in lowered]


def _render_received_chain(chain: Any, add: Any) -> None:
    """渲染 Received 链的单调性与时钟回退（`plan/01` §3 的 M4 输出之一）。"""
    if not chain:
        return
    add("")
    add("### Received 链")
    add("")
    add("- 跳数：%s" % chain.get("hop_count", 0))
    monotonic = chain.get("monotonic")
    label = {True: "是", False: "否", None: "判不了（有时间戳解析不出）"}[monotonic]
    add("- 沿链单调（时间不递增）：%s" % label)
    regressions = chain.get("clock_regressions") or []
    if regressions:
        add("- 时钟回退 %d 处：" % len(regressions))
        for item in regressions:
            add("  - 第 %s 跳（物理顺序下标）→ 第 %s 跳：`%s` → `%s`" % (
                item.get("from_index"), item.get("to_index"),
                item.get("from"), item.get("to")))
    else:
        add("- 时钟回退：无")
    add("")
    add("> 时间只取报文头里的字面值，只做相互比较——**从不与系统时钟比较**（K7）。")


def _render_whatif(whatif: Any, add: Any) -> None:
    """渲染反事实差分块（只在 `whatif` 产物里出现）。"""
    add("## 5 反事实差分")
    add("")
    changes = whatif.get("changes") or []
    add("### 施加的变更")
    add("")
    if not changes:
        add("（无）")
    for change in changes:
        add("- `%s=%s` → 改 `%s` 的 `%s`" % (
            change.get("key"), change.get("value"), change.get("record"), change.get("path")))
        add("  - `%s`" % change.get("from"))
        add("  - → `%s`" % change.get("to"))
    add("")
    diff = whatif.get("diff") or {}
    summary = diff.get("summary") or {}
    code = summary.get("exit_code") or {}
    add("### 与基线的差分")
    add("")
    add("- 退出码：`%s` → `%s`" % (code.get("from"), code.get("to")))
    add("- 结构差分条目：%s 处" % diff.get("op_count", 0))
    changed = diff.get("changed_checks") or []
    if changed:
        add("")
        add("| # | 检查项 | 结果 | 变化字段 |")
        add("| --- | --- | --- | --- |")
        for row in changed:
            result = row.get("result") or {}
            add("| %s | `%s` | `%s` → `%s` | %s |" % (
                row.get("index"), row.get("check_id"),
                result.get("from"), result.get("to"),
                "、".join(row.get("changed_fields") or [])))
    add("")
    rua = whatif.get("rua") or {}
    add("### RUA 关联")
    add("")
    add("- 状态：`%s`" % rua.get("status", "?"))
    period = rua.get("report_period") or {}
    add("- 报告期：`%s` → `%s`" % (period.get("begin"), period.get("end")))
    add("- 口径：%s" % rua.get("period_note", ""))
    if rua.get("status") == "undecidable":
        add("- 所需输入：")
        for item in rua.get("required_inputs") or []:
            add("  - %s" % item)
    else:
        affected = rua.get("affected") or []
        add("- 策略 `%s` 会打断 %d 组来源：" % (
            rua.get("policy_under_test"), rua.get("affected_total", 0)))
        if not affected:
            add("  - （报告期内没有既不过 SPF 也不过 DKIM 对齐的来源）")
        for item in affected:
            add("  - `%s`（`%s`，%s 条）：SPF `%s` / DKIM `%s` → 将取 `%s`" % (
                item.get("source_ip"), item.get("header_from"), item.get("count"),
                item.get("spf"), item.get("dkim"), item.get("would_be")))
    add("")


def render_diff(artifact: dict[str, Any], *, strict_evidence: bool = False) -> str:
    """`mailvault diff` 的人读报告。**单向**由 diff 产物渲染，不含 JSON 里没有的信息。"""
    lines: list[str] = []
    add = lines.append
    diff = artifact.get("diff") or {}
    summary = diff.get("summary") or {}

    add("# mailvault 账本差分")
    add("")
    add("## 1 概要")
    add("")
    add("| 项 | 值 |")
    add("| --- | --- |")
    add("| 基线账本 id | `%s` |" % artifact.get("baseline_ledger_id", ""))
    add("| 候选账本 id | `%s` |" % artifact.get("candidate_ledger_id", ""))
    add("| 结构差分条目 | %s |" % diff.get("op_count", 0))
    code = summary.get("exit_code") or {}
    add("| 退出码 | `%s` → `%s` |" % (code.get("from"), code.get("to")))
    counts = summary.get("counts") or {}
    before = counts.get("from") or {}
    after = counts.get("to") or {}
    add("| pass | %s → %s |" % (before.get("pass"), after.get("pass")))
    add("| fail | %s → %s |" % (before.get("fail"), after.get("fail")))
    add("| undecidable | %s → %s |" % (before.get("undecidable"), after.get("undecidable")))
    add("")

    add("## 2 逐检查条目变化")
    add("")
    changed = diff.get("changed_checks") or []
    if not changed:
        add("（两条账本的 checks[] 逐字段一致）")
    else:
        add("| # | 检查项 | 结果 | 变化字段 |")
        add("| --- | --- | --- | --- |")
        for row in changed:
            result = row.get("result") or {}
            add("| %s | `%s` | `%s` → `%s` | %s |" % (
                row.get("index"), row.get("check_id"),
                result.get("from"), result.get("to"),
                "、".join(row.get("changed_fields") or [])))
    add("")

    add("## 3 结构差分（可复算）")
    add("")
    add("把下表施加到基线得到候选；把 `op` 反转（`add`↔`remove`、`set` 的 from/to 互换）")
    add("施加到候选则得到基线——**两个方向都能反推**。")
    add("")
    ops = diff.get("ops") or []
    if not ops:
        add("（无差异）")
    else:
        add("| op | 路径 | from | to |")
        add("| --- | --- | --- | --- |")
        for op in ops:
            add("| `%s` | `%s` | `%s` | `%s` |" % (
                op.get("op"), op.get("path"),
                _cell(op.get("from")), _cell(op.get("to"))))
    add("")

    text = _normalize("\n".join(lines))
    if strict_evidence:
        violations = find_forbidden(text)
        if violations:
            raise ValueError(
                "--strict-evidence 下出现禁词：%s（请改用『与重算不一致，可能解释为 A 或 B』这类措辞）"
                % "、".join(sorted(set(violations))))
    _assert_no_absolute_path(text)
    return text


def _cell(value: Any) -> str:
    """差分表里的单元格：长值截断，换行压平（否则表格会被撑破）。"""
    if value is None:
        return "（无）"
    text = str(value).replace("\n", " ").replace("|", "\\|")
    return text if len(text) <= 80 else text[:77] + "..."


#: include 树的缩进与切点标注。切点序号来自 `constants.SPF_MAX_TERMS`（唯一出处），
#: 不在渲染层写死 10——那会让"预算上限改了但渲染没改"变成一处静默漂移。
_TREE_CUT_INDEX = SPF_MAX_TERMS


def _tree_lines(node: dict[str, Any], depth: int = 0) -> list[str]:
    """把 include 树渲染成缩进列表（人读；不引入 JSON 里没有的信息）。"""
    result = [""]
    domain = node.get("domain", "?")
    mechanism = node.get("mechanism")
    label = mechanism or "根记录"
    result[0] = "%s- `%s` %s（%s）" % (
        "  " * depth, node.get("node_id", "?"), label, domain)
    if node.get("record"):
        result[0] += " 记录 `%s`" % node["record"]
    if node.get("child_result"):
        result[0] += " → `%s`" % node["child_result"]
    if node.get("receiver_would_stop_here"):
        result[0] += " **[切点：收件方会在此 permerror]**"
    if node.get("note"):
        result[0] += " （%s）" % node["note"]
    for child in node.get("children") or []:
        result.extend(_tree_lines(child, depth + 1))
    return result


def _normalize(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    if not text.endswith("\n"):
        text += "\n"
    return text


def _assert_no_absolute_path(text: str) -> None:
    """账本里不得出现本机绝对路径（K9）。

    绝对路径会同时破坏"跨机可比"和"脱敏发布"两件事。
    """
    match = _ABSOLUTE_PATH.search(text)
    if match:
        raise ValueError("渲染结果含绝对路径（K9 禁）：%r" % (match.group(0),))
