"""`verdict.md` 渲染：**单向**、**零外链**、**逐字节确定**。

三条约束（题面 §5 栏 3 + 交付纪律）：

1. **单向**：`verdict.md` 只由 `verdict.json` 渲染，不含 JSON 里没有的信息。
2. **零外链**：不产生任何 `http(s)://` 链接、不引用外部图片/CSS。读者拿到文件即可读。
3. **确定**：同一份 `verdict.json` 两次渲染逐字节一致 → 不写时间戳、不写主机名、不写绝对路径。
"""

from __future__ import annotations

import re
from typing import Any

from .ledger import summarize

#: 禁词表（`--strict-evidence`）。只在 strict 模式下生效——非 strict 模式允许描述性用词，
#: 但仍建议避免，因为账本会被归档、被转发。
STRICT_FORBIDDEN = (
    "攻击",
    "伪造",
    "被黑",
    "黑客",
    "hacked",
    "forged",
    "attack",
    "compromised",
)

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
            add("- 报文声称：`%s` = `%s`（来源 `%s`）" % (
                claimed.get("method", "?"), claimed.get("result", "?"), claimed.get("source", "?")))
            add("- 本工具重算：`%s`" % recomputed.get("result", "?"))
            explanations = item.get("explanations") or []
            if explanations:
                add("- 可能解释与验证方法：")
                for index, explanation in enumerate(explanations, 1):
                    add("  %d. **%s** → 验证：%s" % (
                        index, explanation.get("hypothesis", ""), explanation.get("verify", "")))
            add("")
    add("")

    add("## 5 灰区声明")
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
