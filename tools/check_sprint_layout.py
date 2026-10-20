#!/usr/bin/env python3
"""布局门（方法论装订第②件）：把"项目还长在方法论上"变成可跑红的断言。

判据集沿用 `ai-tool-project-sprint` 的 `references/templates/check-sprint-layout.mjs`
（Node 实现），本文件是 **Python 重写**——**判据本身不改**，只换实现语言（项目零第三方依赖）。

判据一律落**仓库内文件**（不读 git 元数据：浅克隆下 tag / 历史深度会翻转）。

退出码：0 全绿 / 1 有 FAIL / 2 用法错误。

变异验证（10 组，逐组必须变红；见 `tools/verify_layout_gate.py`）：
  M01 删 AGENTS.md                               → LAYOUT.FILES
  M02 删 plan/02                                 → LAYOUT.FILES
  M03 删 plan/00 顶部装订行                       → LAYOUT.BINDING_HEAD
  M04 改掉 plan/01 的必需小节标题                 → LAYOUT.SECTIONS
  M05 文档点名不存在的 tools 脚本                 → LAYOUT.DOC_TOOLS
  M06 单副本状态翻转                              → LAYOUT.STATUS
  M07 删一份交接单                                → LAYOUT.HANDOFFS
  M08 交接单缺一节                                → LAYOUT.HANDOFFS
  M09 缺口列写回已完成里程碑                      → LAYOUT.GAPS
  M10 发布留档缺覆盖对账                          → LAYOUT.RELEASE
  （LAYOUT.LEDGER 由 M09 同族覆盖：台账行写回 ⬜ 待 M<k>）
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_FILES = [
    "AGENTS.md",
    "README.md",
    "data/README.md",
    "plan/00-README总览.md",
    "plan/01-题目文档.md",
    "plan/02-架构与技术选型.md",
    "plan/03-模块详设.md",
    "plan/04-数据计划.md",
    "plan/05-里程碑与发布.md",
    "plan/06-交付对标与决策.md",
]

#: 三个锚点必须**同现于一行**（方法论名 + 布局门命令 + 装订日期）；顺序无关（前瞻语义）。
#: 写成"或"关系会把残句也判绿（"断言了全世界"的一支）；写死顺序会产生假红。
BINDING_LINE = re.compile(
    r"^>(?=.*ai-tool-project-sprint)(?=.*check_sprint_layout)(?=.*20\d{2}-\d{2}-\d{2}).*$", re.M
)

REQUIRED_SECTIONS = {
    "plan/00-README总览.md": ["文档索引", "决策记录", "承诺-证据台账", "里程碑"],
    "plan/01-题目文档.md": ["任务要求", "评分标准", "边界与非目标"],
    "plan/02-架构与技术选型.md": ["分层", "构建"],
    "plan/04-数据计划.md": ["数据清单", "真值纪律", "数值口径"],
    "plan/05-里程碑与发布.md": ["DoD", "已知未验证项"],
    "plan/06-交付对标与决策.md": ["评分对标", "风险登记"],
    "data/README.md": ["依据查证记录", "数值口径"],
}

#: HANDOFF 七节（硬约束①）。项目自定更细的格式 = 合法超集：只断言"必需节都存在"。
HANDOFF_SECTIONS = ["当前进度", "当前事实", "待办", "既定口径", "环境坑", "DoD", "命令速查"]

#: 项目**已声明**的豁免（门必须复用，别另立更严的一套）。
EXEMPT_MILESTONES = [0]

#: 状态副本：同一里程碑在这几处的状态必须**互相一致**。
#: 判据不取任何一个副本当真值源（那会让"在真值副本里改坏"变成永久不可见）。
STATUS_COPIES = [
    "plan/00-README总览.md",
    "plan/05-里程碑与发布.md",
    "README.md",
    "plan/06-交付对标与决策.md",
]

#: 只认"状态行"：表格行且首格就是里程碑号。自由文本（"当前状态：…"）不参与判定，
#: 否则"未验证项保持 ⬜"这类描述会被读成"M6 仍挂 ⬜"（张冠李戴的假红）。
STATUS_LINE = re.compile(r"^\|\s*\*{0,2}M(\d+)\b")
PENDING_MARKERS = ["⬜", "🟡", "未开始", "未执行", "待执行", "待确认"]

DOC_TOOLS_PATTERN = re.compile(r"tools/[\w.-]+\.(?:py|mjs|js|cjs|sh|ps1)")
DOC_TOOLS_EXEMPT: set[str] = set()  # 形如 "tools/xxx.py"：确实不打算实现时逐条登记理由

#: 发布里程碑（题面 §8：M6 = 发布）。它未 ✅ 时 LAYOUT.RELEASE 报 SKIP 而不是 FAIL。
FINAL_MILESTONE = 6


class Gate:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.results: list[tuple[str, str, str]] = []
        self.scanned = {"docs": 0, "handoffs": 0, "handoff_files": 0, "copies": 0, "doc_tools": 0}

    # ── 基础设施 ────────────────────────────────────────────────────────
    def add(self, status: str, check_id: str, detail: str) -> None:
        self.results.append((status, check_id, detail))

    def read(self, rel: str) -> str | None:
        path = self.root / rel
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8")

    # ── 判据 ────────────────────────────────────────────────────────────
    def check_required_files(self) -> None:
        missing = [rel for rel in REQUIRED_FILES if not (self.root / rel).is_file()]
        self.scanned["docs"] = len(REQUIRED_FILES) - len(missing)
        self.add(
            "FAIL" if missing else "PASS",
            "LAYOUT.FILES",
            ("缺: " + ",".join(missing)) if missing else "%d 份齐备" % len(REQUIRED_FILES),
        )

    def check_binding_head(self) -> None:
        text = self.read("plan/00-README总览.md") or ""
        ok = BINDING_LINE.search(text) is not None
        self.add(
            "PASS" if ok else "FAIL",
            "LAYOUT.BINDING_HEAD",
            "plan/00 顶部装订行三锚点齐" if ok
            else "plan/00 顶部缺装订行（需同一行同现：方法论名 + 布局门命令 + 日期）",
        )

    def check_sections(self) -> None:
        bad = []
        for rel, needles in REQUIRED_SECTIONS.items():
            text = self.read(rel)
            if text is None:
                continue  # 缺文件由 LAYOUT.FILES 报，避免重复红
            missing = [n for n in needles if not _has_heading(text, n)]
            if missing:
                bad.append("%s 缺 %s" % (rel, "/".join(missing)))
        self.add(
            "FAIL" if bad else "PASS",
            "LAYOUT.SECTIONS",
            "；".join(bad) if bad else "%d 份文件小节齐备" % len(REQUIRED_SECTIONS),
        )

    def check_doc_tools(self) -> None:
        docs = ["AGENTS.md", "README.md"]
        plan_dir = self.root / "plan"
        if plan_dir.is_dir():
            docs.extend("plan/" + p.name for p in sorted(plan_dir.glob("*.md")))
        referenced: list[str] = []
        seen: set[str] = set()
        for rel in docs:
            text = self.read(rel)
            if text is None:
                continue
            for match in DOC_TOOLS_PATTERN.findall(text):
                if match not in seen:
                    seen.add(match)
                    referenced.append(match)
        if not referenced:
            # 非空跑自证：一份文档都没提 tools/ 时，这条判据什么也没证明。
            self.add(
                "FAIL",
                "LAYOUT.DOC_TOOLS",
                "扫了 %d 份文档，0 处 tools/ 引用——判据是空的（阳性对照失败）" % len(docs),
            )
            return
        self.scanned["doc_tools"] = len(referenced)
        missing = [rel for rel in referenced if rel not in DOC_TOOLS_EXEMPT and not (self.root / rel).is_file()]
        self.add(
            "FAIL" if missing else "PASS",
            "LAYOUT.DOC_TOOLS",
            ("文档点名但不存在的工具: " + ",".join(missing)) if missing
            else "%d 个文档点名的 tools/ 脚本全部在位" % len(referenced),
        )

    def collect_states(self) -> dict[int, set[str]]:
        states: dict[int, set[str]] = {}

        def note(k: int, state: str) -> None:
            states.setdefault(k, set()).add(state)

        for rel in STATUS_COPIES:
            text = self.read(rel)
            if text is None:
                continue
            self.scanned["copies"] += 1
            for line in text.split("\n"):
                match = STATUS_LINE.match(line)
                if not match:
                    continue
                pending = any(mark in line for mark in PENDING_MARKERS)
                note(int(match.group(1)), "pending" if pending else "done")
        return states

    def check_status_agreement(self, states: dict[int, set[str]]) -> None:
        conflicts = []
        for k in sorted(states):
            if len(states[k]) > 1:
                conflicts.append("M%d 在副本间状态不一致（%s）" % (k, " vs ".join(sorted(states[k]))))
        self.add(
            "FAIL" if conflicts else "PASS",
            "LAYOUT.STATUS",
            "；".join(conflicts) if conflicts
            else "%d 处副本 × %d 个里程碑 状态全一致" % (self.scanned["copies"], len(states)),
        )

    def check_handoffs(self, done: set[int]) -> None:
        problems = []
        plan_dir = self.root / "plan"
        # 非空跑自证的另一半：把"盘上有几份交接单"与"本次按判据要求检查了几份"分开报。
        self.scanned["handoff_files"] = len(list(plan_dir.glob("HANDOFF-M*.md"))) if plan_dir.is_dir() else 0
        for k in sorted(done):
            if k in EXEMPT_MILESTONES:
                continue
            rel = "plan/HANDOFF-M%d.md" % k
            text = self.read(rel)
            if text is None:
                problems.append(rel + "(缺)")
                continue
            self.scanned["handoffs"] += 1
            lack = [n for n in HANDOFF_SECTIONS if not _has_heading(text, n)]
            if lack:
                problems.append("%s(缺节: %s)" % (rel, "/".join(lack)))
        self.add(
            "FAIL" if problems else "PASS",
            "LAYOUT.HANDOFFS",
            "；".join(problems) if problems
            else "%d 份交接单齐（M0 已声明豁免）" % self.scanned["handoffs"],
        )

    def check_stale_gaps(self, done: set[int]) -> None:
        rel = "plan/06-交付对标与决策.md"
        text = self.read(rel)
        if text is None:
            return  # 缺文件由 LAYOUT.FILES 报
        lines = text.split("\n")
        header_idx = None
        for idx, line in enumerate(lines):
            if line.startswith("|") and "缺口" in line:
                header_idx = idx
                break
        if header_idx is None:
            self.add("FAIL", "LAYOUT.GAPS", "plan/06 找不到含『缺口』表头的表（判据表搬走了？）")
            return
        # 按表头定位列号再取单元格——"行里含『缺口』二字"抓不到"数据行把值填进该列"的真实故障。
        header_cells = [c.strip() for c in lines[header_idx].strip().strip("|").split("|")]
        try:
            col = [i for i, c in enumerate(header_cells) if "缺口" in c][0]
        except IndexError:
            self.add("FAIL", "LAYOUT.GAPS", "plan/06『缺口』表头里定位不到列号")
            return
        # 扫描面 = 该表头之后的**连续表格行**（遇到第一个非表格行即止）。
        # 不扫到文件末尾：后面章节的表格也会命中，那是假红。
        stale = []
        scanned_rows = 0
        for line in lines[header_idx + 1:]:
            if not line.startswith("|"):
                break
            scanned_rows += 1
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if col >= len(cells):
                continue
            cell = cells[col]
            if set(cell) <= set("-: "):
                continue  # 分隔行
            # 匹配前剥掉行内代码与 .md 文件名：文件名里的 M6 是标识符，不是状态引用。
            probe = re.sub(r"`[^`]*`", "", cell)
            probe = re.sub(r"[\w\-/]+\.md", "", probe)
            hits = {int(m) for m in re.findall(r"(?<![0-9A-Za-z])M(\d+)(?![0-9])", probe)}
            for k in sorted(hits & done):
                stale.append("plan/06 缺口列仍提 M%d: %s" % (k, cell))
        # 空集是合法终态，但必须与"没扫到表"可区分 → 行数进结论。
        self.add(
            "FAIL" if stale else "PASS",
            "LAYOUT.GAPS",
            "；".join(stale) if stale
            else "plan/06 缺口列扫了 %d 行，无已 ✅ 里程碑" % scanned_rows,
        )

    def check_ledger(self, done: set[int]) -> None:
        """承诺-证据台账是状态的第四份副本，且不在"状态表"里，必须单独一条判据。"""
        text = self.read("plan/00-README总览.md") or ""
        lines = text.split("\n")
        header_idx = None
        for idx, line in enumerate(lines):
            if line.startswith("|") and "承诺" in line and "状态" in line:
                header_idx = idx
                break
        if header_idx is None:
            self.add("FAIL", "LAYOUT.LEDGER", "plan/00 找不到『承诺-证据台账』表头（承诺项与状态列）")
            return
        self.scanned["copies"] += 1  # 它是第四份状态副本，要进"这轮扫到了几个"的计数
        bad = []
        rows = 0
        for line in lines[header_idx + 1:]:
            if not line.startswith("|"):
                break
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if not cells or set("".join(cells)) <= set("-: "):
                continue
            rows += 1
            status = cells[-1]
            if not re.search(r"[⬜🟡]|未开始|待 M\d|待开工", status):
                continue
            hits = {int(m) for m in re.findall(r"(?<![0-9A-Za-z])M(\d+)(?![0-9])", status)}
            for k in sorted(hits & done):
                bad.append("台账行仍挂未完成（M%d）: %s" % (k, status[:60]))
        self.add(
            "FAIL" if (bad or rows == 0) else "PASS",
            "LAYOUT.LEDGER",
            "台账表 0 行——判据空跑" if rows == 0
            else ("；".join(bad) if bad else "台账 %d 行，已成 ✅ 的里程碑无未完成标记" % rows),
        )

    def check_release(self, done: set[int]) -> None:
        if FINAL_MILESTONE not in done:
            self.add("SKIP", "LAYOUT.RELEASE", "发布里程碑 M%d 未完成，发布留档尚不适用" % FINAL_MILESTONE)
            return
        final = FINAL_MILESTONE
        release = self.read("plan/RELEASE-M%d.md" % final)
        wrapup = self.read("plan/WRAPUP-M%d.md" % final)
        if release is None and wrapup is None:
            self.add("FAIL", "LAYOUT.RELEASE", "缺 plan/RELEASE-M%d.md 或 plan/WRAPUP-M%d.md" % (final, final))
            return
        if release is None:
            self.add("PASS", "LAYOUT.RELEASE", "WRAPUP 形态")
            return
        columns = re.search(r"^##\s*一、tag 前事实", release, re.M) is not None and \
            re.search(r"^##\s*二、tag 后", release, re.M) is not None
        coverage = re.search(r"^#{2,3}.*覆盖对账", release, re.M) is not None
        rows = len(re.findall(r"^\|.*(?:实现|不适用|待首推).*\|$", release, re.M))
        ok = columns and coverage and rows >= 3
        self.add(
            "PASS" if ok else "FAIL",
            "LAYOUT.RELEASE",
            "两栏:%s 覆盖对账:%s 三态行:%d" % (columns, coverage, rows),
        )

    # ── 执行 ────────────────────────────────────────────────────────────
    def run(self) -> int:
        steps = [
            self.check_required_files,
            self.check_binding_head,
            self.check_sections,
            self.check_doc_tools,
        ]
        for step in steps:
            try:
                step()
            except Exception as exc:  # 门永不崩：报一条 FAIL 并继续
                self.add("FAIL", step.__name__, "内部错误: %r" % (exc,))

        states = self.collect_states()
        done = {k for k, s in states.items() if "done" in s}
        for step in (
            lambda: self.check_status_agreement(states),
            lambda: self.check_handoffs(done),
            lambda: self.check_stale_gaps(done),
            lambda: self.check_ledger(done),
            lambda: self.check_release(done),
        ):
            try:
                step()
            except Exception as exc:
                self.add("FAIL", "LAYOUT.INTERNAL", "内部错误: %r" % (exc,))

        fails = [r for r in self.results if r[0] == "FAIL"]
        skips = [r for r in self.results if r[0] == "SKIP"]
        out = ["布局门（方法论装订）· 判据只落仓库内文件", "=" * 60]
        for status, check_id, detail in self.results:
            out.append("%-4s  %-22s %s" % (status, check_id, detail))
        out.append("=" * 60)
        out.append(
            "这轮扫到：文档 %d / 交接单 %d（盘上 %d）/ 状态副本 %d / tools 引用 %d"
            % (
                self.scanned["docs"],
                self.scanned["handoffs"],
                self.scanned["handoff_files"],
                self.scanned["copies"],
                self.scanned["doc_tools"],
            )
        )
        out.append("结论: %s" % ("全绿" if not fails else "%d 项 FAIL（另 %d 项 SKIP）" % (len(fails), len(skips))))
        sys.stdout.write("\n".join(out) + "\n")
        return 0 if not fails else 1


def _has_heading(text: str, needle: str) -> bool:
    """判据锚定到**标题行**而不是全文包含：自由文本里出现关键词不等于有这一节。"""
    return re.search(r"^#{1,4}[^\n]*" + re.escape(needle), text, re.M) is not None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="布局门（方法论装订）")
    parser.add_argument("--root", default=None, help="仓库根目录（默认本脚本上一级）")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else ROOT
    return Gate(root).run()


if __name__ == "__main__":
    sys.exit(main())
