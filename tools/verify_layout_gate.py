"""布局门的变异验证（方法论装订的"门必须能红"证据）。

做法：把仓库（只拷布局门会读的文件）复制到临时目录 → 施加**一处**故障 → 跑**该副本里**的布局门
→ 断言退出码 1 且报出**预期的那条判据 id** → 删除副本。

判据有几条，变异就覆盖几条（同一条门里两个 add() 只测一个 = 另一条是未经证伪的假门）。

每条变异遵守三连断言：替换前 marker 存在 / 替换后文件已变 / 结束时副本被删除。

用法：
    py -3.12 tools/verify_layout_gate.py
退出码：0 全部如期变红 / 1 有变异没红（= 假门）。
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE = "tools/check_sprint_layout.py"

COPY_FILES = [
    "AGENTS.md",
    "README.md",
    "data/README.md",
    "plan",
    "tools/check_sprint_layout.py",
]

STATUS_COPIES = [
    "plan/00-README总览.md",
    "plan/05-里程碑与发布.md",
    "README.md",
    "plan/06-交付对标与决策.md",
]


def _copy_repo(dest: Path) -> None:
    for rel in COPY_FILES:
        source = ROOT / rel
        target = dest / rel
        if source.is_dir():
            shutil.copytree(str(source), str(target))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(source), str(target))


def _rewrite(root: Path, rel: str, old: str, new: str) -> None:
    """替换三连：marker 存在 → 已变 → 结果里含 new。"""
    path = root / rel
    before = path.read_text(encoding="utf-8")
    assert old in before, "变异 marker 不存在（%s）：%r" % (rel, old[:60])
    after = before.replace(old, new, 1)
    assert after != before, "变异没有产生字节变化（%s）" % rel
    path.write_bytes(after.encode("utf-8"))
    assert new in path.read_text(encoding="utf-8")


def _delete(root: Path, rel: str) -> None:
    path = root / rel
    assert path.exists(), "要删的文件不存在: %s" % rel
    if path.is_dir():
        shutil.rmtree(str(path))
    else:
        path.unlink()
    assert not path.exists()


def _mark_done(root: Path, milestone: int) -> None:
    """把某里程碑在**全部有该状态行的副本**里标成完成。

    HANDOFFS / LEDGER / RELEASE 判据只在"里程碑已完成"时才有断言面，
    所以必须先**构造**那个状态再破坏——否则测的是"当前进度"，不是门的语义。
    """
    touched = 0
    for rel in STATUS_COPIES:
        path = root / rel
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8").split("\n")
        hits = [i for i, ln in enumerate(lines) if re.match(r"^\|\s*\*{0,2}M%d\b" % milestone, ln)]
        if not hits:
            continue
        lines[hits[0]] = re.sub(r"⬜[^|]*", "✅ 2026-10-21 ", lines[hits[0]])
        path.write_bytes("\n".join(lines).encode("utf-8"))
        touched += 1
    assert touched >= 3, "只改到 %d 处状态副本，构造失败" % touched


def _write_handoff(root: Path, milestone: int) -> None:
    body = (
        "## 一、当前进度\n## 二、当前事实\n## 三、待办\n## 四、既定口径\n"
        "## 五、环境坑\n## 六、DoD\n## 七、关键命令速查\n"
    )
    (root / ("plan/HANDOFF-M%d.md" % milestone)).write_bytes(body.encode("utf-8"))


def _run_gate(root: Path) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, str(root / GATE)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=str(root),
    )
    return result.returncode, result.stdout.decode("utf-8", "replace")


# ── 变异清单：一条变异一个预期判据 id ───────────────────────────────────


def m01_delete_agents(root: Path) -> str:
    _delete(root, "AGENTS.md")
    return "LAYOUT.FILES"


def m02_delete_plan02(root: Path) -> str:
    _delete(root, "plan/02-架构与技术选型.md")
    return "LAYOUT.FILES"


def m03_drop_binding_line(root: Path) -> str:
    rel = "plan/00-README总览.md"
    text = (root / rel).read_text(encoding="utf-8")
    match = re.search(r"^>.*ai-tool-project-sprint.*$", text, re.M)
    assert match, "plan/00 里找不到装订行"
    _rewrite(root, rel, match.group(0) + "\n", "")
    return "LAYOUT.BINDING_HEAD"


def m04_drop_required_section(root: Path) -> str:
    _rewrite(root, "plan/01-题目文档.md", "## 5 评分标准", "## 5 评分口径")
    return "LAYOUT.SECTIONS"


def m05_doc_points_at_missing_tool(root: Path) -> str:
    _rewrite(
        root,
        "AGENTS.md",
        "## 变异验证（改门或改文档后必跑）",
        "## 变异验证\n\n另见 `tools/ghost_gate.py`。",
    )
    return "LAYOUT.DOC_TOOLS"


def m06_status_conflict_one_copy(root: Path) -> str:
    """只在一个副本里把 M1 翻成完成 → 跨副本不一致。"""
    rel = "README.md"
    path = root / rel
    lines = path.read_text(encoding="utf-8").split("\n")
    hits = [i for i, ln in enumerate(lines) if re.match(r"^\|\s*\*{0,2}M1\b", ln)]
    assert hits, "README 里找不到 M1 状态行"
    lines[hits[0]] = re.sub(r"⬜[^|]*", "✅ 2026-10-21 ", lines[hits[0]])
    path.write_bytes("\n".join(lines).encode("utf-8"))
    assert "✅" in path.read_text(encoding="utf-8")
    return "LAYOUT.STATUS"


def m07_delete_handoff(root: Path) -> str:
    _mark_done(root, 1)
    _write_handoff(root, 1)  # M1 尚未交付交接单：先构造再删，测的是"缺件"语义
    _delete(root, "plan/HANDOFF-M1.md")
    return "LAYOUT.HANDOFFS"


def m08_drop_handoff_section(root: Path) -> str:
    _mark_done(root, 1)
    _write_handoff(root, 1)  # M1 尚未交付交接单：先构造"有"的状态，再破坏它
    _rewrite(root, "plan/HANDOFF-M1.md", "## 七、关键命令速查", "## 七、附注")
    return "LAYOUT.HANDOFFS"


def m09_stale_gap(root: Path) -> str:
    rel = "plan/06-交付对标与决策.md"
    lines = (root / rel).read_text(encoding="utf-8").split("\n")
    header = next(i for i, ln in enumerate(lines) if ln.startswith("|") and "缺口" in ln)
    cells_hdr = [c.strip() for c in lines[header].strip().strip("|").split("|")]
    col = cells_hdr.index("缺口")
    target = None
    for i in range(header + 1, len(lines)):
        if not lines[i].startswith("|"):
            break
        if set(lines[i]) <= set("|-: "):
            continue
        target = i
        break
    assert target is not None, "缺口表没有数据行"
    cells = lines[target].strip().strip("|").split("|")
    cells[col] = " 已关闭：M0 已落地 " + cells[col]
    lines[target] = "|" + "|".join(cells) + "|"
    (root / rel).write_bytes("\n".join(lines).encode("utf-8"))
    assert "已关闭：M0" in (root / rel).read_text(encoding="utf-8")
    return "LAYOUT.GAPS"


def m10_release_doc_incomplete(root: Path) -> str:
    """把 M6 标成完成（各处一致）并给一份缺"覆盖对账"节的留档 → LAYOUT.RELEASE 红。"""
    _mark_done(root, 6)
    _write_handoff(root, 6)
    (root / "plan/RELEASE-M6.md").write_bytes(
        "# 发布留档\n\n## 一、tag 前事实\n\n待填。\n\n## 二、tag 后追加\n\n待填。\n".encode("utf-8")
    )
    return "LAYOUT.RELEASE"


def m11_ledger_pending_marker(root: Path) -> str:
    """台账（第四份副本）里一条 ✅ 行改成 `⬜ 待 M1`，且 M1 已完成 → LAYOUT.LEDGER 红。"""
    _mark_done(root, 1)
    rel = "plan/00-README总览.md"
    lines = (root / rel).read_text(encoding="utf-8").split("\n")
    header = next(i for i, ln in enumerate(lines)
                  if ln.startswith("|") and "承诺" in ln and "状态" in ln)
    target = None
    for i in range(header + 1, len(lines)):
        if not lines[i].startswith("|"):
            break
        if set(lines[i]) <= set("|-: "):
            continue
        target = i
        break
    assert target is not None, "台账没有数据行"
    cells = lines[target].strip().strip("|").split("|")
    cells[-1] = " ⬜ 待 M1 验证 "
    lines[target] = "|" + "|".join(cells) + "|"
    (root / rel).write_bytes("\n".join(lines).encode("utf-8"))
    assert "⬜ 待 M1" in (root / rel).read_text(encoding="utf-8")
    return "LAYOUT.LEDGER"


MUTATIONS = [
    ("M01 删 AGENTS.md", m01_delete_agents),
    ("M02 删 plan/02", m02_delete_plan02),
    ("M03 删 plan/00 装订行", m03_drop_binding_line),
    ("M04 改掉 plan/01 的必需小节标题", m04_drop_required_section),
    ("M05 文档点名不存在的 tools 脚本", m05_doc_points_at_missing_tool),
    ("M06 单副本状态翻转", m06_status_conflict_one_copy),
    ("M07 删一份交接单", m07_delete_handoff),
    ("M08 交接单缺一节", m08_drop_handoff_section),
    ("M09 缺口列写回已完成里程碑", m09_stale_gap),
    ("M10 发布留档缺覆盖对账", m10_release_doc_incomplete),
    ("M11 台账行写回未完成标记", m11_ledger_pending_marker),
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="布局门变异验证")
    parser.add_argument("--root", default=None)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else ROOT

    base_code, base_out = _run_gate(root)
    if base_code != 0:
        sys.stderr.write("前置条件失败：当前仓库布局门不是全绿，先修布局再跑变异验证。\n")
        sys.stderr.write(base_out + "\n")
        return 1

    rows = []
    for label, mutate in MUTATIONS:
        tmp = Path(tempfile.mkdtemp(prefix="layout-mut-"))
        try:
            _copy_repo(tmp)
            expected = mutate(tmp)
            code, out = _run_gate(tmp)
            hit = re.search(r"^FAIL\s+%s\b" % re.escape(expected), out, re.M) is not None
            rows.append((label, expected, code == 1 and hit, code, hit, ""))
        except AssertionError as exc:
            rows.append((label, "?", False, None, False, str(exc)))
        finally:
            shutil.rmtree(str(tmp), ignore_errors=True)

    print("布局门变异验证（每条变异必须红，且红在预期的判据上）")
    print("=" * 78)
    for label, expected, ok, code, hit, extra in rows:
        print("%-4s  %-34s → %-22s exit=%s 命中=%s%s"
              % ("PASS" if ok else "FAIL", label, expected, code, hit,
                 ("  [%s]" % extra) if extra else ""))
    failed = [row for row in rows if not row[2]]
    print("=" * 78)
    print("结论: %s" % ("%d/%d 全部如期变红" % (len(rows), len(rows)) if not failed
                     else "%d 条未如期变红（假门）" % len(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
