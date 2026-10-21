#!/usr/bin/env python3
"""AST 守门：源码零系统时钟（K7）。

判定的时间只能来自快照元数据。读系统时钟会让同一输入在不同时刻给出不同账本，
"两次运行逐字节一致"当场失效，而且失败得很隐蔽（只有在跨秒边界的两次运行才复现）。

禁：`datetime.now` / `datetime.today` / `datetime.utcnow` / `datetime.fromtimestamp` /
`time.time` / `time.monotonic` / `time.perf_counter` / `time.localtime` / `time.gmtime`。

**唯一豁免（M1 登记）**：

    mailvault/net.py::utc_now_z

理由：`snapshot fetch` 必须给快照盖 `fetched_at`，"这份快照什么时候抓的"本质上只能读时钟。
K7 约束的是**判定**不读时钟（时间只来自快照），不是"抓取不读时钟"。
豁免**精确到函数名**而不是整个文件：net.py 里除 `utc_now_z` 之外的任何时钟调用仍然报红。
判据实现见 :func:`_exempt_spans`——它按 AST 定位函数的**行区间**，不是按文件放行。

变异验证：在 `mailvault/render.py` 里加一句 `import time; time.time()` → 本脚本必须报红。

退出码：0 通过 / 1 有违规。
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

FORBIDDEN = {
    "datetime.datetime.now",
    "datetime.datetime.today",
    "datetime.datetime.utcnow",
    "datetime.datetime.fromtimestamp",
    "datetime.datetime.utcfromtimestamp",
    "datetime.date.today",
    "time.time",
    "time.monotonic",
    "time.perf_counter",
    "time.localtime",
    "time.gmtime",
    "time.ctime",
}

ROOT = Path(__file__).resolve().parent.parent

#: 精确豁免：(相对路径, 函数名)。只放行该函数**行区间内**的时钟调用。
CLOCK_EXEMPT_FUNCTIONS = {
    ("mailvault/net.py", "utc_now_z"):
        "snapshot fetch 要给快照盖 fetched_at——抓取时长不是判定时长（K7 只管判定）",
}


def _exempt_spans(tree: ast.AST) -> list[tuple[int, int]]:
    """返回被豁免函数的 ``(起行, 止行)`` 列表（闭区间，按 AST 的 lineno/end_lineno）。"""
    spans: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for owner, name in CLOCK_EXEMPT_FUNCTIONS:
            if node.name != name:
                continue
            start = node.lineno
            end = getattr(node, "end_lineno", None) or start
            spans.append((start, end))
    return spans


def scan(root: Path) -> tuple[list[str], int]:
    violations: list[str] = []
    scanned = 0
    for path in sorted((root / "mailvault").rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        scanned += 1
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            violations.append("%s:%s 语法错误 %s" % (rel, exc.lineno, exc.msg))
            continue

        aliases = _aliases(tree)
        exempt = _exempt_spans(tree) if rel in {o for o, _n in CLOCK_EXEMPT_FUNCTIONS} else []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = _dotted(node.func, aliases)
            if dotted not in FORBIDDEN:
                continue
            if _in_spans(node.lineno, exempt):
                continue
            violations.append("%s:%d 调用 %s（判定不许读系统时钟）"
                              % (rel, node.lineno, dotted))
    return violations, scanned


def _in_spans(lineno: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= lineno <= end for start, end in spans)


def _aliases(tree: ast.AST) -> dict[str, str]:
    """把 `from datetime import datetime as dt` 这类别名映射回全名。"""
    mapping: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mapping[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                mapping[alias.asname or alias.name] = "%s.%s" % (node.module, alias.name)
    return mapping


def _dotted(func: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(func, ast.Attribute):
        base = _dotted(func.value, aliases)
        return "%s.%s" % (base, func.attr) if base else func.attr
    if isinstance(func, ast.Name):
        return aliases.get(func.id, func.id)
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AST 守门：零系统时钟")
    parser.add_argument("--root", default=None)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else ROOT

    violations, scanned = scan(root)
    print("零系统时钟守门（AST）· 时间只许来自快照元数据")
    print("=" * 60)
    if scanned == 0:
        print("FAIL  扫了 0 个源文件——判据是空的")
        return 1
    for item in violations:
        print("FAIL  %s" % item)
    if not violations:
        print("PASS  %d 个源文件零系统时钟调用" % scanned)
    print("=" * 60)
    print("这轮扫到：%d 个源文件" % scanned)
    print("结论: %s" % ("全绿" if not violations else "%d 处违规" % len(violations)))
    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main())
