#!/usr/bin/env python3
"""AST 守门：`mailvault/net.py` 之外**零网络**。

题面 §7 隐私红线是"审计阶段零网络"。这条纪律必须能被一条命令证明，而不是靠"我记得"。

判据（AST 级，不看字符串，所以注释里的 `import socket` 不会误报）：

- `Import` / `ImportFrom` 的模块名命中 `BLOCKED` → FAIL；
- 动态导入 `importlib.import_module("socket")` / `__import__("socket")` 的字面量参数命中 → FAIL；
- `net.py` 自身**豁免**（它就是唯一出口）。

变异验证：在 `mailvault/cli.py` 里加一行 `import socket` → 本脚本必须报红。

退出码：0 通过 / 1 有违规 / 2 用法错误。
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

BLOCKED = {
    "socket",
    "ssl",
    "http",
    "urllib",
    "urllib2",
    "urllib3",
    "ftplib",
    "telnetlib",
    "smtplib",
    "poplib",
    "imaplib",
    "xmlrpc",
    "requests",
    "httpx",
    "aiohttp",
    "asyncio",  # 骨架期先禁；若将来确需，必须在本文件登记理由
}

EXEMPT_FILES = {"mailvault/net.py"}

ROOT = Path(__file__).resolve().parent.parent


def scan(root: Path) -> tuple[list[str], int]:
    """返回 (违规列表, 扫描文件数)。"""
    violations: list[str] = []
    scanned = 0
    for path in sorted((root / "mailvault").rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if rel in EXEMPT_FILES:
            continue
        scanned += 1
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:  # 门永不崩
            violations.append("%s:%s 语法错误 %s" % (rel, exc.lineno, exc.msg))
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in BLOCKED:
                        violations.append("%s:%d import %s" % (rel, node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module.split(".")[0] in BLOCKED:
                    violations.append("%s:%d from %s import ..." % (rel, node.lineno, module))
            elif isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name in ("importlib.import_module", "__import__"):
                    if node.args and isinstance(node.args[0], ast.Constant):
                        target = node.args[0].value
                        if isinstance(target, str) and target.split(".")[0] in BLOCKED:
                            violations.append(
                                "%s:%d 动态导入 %r" % (rel, node.lineno, target))
    return violations, scanned


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _call_name(func.value)
        return "%s.%s" % (base, func.attr) if base else func.attr
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AST 守门：net.py 之外零网络")
    parser.add_argument("--root", default=None, help="仓库根（默认本脚本上一级）")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else ROOT

    violations, scanned = scan(root)
    print("零网络守门（AST）· 判据: net.py 之外不得 import 网络模块")
    print("=" * 60)
    if scanned == 0:
        print("FAIL  扫了 0 个源文件——判据是空的（阳性对照失败）")
        return 1
    for item in violations:
        print("FAIL  %s" % item)
    if not violations:
        print("PASS  %d 个源文件（不含 net.py）零网络引用" % scanned)
    print("=" * 60)
    print("这轮扫到：%d 个源文件" % scanned)
    print("结论: %s" % ("全绿" if not violations else "%d 处违规" % len(violations)))
    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main())
