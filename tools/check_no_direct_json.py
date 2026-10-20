#!/usr/bin/env python3
"""AST 守门：`json.dumps` / `json.dump` 只允许出现在 `canonical.py`（K2）。

为什么：确定性序列化的保障全部押在"唯一出口"上。多一个 `json.dumps(x)` 就多一条
不排序键、不拒绝浮点的路。字符串搜索会被注释/文档串误伤，所以用 AST。

变异验证：在 `mailvault/cli.py` 里加一句 `json.dumps({})` → 本脚本必须报红。

退出码：0 通过 / 1 有违规。
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ALLOWED = {"mailvault/canonical.py"}
TARGET_ATTRS = {"dumps", "dump", "dumps_pretty"}
ROOT = Path(__file__).resolve().parent.parent


def scan(root: Path) -> tuple[list[str], int]:
    violations: list[str] = []
    scanned = 0
    for path in sorted((root / "mailvault").rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if rel in ALLOWED:
            continue
        scanned += 1
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            violations.append("%s:%s 语法错误 %s" % (rel, exc.lineno, exc.msg))
            continue
        json_names = _json_aliases(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _is_json_serializer(node.func, json_names):
                violations.append("%s:%d 直接调用 json 序列化（应走 canonical）"
                                  % (rel, node.lineno))
    return violations, scanned


def _json_aliases(tree: ast.AST) -> set[str]:
    """抓 `import json` 与 `import json as j` 两种形态。"""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "json":
                    names.add(alias.asname or "json")
        elif isinstance(node, ast.ImportFrom) and (node.module or "") == "json":
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def _is_json_serializer(func: ast.AST, json_names: set[str]) -> bool:
    if isinstance(func, ast.Attribute):
        if func.attr not in TARGET_ATTRS:
            return False
        base = func.value
        if isinstance(base, ast.Name) and base.id in json_names:
            return True
        if isinstance(base, ast.Name) and base.id == "json":
            return True
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AST 守门：json 序列化唯一出口")
    parser.add_argument("--root", default=None)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else ROOT

    violations, scanned = scan(root)
    print("序列化唯一出口守门（AST）· 只允许 canonical.py 调 json.dumps/dump")
    print("=" * 60)
    if scanned == 0:
        print("FAIL  扫了 0 个源文件——判据是空的")
        return 1
    for item in violations:
        print("FAIL  %s" % item)
    if not violations:
        print("PASS  %d 个源文件（不含 canonical.py）零直接 serialization" % scanned)
    print("=" * 60)
    print("这轮扫到：%d 个源文件" % scanned)
    print("结论: %s" % ("全绿" if not violations else "%d 处违规" % len(violations)))
    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main())
