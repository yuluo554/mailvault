#!/usr/bin/env python3
"""禁词守门（K10）：`--strict-evidence` 口径下不得出现定性词。

题面 §7 红线：`--strict-evidence` 下不得出现"攻击/伪造"字样，只能出现
"与重算不一致，可能解释为 A 或 B"。

扫描面 = `examples/` 下已归档的样例产物（`verdict.json` / `verdict.md`）。
**M0 无样例 → SKIP 并打印扫描数**（"没扫到"必须与"都合规"可区分）。

变异验证：往 `examples/` 放一份含"攻击"的 verdict.md → 必须报红。

退出码：0 通过或 SKIP / 1 有违规。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN = ("攻击", "伪造", "被黑", "黑客", "hacked", "forged", "attack", "compromised")
TARGET_SUFFIXES = {".json", ".md"}


def scan(root: Path) -> tuple[list[str], int]:
    violations: list[str] = []
    scanned = 0
    examples = root / "examples"
    if not examples.is_dir():
        return violations, scanned
    for path in sorted(examples.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TARGET_SUFFIXES:
            continue
        scanned += 1
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        rel = path.relative_to(root).as_posix()
        for word in FORBIDDEN:
            if word.lower() in lowered:
                violations.append("%s 含禁词 %r" % (rel, word))
    return violations, scanned


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="strict-evidence 禁词守门")
    parser.add_argument("--root", default=None)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else ROOT

    violations, scanned = scan(root)
    print("禁词守门 · strict-evidence 口径（样例产物面）")
    print("=" * 60)
    if scanned == 0:
        print("SKIP  扫了 0 份样例产物（M0 尚无 examples/；发布棒起转为 FAIL 判定）")
        print("=" * 60)
        print("这轮扫到：0 份")
        print("结论: SKIP（不是通过）")
        return 0
    for item in violations:
        print("FAIL  %s" % item)
    if not violations:
        print("PASS  %d 份样例产物无禁词" % scanned)
    print("=" * 60)
    print("这轮扫到：%d 份" % scanned)
    print("结论: %s" % ("全绿" if not violations else "%d 处违规" % len(violations)))
    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main())
