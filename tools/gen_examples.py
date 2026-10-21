#!/usr/bin/env python3
"""生成 `examples/` 下**已归档的样例产物**（M6 脱敏四步之①：产物扫描面）。

归档样例有两重身份：

1. **禁词门的扫描面**（`tools/check_forbidden_terms.py`）：M0 期 `examples/` 为空，
   那条门只能报 `SKIP`——"没扫到"与"都合规"必须可区分。M6 往这里放真产物，
   门才从 `SKIP` 转成真判定。
2. **Release 附件里的"示例产物"**（`plan/05` §4.1）：让读者不装环境也能看到
   一份真实账本长什么样。

做法：**用真 CLI 跑真 fixture**（`mailvault.cli.main`，不是手搓 JSON）——
手搓的样例会随时间与渲染层漂移，而它们恰恰是"输出长什么样"的对外凭证。

归档的四个用例（覆盖 `audit` / `whatif` / `diff` 三条命令 + 三种退出码）：

| 目录 | 命令 | 展示 | 期望退出码 |
|---|---|---|---|
| `reconcile-r2-gateway-body/` | `audit` | 矛盾 → `cross_check` undecidable + 双解释 | 2 |
| `dmarc-b41/` | `audit` | 干净 pass（DMARC tree walk 复现例） | 0 |
| `whatif-spf-tighten/` | `whatif` | 差分 + `?all`→`-all` 让退出码 0→1 | 1 |
| `diff-p-reject/` | `diff` | 账本结构差分（含基线/候选） | 0 |

全部带 `--strict-evidence`：归档样例必须是禁词合规的形态（也是 `--strict-evidence` 的示形）。

幂等性（与 fixture 生成器同一纪律）：`--check` 重生成到临时目录后**逐字节比对**
已入仓文件，并断言期望退出码没漂。

用法：

    py -3.12 tools/gen_examples.py            # 生成/覆盖 examples/
    py -3.12 tools/gen_examples.py --check    # 只比对，不写盘；不一致 → 退出码 1

退出码：0 成功 / 1 `--check` 不一致或退出码漂移。
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EXAMPLES_DIR = ROOT / "examples"

#: 归档样例集。`kind` 决定跑哪条子命令；`expect_exit` 是**期望退出码**（漂了就报红）。
CASES = [
    {
        "name": "reconcile-r2-gateway-body",
        "kind": "audit",
        "fixture": "fixtures/reconcile/r2-gateway-body",
        "changes": [],
        "rua": None,
        "expect_exit": {"audit": 2},
        "shows": "矛盾（网关改正文）→ cross_check undecidable + ≥2 条可能解释",
    },
    {
        "name": "dmarc-b41",
        "kind": "audit",
        "fixture": "fixtures/dmarc/b41",
        "changes": [],
        "rua": None,
        "expect_exit": {"audit": 0},
        "shows": "干净通过（RFC 9989 B.4.1 的 DMARC tree walk 复现例）",
    },
    {
        "name": "whatif-spf-tighten",
        "kind": "whatif",
        "fixture": "fixtures/whatif/spf-tighten",
        "changes": ["all=-all"],
        "rua": None,
        "expect_exit": {"whatif": 1},
        "shows": "what-if 差分：?all → -all 让退出码 0 翻成 1",
    },
    {
        "name": "diff-p-reject",
        "kind": "diff",
        "fixture": "fixtures/whatif/p-reject",
        "changes": ["p=reject"],
        "rua": "fixtures/whatif/rua.json",
        "expect_exit": {"audit": 1, "whatif": 1, "diff": 0},
        "shows": "两份账本的结构差分（附基线与候选），p=none → p=reject",
    },
]

#: `examples/` 下允许存在、但不由本生成器产出的文件（人手写的说明）。
HANDWRITTEN = {"README.md"}


def _run_cli(argv: list[str]) -> int:
    """跑真 CLI（`mailvault.cli.main`），吞掉它自己的 stdout/stderr 噪音。"""
    from mailvault.cli import main as cli_main

    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return cli_main(argv)


def _base_args(fixture: Path) -> list[str]:
    return [
        "--snapshot", str(fixture / "snap.json"),
        "--eml", str(fixture / "message.eml"),
        "--query", str(fixture / "query.json"),
    ]


def _emit(case: dict, out_dir: Path, scratch: Path) -> tuple[dict[str, bytes], dict[str, int]]:
    """跑一个用例，返回 ({相对文件名: 字节}, {命令: 退出码})。"""
    fixture = ROOT / case["fixture"]
    base = _base_args(fixture)
    target = out_dir / case["name"]
    target.mkdir(parents=True, exist_ok=True)
    codes: dict[str, int] = {}
    produced: dict[str, bytes] = {}

    if case["kind"] == "audit":
        codes["audit"] = _run_cli([
            "audit", *base, "--strict-evidence",
            "--json", str(target / "verdict.json"), "--md", str(target / "verdict.md"),
        ])
        produced["verdict.json"] = (target / "verdict.json").read_bytes()
        produced["verdict.md"] = (target / "verdict.md").read_bytes()

    elif case["kind"] == "whatif":
        argv = ["whatif", *base]
        for change in case["changes"]:
            argv += ["--change", change]
        if case["rua"]:
            argv += ["--rua", str(ROOT / case["rua"])]
        codes["whatif"] = _run_cli([
            *argv, "--strict-evidence",
            "--json", str(target / "verdict.json"), "--md", str(target / "verdict.md"),
        ])
        produced["verdict.json"] = (target / "verdict.json").read_bytes()
        produced["verdict.md"] = (target / "verdict.md").read_bytes()

    elif case["kind"] == "diff":
        # 基线 / 候选是**真产物**（不是手搓），diff 才是在比较两份真账本。
        # 中间态的 md 写进 scratch，不入 examples/。
        codes["audit"] = _run_cli([
            "audit", *base, "--strict-evidence",
            "--json", str(target / "baseline.json"), "--md", str(scratch / "baseline.md"),
        ])
        whatif_argv = ["whatif", *base]
        for change in case["changes"]:
            whatif_argv += ["--change", change]
        if case["rua"]:
            whatif_argv += ["--rua", str(ROOT / case["rua"])]
        codes["whatif"] = _run_cli([
            *whatif_argv, "--strict-evidence",
            "--json", str(target / "candidate.json"), "--md", str(scratch / "candidate.md"),
        ])
        codes["diff"] = _run_cli([
            "diff",
            "--baseline", str(target / "baseline.json"),
            "--candidate", str(target / "candidate.json"),
            "--json", str(target / "diff.json"), "--md", str(target / "diff.md"),
        ])
        for name in ("baseline.json", "candidate.json", "diff.json", "diff.md"):
            produced[name] = (target / name).read_bytes()

    else:  # pragma: no cover - CASES 是闭集
        raise AssertionError("未知 kind: %r" % (case["kind"],))

    return produced, codes


def build_artifacts(prefix: str) -> tuple[dict[str, bytes], dict[str, int], list[str]]:
    """在临时目录里跑全部用例，返回 (相对路径→字节, 用例→退出码, 问题清单)。"""
    artifacts: dict[str, bytes] = {}
    exits: dict[str, int] = {}
    problems: list[str] = []
    with tempfile.TemporaryDirectory(prefix=prefix) as tmp:
        workdir = Path(tmp)
        scratch = workdir / "_scratch"
        scratch.mkdir()
        for case in CASES:
            produced, codes = _emit(case, workdir, scratch)
            for name, payload in produced.items():
                artifacts["%s/%s" % (case["name"], name)] = payload
            for command, code in codes.items():
                exits["%s:%s" % (case["name"], command)] = code
                expected = case["expect_exit"].get(command)
                if expected is not None and code != expected:
                    problems.append("%s 的 `%s` 退出码 %d ≠ 期望 %d"
                                    % (case["name"], command, code, expected))
    return artifacts, exits, problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="生成 examples/ 下的归档样例产物")
    parser.add_argument("--check", action="store_true",
                        help="只比对已入仓文件，不写盘（逐字节 + 退出码）")
    args = parser.parse_args(argv)

    artifacts, exits, problems = build_artifacts("gen-examples-")

    print("样例产物生成器 · %d 个用例（audit ×2 / whatif / diff，全带 --strict-evidence）"
          % len(CASES))
    print("=" * 66)
    for case in CASES:
        codes = ", ".join("%s=%d" % (cmd, exits["%s:%s" % (case["name"], cmd)])
                          for cmd in sorted(case["expect_exit"]))
        print("  %-26s %-6s exit: %s" % (case["name"], case["kind"], codes))
        print("     %s" % case["shows"])
    print("=" * 66)

    if args.check:
        mismatches = list(problems)
        for name in sorted(artifacts):
            target = EXAMPLES_DIR / name
            if not target.is_file():
                mismatches.append("%s 缺失" % name)
            elif target.read_bytes() != artifacts[name]:
                mismatches.append("%s 字节不一致" % name)
        # examples/ 里不得有本生成器不认识的额外产物（README.md 是人手写的说明）。
        expected = {os.path.dirname(name) for name in artifacts}
        if EXAMPLES_DIR.is_dir():
            for path in sorted(EXAMPLES_DIR.rglob("*")):
                if not path.is_file():
                    continue
                rel = path.relative_to(EXAMPLES_DIR).as_posix()
                if rel in HANDWRITTEN:
                    continue
                if rel not in artifacts:
                    mismatches.append("%s 不在生成器产物集里（多余/过期文件）" % rel)
        for dirname in sorted(expected):
            if not (EXAMPLES_DIR / dirname).is_dir():
                mismatches.append("%s 目录缺失" % dirname)
        if mismatches:
            for item in mismatches:
                print("FAIL  %s" % item)
            print("结论: %d 处不一致（样例不幂等或退出码漂移）" % len(mismatches))
            return 1
        print("PASS  %d 份样例产物逐字节一致，退出码未漂" % len(artifacts))
        return 0

    written = 0
    for name in sorted(artifacts):
        target = EXAMPLES_DIR / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(artifacts[name])
        written += 1
    print("已写入 %d 份文件" % written)
    if problems:
        for item in problems:
            print("FAIL  %s" % item)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())