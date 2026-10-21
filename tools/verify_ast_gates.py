#!/usr/bin/env python3
"""AST / 扫描门的变异验证：**每一条守门都必须能变红**。

做法：把仓库复制到临时目录 → 往被测面**植入一处真实违规** → 跑该副本里的门
→ 断言退出码 1 → 还原。三连断言：植入前 marker 不存在 / 植入后文件已变 / 结束时副本被删。

为什么必须做这一步：一条"永远返回 0"的门与一条"项目确实干净"的门，输出一模一样。
只有植入违规仍绿，才能确定它是假门。

用法：
    py -3.12 tools/verify_ast_gates.py
退出码：0 全部如期变红 / 1 有门没红（= 假门）。
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

COPY_FILES = ["mailvault", "tools", "fixtures", "examples"]

#: (标签, 门脚本, 要植入的文件, 植入内容, 期望门输出里出现的关键词)
CASES = [
    (
        "A01 在 cli.py 里 import socket",
        "tools/check_no_network.py",
        "mailvault/cli.py",
        "\nimport socket  # MUTANT\n",
        "import socket",
    ),
    (
        "A02 在 cli.py 里直接 json.dumps",
        "tools/check_no_direct_json.py",
        "mailvault/cli.py",
        "\nimport json\n\ndef _mutant():\n    return json.dumps({})\n",
        "json 序列化",
    ),
    (
        "A03 在 render.py 里读系统时钟",
        "tools/check_no_clock.py",
        "mailvault/render.py",
        "\nimport time\n\ndef _mutant():\n    return time.time()\n",
        "time.time",
    ),
    (
        "A04 fixture 里放真实域名",
        "tools/check_fixture_hygiene.py",
        "fixtures/mutant-probe.txt",
        "sender: ops@mail.google.com\n",
        "mail.google.com",
    ),
    (
        "A05 examples 里放禁词",
        "tools/check_forbidden_terms.py",
        "examples/mutant-verdict.md",
        "# 结论\n\n该头疑似伪造。\n",
        "禁词",
    ),
    (
        # 精确豁免的**阴性对照**：net.py 是唯一有豁免的文件，但豁免只到 utc_now_z 这一个函数。
        # 同文件里别处读时钟必须照样报红——否则"函数级豁免"就悄悄退化成了"文件级放行"。
        "A06 豁免文件里越界读时钟（net.py 非豁免函数）",
        "tools/check_no_clock.py",
        "mailvault/net.py",
        "\n\ndef _mutant_outside_exemption():\n    import time\n    return time.time()\n",
        "time.time",
    ),
]


def _copy_repo(dest: Path) -> None:
    for rel in COPY_FILES:
        source = ROOT / rel
        if not source.exists():
            continue
        target = dest / rel
        if source.is_dir():
            shutil.copytree(str(source), str(target))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(source), str(target))
    (dest / "fixtures").mkdir(exist_ok=True)
    (dest / "examples").mkdir(exist_ok=True)


def _plant(root: Path, rel: str, payload: str, *, append: bool) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    assert "MUTANT" not in (path.read_text(encoding="utf-8") if path.exists() and append else ""), \
        "植入点已有 MUTANT 标记"
    if append:
        before = path.read_text(encoding="utf-8")
        after = before + payload
        assert after != before
        path.write_bytes(after.encode("utf-8"))
    else:
        path.write_bytes(payload.encode("utf-8"))
    text = path.read_text(encoding="utf-8")
    assert "MUTANT" in text or "mutant" in text or "mail.google.com" in text or "伪造" in text


def _run(root: Path, script: str) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, str(root / script)],
        cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    return result.returncode, result.stdout.decode("utf-8", "replace")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AST/扫描门的变异验证")
    parser.add_argument("--root", default=None)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else ROOT

    rows = []
    for label, script, rel, payload, needle in CASES:
        tmp = Path(tempfile.mkdtemp(prefix="ast-mut-"))
        try:
            _copy_repo(tmp)
            _plant(tmp, rel, payload, append=rel.startswith("mailvault/"))
            code, out = _run(tmp, script)
            hit = needle in out
            rows.append((label, script, code == 1 and hit, code, hit))
        except AssertionError as exc:
            rows.append((label, script, False, None, False))
            print("  构造失败: %s" % exc)
        finally:
            shutil.rmtree(str(tmp), ignore_errors=True)

    print("AST/扫描门变异验证（每条植入违规后必须 red）")
    print("=" * 78)
    for label, script, ok, code, hit in rows:
        print("%-4s  %-32s → %-34s exit=%s 关键词命中=%s"
              % ("PASS" if ok else "FAIL", label, script, code, hit))
    failed = [row for row in rows if not row[2]]
    print("=" * 78)
    print("结论: %s" % ("%d/%d 全部如期变红" % (len(rows), len(rows)) if not failed
                     else "%d 条未如期变红（假门）" % len(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
