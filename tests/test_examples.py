"""`examples/` 归档样例的断言（M6 脱敏四步的判据面）。

四步里与本文件相关的三步：

1. **产物扫描**：`examples/` 无禁词（复用 `tools/check_forbidden_terms.py` 的判据）。
2. **无真实域名 / 私有路径**：复用 `tools/check_fixture_hygiene.py`（它已把 `examples/`
   纳入扫描面）。
3. **账本无绝对路径（K9）**：这里直接扫样例产物，断言不出现盘符 / 家目录形态。

另加一条"**样例不是陈货**"的断言：`tools/gen_examples.py --check` 逐字节一致 +
退出码未漂；并断言每份账本的 `tool_version` 等于当前 `__version__`——
版本一旦定版，样例的字节也随之绑定，旧版本的样例会在这里显形。
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from mailvault import __version__

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
sys.path.insert(0, str(ROOT / "tools"))

from check_fixture_hygiene import scan as hygiene_scan        # noqa: E402
from check_forbidden_terms import scan as forbidden_scan      # noqa: E402

#: 归档用例 → 必须存在的产物文件名。
CASES = {
    "reconcile-r2-gateway-body": ["verdict.json", "verdict.md"],
    "dmarc-b41": ["verdict.json", "verdict.md"],
    "whatif-spf-tighten": ["verdict.json", "verdict.md"],
    "diff-p-reject": ["baseline.json", "candidate.json", "diff.json", "diff.md"],
}

#: 绝对路径形态：Windows 盘符 / POSIX 家目录 / POSIX 系统根下的常见段。
ABSOLUTE_PATH = re.compile(r"(?:\b[A-Za-z]:[\\/]|/(?:home|Users|root|tmp|mnt|opt|var)/)")


def test_every_case_directory_has_its_artifacts() -> None:
    for case, filenames in CASES.items():
        case_dir = EXAMPLES / case
        assert case_dir.is_dir(), "缺归档样例目录 examples/%s" % case
        for name in filenames:
            assert (case_dir / name).is_file(), "缺 examples/%s/%s" % (case, name)


def test_examples_are_reproducible_and_exit_codes_did_not_drift() -> None:
    """`gen_examples.py --check`：逐字节一致 + 退出码未漂（这是"样例不是陈货"的硬证据）。"""
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "gen_examples.py"), "--check"],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    assert result.returncode == 0, result.stdout.decode("utf-8", "replace")


def test_examples_carry_the_current_tool_version() -> None:
    """样例账本里的 `tool_version` 必须等于当前 `__version__`（定版后不许留旧版样例）。"""
    for path in sorted(EXAMPLES.rglob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if "tool_version" not in payload:
            continue
        assert payload["tool_version"] == __version__, (
            "%s 的 tool_version=%r ≠ 当前 %r（样例是旧版本生成的）"
            % (path.relative_to(ROOT).as_posix(), payload["tool_version"], __version__)
        )


def test_examples_have_no_forbidden_terms() -> None:
    violations, scanned = forbidden_scan(ROOT)
    assert scanned >= len(CASES), "禁词门至少该扫到每个用例的产物"
    assert violations == [], "examples/ 出现禁词：%r" % (violations,)


def test_examples_only_use_reserved_domains_and_doc_ips() -> None:
    violations, scanned, _exempt = hygiene_scan(ROOT)
    assert scanned > 0
    assert violations == [], "examples/ 卫生违规：%r" % (violations,)


def test_examples_contain_no_absolute_paths() -> None:
    """K9：账本内不得出现绝对路径（脱敏 + 跨机可比）。"""
    offenders = []
    for path in sorted(EXAMPLES.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".json", ".md"}:
            continue
        text = path.read_text(encoding="utf-8")
        for match in ABSOLUTE_PATH.finditer(text):
            offenders.append("%s: %r" % (path.relative_to(ROOT).as_posix(), match.group(0)))
    assert offenders == [], "样例产物出现绝对路径：%r" % (offenders,)


@pytest.mark.parametrize("case", sorted(CASES))
def test_examples_markdown_is_non_empty(case: str) -> None:
    for name in CASES[case]:
        if name.endswith(".md"):
            body = (EXAMPLES / case / name).read_text(encoding="utf-8")
            assert body.strip(), "%s/%s 是空文件" % (case, name)