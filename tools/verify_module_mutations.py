#!/usr/bin/env python3
"""判定逻辑的变异验证：**每条判定口径都要能被一条具体断言按住**。

`tools/verify_ast_gates.py` 验的是**语法类**守门（零网络 / 零时钟 / 单一序列化）；
它抓不到"tree walk 漏了跳步""不可信 authserv-id 被当可信"这类**语义**错误——
那类错误只有在求值器被改坏时才会显形，靠的是测试。

做法：把仓库（`mailvault/` + `tests/` + `fixtures/` + `tools/` + `pyproject.toml`）复制到
临时目录 → 往**被测面**植入一处真实的语义故障 → 在副本里跑**指定的那条测试**
→ 断言三件事：

1. 植入点确实变了（marker 存在 → 替换后字节不同）；
2. 植入后的文件**仍能编译**（防空：语法错会让 pytest 红，但红得毫无意义）；
3. 测试输出里出现**预期的那个 node id** 的 FAILED（防空：随便一条别的红也算过）。

三条缺一不可。只有第 3 条能区分"改坏了我以为的那条口径"与"改坏成了另一个错"。

用法：
    py -3.12 tools/verify_module_mutations.py
退出码：0 全部如期变红 / 1 有变异没红（= 该口径没有断言在守）。
"""

from __future__ import annotations

import argparse
import os
import py_compile
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

COPY_FILES = ["mailvault", "tests", "fixtures", "tools", "pyproject.toml"]

#: (标签, 被改的文件, 原文, 改后, 期望 FAILED 的 node id 子串)
#: 每条都必须"改了 → 那条测试红"，否则说明该口径没有被断言守住。
CASES = [
    # ── M5 对账 ──────────────────────────────────────────────────────
    (
        "B01 对账：不可信 authserv-id 也当可信（fail-open，authres_status #86 的坑）",
        "mailvault/modules/reconcile.py",
        "    trusted = bool(claim.authserv_id) and claim.authserv_id.lower() in trusted_lower",
        "    trusted = True  # MUTANT: fail-open",
        "test_untrusted_authserv_id_beats_matching_result",
    ),
    (
        "B02 对账：矛盾只给 1 条解释",
        "mailvault/modules/reconcile.py",
        "    return \"contradiction\", _hypotheses(method, claimed_result, computed_result, context)",
        "    return \"contradiction\", _hypotheses(method, claimed_result, computed_result, context)[:1]",
        "test_every_contradiction_has_at_least_two_explanations_with_verify",
    ),
    (
        "B03 对账：把矛盾折成 fail（题面风险 ③：会被读成『你被黑了』）",
        "mailvault/modules/reconcile.py",
        "            result = \"undecidable\"\n            reason = (\"对账 %d 条：一致 %d、矛盾 %d、无法判定 %d——\"",
        "            result = \"fail\"\n            reason = (\"对账 %d 条：一致 %d、矛盾 %d、无法判定 %d——\"",
        "test_contradiction_is_never_reported_as_fail",
    ),
    (
        "B04 对账：时间戳解析不出也硬给单调性（猜）",
        "mailvault/modules/reconcile.py",
        "    if unparsed:\n        monotonic = None\n    else:\n        monotonic = not regressions",
        "    monotonic = not regressions  # MUTANT: 猜一个",
        "test_unparsed_received_date_makes_monotonic_undecidable_not_guessed",
    ),
    (
        "B05 对账：禁词自检位恒为 true（假干净）",
        "mailvault/modules/reconcile.py",
        "    text = \"\\n\".join(haystack).lower()\n    return not any(word.lower() in text for word in STRICT_FORBIDDEN)",
        "    return True  # MUTANT: 假干净",
        "test_strict_evidence_selfcheck_can_actually_fail",
    ),
    # ── M5 what-if ───────────────────────────────────────────────────
    (
        "B06 what-if：未知 --change 键静默忽略",
        "mailvault/modules/whatif.py",
        "        if key not in WHATIF_CHANGE_KEYS:\n            raise InputError(",
        "        if False:\n            raise InputError(",
        "test_bad_change_is_an_error_not_ignored",
    ),
    (
        "B07 what-if：差分不可逆（invert 不换 add/remove）",
        "mailvault/modules/whatif.py",
        "        elif kind == \"add\":\n            flipped.append({\"op\": \"remove\", \"path\": op[\"path\"],",
        "        elif kind == \"add\":\n            flipped.append({\"op\": \"add\", \"path\": op[\"path\"],",
        "test_diff_handles_added_and_removed_keys",
    ),
    (
        "B08 what-if：就地改传入的快照（基线被改掉，差分无从谈起）",
        "mailvault/modules/whatif.py",
        "    out = copy.deepcopy(snap_dict)\n    queries = out[\"queries\"]",
        "    out = snap_dict  # MUTANT: 就地改\n    queries = out[\"queries\"]",
        "test_apply_changes_does_not_mutate_the_input_snapshot",
    ),
    (
        "B09 what-if：RUA 的 affected 口径放宽（任一不过就算）",
        "mailvault/modules/whatif.py",
        "        aligned = spf_result == \"pass\" or dkim_result == \"pass\"",
        "        aligned = spf_result == \"pass\" and dkim_result == \"pass\"",
        "test_rua_fixture_clusters_the_senders_that_reject_would_break",
    ),
    # ── M4 DMARC（回填 HANDOFF-M4 声称的"变异如期变红"，落到可复跑的脚本里）──
    (
        "B10 DMARC：tree walk 漏掉 ≥8 标签的跳步（逐级爬）",
        "mailvault/modules/dmarc.py",
        "    if len(labels) < DMARC_MAX_LABELS:\n        remaining = labels[1:]\n"
        "    else:\n        keep = min(DMARC_TREE_KEEP_LABELS, len(labels) - 1)\n"
        "        remaining = labels[len(labels) - keep:]",
        "    remaining = labels[1:]  # MUTANT: 逐级爬，不跳步",
        "test_rfc9989_b42_walk_skips_intermediate_labels",
    ),
    (
        "B11 DMARC：数据缺口当成『没有记录』（K13）",
        "mailvault/modules/dmarc.py",
        "    gaps = _collect_gaps(author_walk)\n    if gaps:",
        "    gaps = ()\n    if gaps:",
        "test_data_gap_is_undecidable_not_none",
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


def _plant(root: Path, rel: str, old: str, new: str) -> None:
    path = root / rel
    before = path.read_text(encoding="utf-8")
    assert old in before, "植入点不存在（%s）：%r" % (rel, old[:70])
    after = before.replace(old, new, 1)
    assert after != before, "植入没有产生字节变化（%s）" % rel
    path.write_bytes(after.encode("utf-8"))
    assert new in path.read_text(encoding="utf-8")


def _compiles(root: Path, rel: str) -> bool:
    try:
        py_compile.compile(str(root / rel), doraise=True, cfile=str(root / "_mutant.pyc"))
    except py_compile.PyCompileError:
        return False
    return True


def _run_pytest(root: Path, needle: str) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-q", "--no-header",
         "-p", "no:cacheprovider", "-k", needle],
        cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, "PYTHONUTF8": "1"},
    )
    return result.returncode, result.stdout.decode("utf-8", "replace")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="判定逻辑的变异验证")
    parser.add_argument("--root", default=None)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else ROOT

    rows = []
    for label, rel, old, new, expect in CASES:
        tmp = Path(tempfile.mkdtemp(prefix="mod-mut-"))
        try:
            _copy_repo(tmp)
            _plant(tmp, rel, old, new)
            if not _compiles(tmp, rel):
                rows.append((label, expect, False, None, "植入后语法错（假红）"))
                continue
            code, out = _run_pytest(tmp, expect)
            failed_lines = [line for line in out.splitlines() if line.startswith("FAILED")]
            hit = any(expect in line for line in failed_lines)
            extra = "" if hit else ("未出现 FAILED %s；实际 %d 行 FAILED"
                                    % (expect, len(failed_lines)))
            rows.append((label, expect, code != 0 and hit, code, extra))
        except AssertionError as exc:
            rows.append((label, expect, False, None, str(exc)))
        finally:
            shutil.rmtree(str(tmp), ignore_errors=True)

    print("判定逻辑变异验证（每处语义故障都必须让**指定的那条测试**变红）")
    print("=" * 96)
    for label, expect, ok, code, extra in rows:
        print("%-4s  %-52s exit=%-4s %s%s"
              % ("PASS" if ok else "FAIL", label, code,
                 ("→ " + expect) if not ok else "", ("  [%s]" % extra) if extra else ""))
    failed = [row for row in rows if not row[2]]
    print("=" * 96)
    print("结论: %s" % ("%d/%d 全部如期变红" % (len(rows), len(rows)) if not failed
                     else "%d 处未被断言守住（判据缺守门）" % len(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())