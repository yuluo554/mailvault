"""确定性纪律：双跑逐字节 + 源码级扫描（零时钟 / 零网络 / 零裸 json.dumps）。

这里的两类断言要分开看：

- **运行时**断言（双跑 diff、定点化）：证明"这次跑出来一样"。
- **扫描型**断言（AST）：证明"没有任何一条路径能不一样"——即使某分支没被覆盖也照样抓到。
  扫描型断言的价值在于它与覆盖率无关。
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from mailvault import canonical
from mailvault.constants import LEDGER_SCHEMA_VERSION
from mailvault.ledger import assemble, check_entry

ROOT = Path(__file__).resolve().parent.parent


# ── 序列化确定性 ────────────────────────────────────────────────────────


def test_dumps_is_key_sorted_and_compact():
    payload = {"b": 1, "a": {"z": 2, "y": [3, 1]}}
    assert canonical.dumps(payload) == '{"a":{"y":[3,1],"z":2},"b":1}'


def test_dumps_rejects_floats():
    with pytest.raises(TypeError):
        canonical.dumps({"ratio": 0.5})


def test_dumps_is_idempotent_and_byte_identical():
    payload = {"checks": [{"b": 2, "a": 1}], "summary": {"x": "y"}}
    first = canonical.dumps(payload)
    second = canonical.dumps(payload)
    assert first == second
    assert canonical.digest(payload) == canonical.digest(payload)


def test_digest_changes_with_content():
    assert canonical.digest({"a": 1}) != canonical.digest({"a": 2})


def test_fixed6_uses_half_even():
    assert canonical.fixed6(0.5) == "0.500000"
    assert canonical.fixed6("1") == "1.000000"
    assert canonical.fixed6(0) == "0.000000"
    # 半偶舍入：0.1234565 → 末位 6 是偶数，不舍入到 7
    from decimal import Decimal

    assert canonical.fixed6(Decimal("0.1234565")) == "0.123456"
    assert canonical.fixed6(Decimal("0.1234575")) == "0.123458"


def test_fixed6_output_type_is_str():
    assert isinstance(canonical.fixed6(1), str)
    assert all(isinstance(canonical.fixed6(value), str) for value in (0, 1, 2.5))


def test_write_text_normalizes_newlines(tmp_path):
    target = tmp_path / "x.md"
    canonical.write_text(target, "a\r\nb\rc")
    assert target.read_bytes() == b"a\nb\nc\n"


def test_dump_file_has_single_trailing_newline(tmp_path):
    target = tmp_path / "x.json"
    canonical.dump_file(target, {"a": 1})
    raw = target.read_bytes()
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    assert b"\r" not in raw


def test_reject_floats_reports_path():
    with pytest.raises(TypeError) as exc:
        canonical.reject_floats({"outer": {"inner": [1.5]}})
    assert "outer" in str(exc.value) and "inner" in str(exc.value)


# ── 账本装配的双跑一致 ──────────────────────────────────────────────────


def _sample_ledger():
    entry = check_entry(
        check_id="spf.check_host",
        module="M1",
        subject={"domain": "example.invalid"},
        result="pass",
        reason="synthetic",
        evidence_ref=["RFC7208#4.6.4"],
    )
    return assemble(
        snapshot_meta={"fetched_at": "2026-10-19T18:35:00Z", "resolver": "synthetic"},
        query={"mail_from": "a@example.invalid"},
        checks=[entry],
    )


def test_ledger_two_runs_byte_identical():
    first = canonical.dumps(_sample_ledger())
    second = canonical.dumps(_sample_ledger())
    assert first == second


def test_ledger_id_is_stable_and_content_dependent():
    first = _sample_ledger()
    second = _sample_ledger()
    assert first["ledger_id"] == second["ledger_id"]

    third = check_entry(
        check_id="spf.check_host", module="M1", subject={"domain": "other.example.invalid"},
        result="pass", reason="synthetic", evidence_ref=["RFC7208#4.6.4"],
    )
    changed = assemble(
        snapshot_meta={"fetched_at": "2026-10-19T18:35:00Z", "resolver": "synthetic"},
        query={"mail_from": "a@example.invalid"},
        checks=[third],
    )
    assert changed["ledger_id"] != first["ledger_id"]


def test_ledger_schema_version_single_source():
    assert _sample_ledger()["schema_version"] == LEDGER_SCHEMA_VERSION


# ── 扫描型断言：AST 级，与覆盖率无关 ────────────────────────────────────


def _py_files() -> list[Path]:
    return sorted((ROOT / "mailvault").rglob("*.py"))


def test_source_has_no_system_clock():
    """判定的时间只能来自快照（K7）。扫 AST 而不是 grep：注释/文档串不该误报。"""
    forbidden = {
        "now", "today", "utcnow", "fromtimestamp", "utcfromtimestamp",
        "time", "monotonic", "perf_counter", "localtime", "gmtime",
    }
    offenders = []
    for path in _py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in forbidden and _looks_like_clock(node.func):
                    offenders.append("%s:%d" % (path.name, node.lineno))
    assert offenders == []


def _looks_like_clock(func: ast.Attribute) -> bool:
    base = func.value
    if isinstance(base, ast.Name):
        return base.id in ("datetime", "date", "time")
    if isinstance(base, ast.Attribute):
        return base.attr in ("datetime", "date", "time")
    return False


def test_net_module_is_only_network_exit():
    """`socket` 等 import 只允许出现在 net.py（K3）。"""
    blocked = {"socket", "ssl", "http", "urllib", "urllib2", "ftplib", "telnetlib", "smtplib"}
    offenders = []
    for path in _py_files():
        if path.name == "net.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in blocked:
                        offenders.append("%s:%d %s" % (path.name, node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in blocked:
                offenders.append("%s:%d %s" % (path.name, node.lineno, node.module))
    assert offenders == []


def test_json_serialization_only_in_canonical():
    """`json.dumps/dump` 只允许出现在 canonical.py（K2）。"""
    offenders = []
    for path in _py_files():
        if path.name == "canonical.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("dumps", "dump", "dumps_pretty"):
                    base = node.func.value
                    if isinstance(base, ast.Name) and base.id == "json":
                        offenders.append("%s:%d" % (path.name, node.lineno))
    assert offenders == []


# ── 守门脚本自身能被跑 ──────────────────────────────────────────────────


@pytest.mark.parametrize("script", [
    "tools/check_no_network.py",
    "tools/check_no_direct_json.py",
    "tools/check_no_clock.py",
    "tools/check_sprint_layout.py",
])
def test_gate_script_exits_zero(script):
    """门必须真的能跑通（绿的基线）。变异验证在 tools/verify_layout_gate.py 里。"""
    result = subprocess.run(
        [sys.executable, str(ROOT / script)],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    assert result.returncode == 0, result.stdout.decode("utf-8", "replace")
