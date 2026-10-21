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
    """判定的时间只能来自快照（K7）。扫 AST 而不是 grep：注释/文档串不该误报。

    **精确豁免**（与 `tools/check_no_clock.py` 同一口径）：`net.py::utc_now_z` 是给快照盖
    `fetched_at` 的唯一位置。豁免按**函数行区间**判定——同文件里别处读时钟仍报红。
    """
    forbidden = {
        "now", "today", "utcnow", "fromtimestamp", "utcfromtimestamp",
        "time", "monotonic", "perf_counter", "localtime", "gmtime",
    }
    exempt = {("net.py", "utc_now_z")}
    offenders = []
    for path in _py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        spans = _clock_exempt_spans(tree, path.name, exempt)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in forbidden and _looks_like_clock(node.func):
                    if any(start <= node.lineno <= end for start, end in spans):
                        continue
                    offenders.append("%s:%d" % (path.name, node.lineno))
    assert offenders == []


def _clock_exempt_spans(tree: ast.AST, filename: str, exempt: set[tuple[str, str]]) -> list[tuple[int, int]]:
    names = {name for owner, name in exempt if owner == filename}
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
            spans.append((node.lineno, getattr(node, "end_lineno", None) or node.lineno))
    return spans


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


def test_runtime_has_no_third_party_imports():
    """运行时零第三方依赖：`mailvault/` 包内只许 import 标准库与自身。

    为什么要有这条：`pyyaml` 进了 `dev` extra（RFC 7208 测试集要解析 YAML）。
    "测试期依赖不泄漏进运行时"如果只靠约定，某天有人在 `psl.py` 里 `import yaml`
    读配置就会悄悄把发布件变成需要联网装包的东西。这条扫描把它变成一条能跑红的断言。
    """
    stdlib = set(sys.stdlib_module_names)
    offenders = []
    for path in _py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            roots: list[str] = []
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:  # 相对 import（包内）
                    continue
                roots = [(node.module or "").split(".")[0]]
            for root in roots:
                if not root or root == "__future__" or root == "mailvault":
                    continue
                if root not in stdlib:
                    offenders.append("%s:%d 非标准库 import %r"
                                     % (path.name, node.lineno, root))
    assert offenders == [], "运行时不得依赖第三方包"


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


# ── `.eml` fixture 的字节必须被 git 放过 ────────────────────────────────


def test_eml_fixtures_need_crlf_and_must_be_declared_minus_text():
    """`.eml` fixture 的**字节形态本身就是被测对象**，必须 `-text`。

    为什么单列一条：`.gitattributes` 的 `* text=auto eol=lf` 会在 `git add` 时把 CRLF
    归一成 LF。而 DKIM 的 `bh=`（RFC 6376 §3.4）是对**规范化后的字节**算的——
    归一之后**裸 clone** 起来的 fixture 会让验签全变 `body_hash` 失败、
    四个生成器的 `--check` 全部报不一致。

    这条故障**在本机看不出来**（工作区文件没被碰过），只在克隆/CI 时显形，
    所以必须有一条断言把它钉住。判据拆成两半，缺一不可：

    1. 每个 `.eml` fixture 确实含 CRLF（证明这条规则不是多余的）；
    2. `.gitattributes` 里有匹配 `*.eml` 的 `-text`（或 `binary`）规则（证明 git 不会动它）。

    实测（临时 bare 仓库 round-trip）：带规则 → 克隆后 25 处 CRLF、`--check` 全绿；
    去掉规则 → 0 处 CRLF、`--check` 报 `message.eml 字节不一致`。
    """
    eml_files = sorted((ROOT / "fixtures").rglob("*.eml"))
    assert eml_files, "没有任何 .eml fixture——这条判据会空跑"
    for path in eml_files:
        raw = path.read_bytes()
        assert b"\r\n" in raw, "%s 里没有 CRLF：报文 fixture 用 CRLF 行终止" % path.name

    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    rules = []
    for line in attributes.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pattern, _, flags = line.partition(" ")
        if pattern in ("*.eml", "fixtures/**/*.eml"):
            rules.append(flags.split())
    assert rules, ".gitattributes 里没有匹配 *.eml 的规则"
    assert any(("-text" in flags) or ("binary" in flags) for flags in rules), \
        "*.eml 必须声明 `-text`（或 binary），否则 git 会把 CRLF 归一、裸 clone 后 DKIM 全挂"
