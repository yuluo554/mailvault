"""CLI 契约与退出码（M0 冻结面）。

这些测试锁的是"口径"，不是"功能"——功能还没有。
每一条改动都会让某个下游里程碑的行为悄悄变掉，所以全部写成强断言。
"""

from __future__ import annotations

import json

import pytest

from mailvault import __version__
from mailvault.cli import build_parser, main
from mailvault.constants import RESULTS
from mailvault.exits import ExitCode, InputError, InternalError, exit_code_for, worst


# ── 退出码 ──────────────────────────────────────────────────────────────


def test_exit_codes_numeric_values():
    assert int(ExitCode.OK) == 0
    assert int(ExitCode.FAIL) == 1
    assert int(ExitCode.UNDECIDABLE) == 2
    assert int(ExitCode.INPUT_ERROR) == 3
    assert int(ExitCode.INTERNAL_ERROR) == 4


def test_exit_priority_is_single_source():
    """优先级 4 > 3 > 2 > 1 > 0：取最大数值。"""
    assert worst(ExitCode.OK, ExitCode.FAIL) is ExitCode.FAIL
    assert worst(ExitCode.FAIL, ExitCode.UNDECIDABLE) is ExitCode.UNDECIDABLE
    assert worst(ExitCode.UNDECIDABLE, ExitCode.INPUT_ERROR) is ExitCode.INPUT_ERROR
    assert worst(ExitCode.INPUT_ERROR, ExitCode.INTERNAL_ERROR) is ExitCode.INTERNAL_ERROR
    assert worst() is ExitCode.OK


def test_exit_code_for_results():
    assert exit_code_for([]) is ExitCode.OK
    assert exit_code_for(["pass", "none"]) is ExitCode.OK
    assert exit_code_for(["pass", "fail"]) is ExitCode.FAIL
    assert exit_code_for(["softfail"]) is ExitCode.FAIL
    # undecidable 比 fail 更严重（口径：宁可说"判不了"，也不把判不了混成 fail）
    assert exit_code_for(["fail", "undecidable"]) is ExitCode.UNDECIDABLE


def test_exit_code_for_unknown_result_raises():
    with pytest.raises(InternalError):
        exit_code_for(["totally-made-up"])


# ── 结果枚举 ────────────────────────────────────────────────────────────


def test_results_enum_contains_undecidable():
    assert "undecidable" in RESULTS
    assert "pass" in RESULTS and "fail" in RESULTS and "permerror" in RESULTS


# ── argparse → 退出码转换 ────────────────────────────────────────────────


def test_argparse_exit_code_is_input_error(capsys):
    """argparse 默认 SystemExit(2) 会与 undecidable 的 2 撞语义 → 入口转 3。"""
    assert main(["audit"]) == int(ExitCode.INPUT_ERROR)   # 缺必填参数
    assert main(["nosuchcommand"]) == int(ExitCode.INPUT_ERROR)


def test_no_command_returns_input_error(capsys):
    assert main([]) == int(ExitCode.INPUT_ERROR)


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert __version__ in captured.out


# ── 参数面（文档 → parser 反射对账的雏形） ──────────────────────────────


def test_change_is_repeatable_not_comma():
    """`--change` 是 action=append。逗号多值会被当成一个整串——那是文档与代码漂移的典型。"""
    parser = build_parser()
    args = parser.parse_args([
        "whatif", "--snapshot", "s.json", "--eml", "m.eml", "--query", "q.json",
        "--change", "p=reject", "--change", "t=y",
    ])
    assert args.change == ["p=reject", "t=y"]


def test_change_has_no_choices_restriction():
    """不能给 `--change` 加 `choices=`：那会把 `p=reject` 整串当一个值判非法。"""
    parser = build_parser()
    args = parser.parse_args([
        "whatif", "--snapshot", "s", "--eml", "m", "--query", "q",
        "--change", "include:_spf.example.invalid",
    ])
    assert args.change == ["include:_spf.example.invalid"]


def test_strict_evidence_flag_defaults_false():
    parser = build_parser()
    args = parser.parse_args(["audit", "--snapshot", "s", "--eml", "m", "--query", "q"])
    assert args.strict_evidence is False


def test_out_dir_and_explicit_paths_coexist():
    parser = build_parser()
    args = parser.parse_args([
        "audit", "--snapshot", "s", "--eml", "m", "--query", "q",
        "--json", "a.json", "--md", "a.md", "--out-dir", "out",
    ])
    assert (args.json_out, args.md_out, args.out_dir) == ("a.json", "a.md", "out")


# ── 未实现子命令 → fail-closed ──────────────────────────────────────────


def test_audit_is_implemented_and_requires_inputs(tmp_path):
    """M2 起 `audit` 已实现：输入缺失 → 3（输入错误），不再是"没做"（2）。

    这条与 `test_audit_judges_end_to_end` 成对：一条证明"缺输入不会被当成成功"，
    另一条证明"有输入时真的算出判定"。只有前者的话，一个永远返回 3 的壳也能过。
    """
    assert main([
        "audit", "--snapshot", "s.json", "--eml", "m.eml", "--query", "q.json",
        "--out-dir", str(tmp_path),
    ]) == int(ExitCode.INPUT_ERROR)


def test_audit_judges_end_to_end(tmp_path):
    """完整三件套 → 真实判定 + 两轨产物落盘（M2 DoD："断网下 audit 成功"）。"""
    from mailvault import canonical

    canonical.dump_file(tmp_path / "snap.json", {
        "schema_version": 1,
        "fetched_at": "2026-10-19T18:35:00Z",
        "resolver": "synthetic",
        "psl_version": "2026-10-20_08-40-56_UTC",
        "psl_date": "2026-10-20",
        "queries": [{"qname": "example.com", "qtype": "TXT", "rcode": "NOERROR",
                     "answer": ["v=spf1 ip4:192.0.2.0/24 -all"], "ttl": 300}],
    })
    canonical.dump_file(tmp_path / "query.json", {
        "mail_from": "sender@example.com",
        "client_ip": "192.0.2.10",
        "helo": "mail.example.com",
    })
    (tmp_path / "message.eml").write_bytes(b"Subject: t\r\n\r\nbody\r\n")

    code = main([
        "audit",
        "--snapshot", str(tmp_path / "snap.json"),
        "--eml", str(tmp_path / "message.eml"),
        "--query", str(tmp_path / "query.json"),
        "--out-dir", str(tmp_path),
    ])
    assert code == int(ExitCode.OK)      # SPF pass
    verdict = json.loads((tmp_path / "verdict.json").read_text(encoding="utf-8"))
    assert verdict["checks"][0]["check_id"] == "spf.check_host"
    assert verdict["checks"][0]["result"] == "pass"
    assert verdict["checks"][0]["evidence_ref"]
    assert (tmp_path / "verdict.md").is_file()


def test_audit_double_run_is_byte_identical(tmp_path):
    """两次运行 `verdict.json` 字节级一致（M2 DoD）。"""
    import hashlib

    from mailvault import canonical

    canonical.dump_file(tmp_path / "snap.json", {
        "schema_version": 1,
        "fetched_at": "2026-10-19T18:35:00Z",
        "resolver": "synthetic",
        "psl_version": "2026-10-20_08-40-56_UTC",
        "psl_date": "2026-10-20",
        "queries": [{"qname": "example.com", "qtype": "TXT", "rcode": "NOERROR",
                     "answer": ["v=spf1 -all"], "ttl": 300}],
    })
    canonical.dump_file(tmp_path / "query.json", {
        "mail_from": "sender@example.com",
        "client_ip": "192.0.2.10",
    })
    (tmp_path / "message.eml").write_bytes(b"Subject: t\r\n\r\nbody\r\n")

    digests = []
    for name in ("a.json", "b.json"):
        main([
            "audit",
            "--snapshot", str(tmp_path / "snap.json"),
            "--eml", str(tmp_path / "message.eml"),
            "--query", str(tmp_path / "query.json"),
            "--json", str(tmp_path / name),
            "--md", str(tmp_path / (name + ".md")),
        ])
        digests.append(hashlib.sha256((tmp_path / name).read_bytes()).hexdigest())
    assert digests[0] == digests[1]


def test_whatif_requires_change():
    """先做参数面校验：参数写错（3）与功能没做（2）必须是两种输出。"""
    assert main([
        "whatif", "--snapshot", "s", "--eml", "m", "--query", "q",
    ]) == int(ExitCode.INPUT_ERROR)


def test_whatif_bad_change_shape():
    assert main([
        "whatif", "--snapshot", "s", "--eml", "m", "--query", "q", "--change", "p",
    ]) == int(ExitCode.INPUT_ERROR)


def test_whatif_valid_change_requires_existing_inputs():
    """M5 起 `whatif` 已实现：参数合法但输入缺失 → 3（输入错误），不再是"没做"（2）。

    这条与 `test_whatif_diff_is_recomputable` 成对：一条证明"缺输入不会被当成成功"，
    另一条证明"有输入时真的算出差分"。只有前者的话，一个永远返回 3 的壳也能过。
    """
    assert main([
        "whatif", "--snapshot", "s", "--eml", "m", "--query", "q", "--change", "p=reject",
    ]) == int(ExitCode.INPUT_ERROR)


def test_whatif_unknown_key_is_input_error_not_silent():
    """未知 `--change` 键 → 3，不做静默忽略（`plan/03` §2 第 3 条）。

    静默忽略会让用户以为"我改了"，实际跑的还是基线——那是最坏的一种"看起来成功"。
    """
    assert main([
        "whatif", "--snapshot", "s", "--eml", "m", "--query", "q", "--change", "q=reject",
    ]) == int(ExitCode.INPUT_ERROR)


def test_whatif_bad_value_is_input_error():
    assert main([
        "whatif", "--snapshot", "s", "--eml", "m", "--query", "q", "--change", "p=drop",
    ]) == int(ExitCode.INPUT_ERROR)


def test_diff_is_implemented_and_requires_inputs(tmp_path):
    """M5 起 `diff` 已实现：两份账本缺一 → 3（输入错误）。"""
    assert main([
        "diff", "--baseline", str(tmp_path / "nope.json"),
        "--candidate", str(tmp_path / "nope2.json"), "--out-dir", str(tmp_path),
    ]) == int(ExitCode.INPUT_ERROR)


def test_snapshot_fetch_requires_existing_inputs(tmp_path):
    """M1 起 `snapshot fetch` 已实现：输入缺失 → 输入错误（3），而不是"没做"（2）。"""
    assert main([
        "snapshot", "fetch", "--eml", "m.eml", "--query", "q.json",
        "-o", str(tmp_path / "s.json"),
    ]) == int(ExitCode.INPUT_ERROR)


# ── 错误类型 → 退出码 ───────────────────────────────────────────────────


def test_input_error_exit_code():
    assert InputError.exit_code is ExitCode.INPUT_ERROR


def test_internal_error_exit_code():
    assert InternalError.exit_code is ExitCode.INTERNAL_ERROR
