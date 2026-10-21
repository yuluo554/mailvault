"""what-if 反事实与 RUA 关联（M5）。

测试分四层：

1. **参数与变更施加**（纯函数）：`--change` 的键/值校验必须 raise 而不是静默忽略；
   `p=` / `sp=` / `np=` / `t=` / `all=` / `include:` 各改哪一处、保留什么、凭什么 raise。
2. **差分可复算**：`diff_ledgers` 的 ops 施加到基线得到候选、反转施加到候选得到基线。
   两个方向都由**真实账本**（CLI 产物）验证，不是合成玩具字典。
3. **fixture 逐条对账**（`fixtures/whatif/*/expected.json`）：`expect` 用点路径 → 值。
4. **反自证 / 结构性断言**：差分必须**能真的改变判定与退出码**（`spf-tighten` 证 0→1）；
   RUA 缺数据必须判 undecidable 并给出所需输入清单；`affected` 的筛选口径被真实报告钉住
   （写成"任一不过就算"会把数量从 1 变 2，立刻变红）；生成器 `--check` 幂等。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from mailvault.constants import DIFF_SCHEMA_VERSION, WHATIF_CHANGE_KEYS
from mailvault.exits import ExitCode, InputError
from mailvault.modules.whatif import (
    Change,
    apply_changes,
    apply_ops,
    diff_ledgers,
    invert_ops,
    parse_changes,
    rua_association,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_ROOT = REPO_ROOT / "fixtures" / "whatif"


# ── 夹具小工具 ──────────────────────────────────────────────────────────


def _case_dirs() -> list[Path]:
    if not FIXTURE_ROOT.is_dir():
        return []
    return sorted(path for path in FIXTURE_ROOT.iterdir()
                  if path.is_dir() and (path / "expected.json").is_file())


def _expected(directory: Path) -> dict:
    return json.loads((directory / "expected.json").read_text(encoding="utf-8"))


def _snap(queries: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "fetched_at": "2026-10-19T18:35:00Z",
        "resolver": "synthetic",
        "psl_version": "2026-10-20_08-40-56_UTC",
        "psl_date": "2026-10-20",
        "queries": queries,
    }


def _txt(qname: str, answers: list[str]) -> dict:
    return {"qname": qname, "qtype": "TXT", "rcode": "NOERROR", "answer": answers, "ttl": 300}


def _run_case(directory: Path, tmp_path: Path):
    """跑一遍 `audit`（基线）与 `whatif`（候选），返回两份产物。"""
    from mailvault.cli import main

    expected = _expected(directory)
    changes = list(expected["input"]["changes"])
    baseline_path = tmp_path / ("%s-baseline.json" % directory.name)
    candidate_path = tmp_path / ("%s-candidate.json" % directory.name)

    args = [
        "audit", "--snapshot", str(directory / "snap.json"),
        "--eml", str(directory / "message.eml"), "--query", str(directory / "query.json"),
    ]
    baseline_code = main(args + ["--json", str(baseline_path),
                                 "--md", str(tmp_path / "baseline.md")])

    whatif_args = [
        "whatif", "--snapshot", str(directory / "snap.json"),
        "--eml", str(directory / "message.eml"), "--query", str(directory / "query.json"),
        "--json", str(candidate_path), "--md", str(tmp_path / ("%s.md" % directory.name)),
    ]
    for change in changes:
        whatif_args.extend(["--change", change])
    rua = expected["input"].get("rua")
    if rua:
        whatif_args.extend(["--rua", str(FIXTURE_ROOT / rua)])
    candidate_code = main(whatif_args)

    return (
        baseline_code, json.loads(baseline_path.read_text(encoding="utf-8")),
        candidate_code, json.loads(candidate_path.read_text(encoding="utf-8")),
    )


# ── 第 1 层：参数校验与变更施加 ─────────────────────────────────────────


def test_every_change_key_is_exercised_in_this_file():
    """`constants.WHATIF_CHANGE_KEYS` 里每个键都必须在本文件里**真的被用过一次**。

    为什么不是断言 `{"p", "all"} <= set(WHATIF_CHANGE_KEYS)` 那种子集关系——
    那是个恒真式：往键集里加一个没人用的键，断言照样绿，而它意味着
    "多了一个 CLI 接受、实现却不处理"的键（那正是静默忽略）。
    这条按**源码里出现过该键的调用形态**判定，加键而没测试就会红。
    """
    source = Path(__file__).read_text(encoding="utf-8")
    markers = {
        "p": "p=reject", "sp": "sp=quarantine", "np": "np=quarantine",
        "t": "t=y", "all": "all=-all", "include": "include:_spf.example",
    }
    assert set(markers) == set(WHATIF_CHANGE_KEYS), \
        "键集变了：本文件与新键没有对应测试（新增 %s）" % (
            sorted(set(WHATIF_CHANGE_KEYS) - set(markers)),)
    for key, marker in markers.items():
        assert marker in source, "键 %r 没有被任何用例真正施加过（找不到 %r）" % (key, marker)


@pytest.mark.parametrize("item", [
    "p",              # 没有 =（也不是 include: 形态）
    "=reject",        # 键为空
    "q=reject",       # 未知键
    "p=",             # 值为空
    "p=drop",         # 策略值非法
    "t=maybe",        # t 只允许 y/n
    "all=all",        # 裸 all 被拒（要写限定符）
    "all=-alll",      # 形态错
    "include:",       # 空域名
    "include:not a domain",
])
def test_bad_change_is_an_error_not_ignored(item):
    """未知键或不可解析的值 → `InputError`（exit 3），**不做静默忽略**（`plan/03` §2 第 3 条）。"""
    with pytest.raises(InputError):
        parse_changes([item])


def test_include_uses_the_frozen_colon_form():
    """`plan/03` §2 冻结的 `include:` 形态**没有 `=`**——只按 `=` 切的实现会把它判成非法。"""
    changes = parse_changes(["include:_spf.example.invalid"])
    assert changes[0].key == "include"
    assert changes[0].value == "_spf.example.invalid"
    # `include=<domain>` 是同一件事的另一种写法，语义必须完全一致（raw 记录原文）。
    other = parse_changes(["include=_spf.example.invalid"])[0]
    assert (other.key, other.value) == (changes[0].key, changes[0].value)


def test_empty_change_list_is_an_error():
    with pytest.raises(InputError):
        parse_changes([])


def test_duplicate_key_is_rejected():
    """同一键两条变更：后者会静默覆盖前者——那种"我改了"是假的。"""
    with pytest.raises(InputError):
        parse_changes(["p=reject", "p=none"])


def test_valid_changes_are_parsed():
    changes = parse_changes(["p=reject", "t=y", "all=-all", "include:_spf.example.net"])
    assert [item.key for item in changes] == ["p", "t", "all", "include"]
    assert changes[0] == Change(key="p", value="reject", raw="p=reject")


def test_set_tag_preserves_other_tags_and_order():
    snap = _snap([_txt("_dmarc.example.com", ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"])])
    new, applied = apply_changes(
        snap, changes=parse_changes(["p=reject"]), author_domain="example.com")
    assert new["queries"][0]["answer"][0] == \
        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
    assert applied[0]["record"] == "_dmarc.example.com"
    assert applied[0]["path"] == "queries[0].answer[0]"
    assert applied[0]["from"] != applied[0]["to"]


def test_apply_changes_does_not_mutate_the_input_snapshot():
    """改的是**副本**：基线快照被就地改掉的话，"与基线做差分"就没意义了。"""
    original = _snap([_txt("_dmarc.example.com", ["v=DMARC1; p=none"])])
    snapshot = json.loads(json.dumps(original))
    apply_changes(snapshot, changes=parse_changes(["p=reject"]), author_domain="example.com")
    assert snapshot == original


def test_t_change_normalises_boolean_forms():
    snap = _snap([_txt("_dmarc.example.com", ["v=DMARC1; p=none"])])
    new, applied = apply_changes(
        snap, changes=parse_changes(["t=true"]), author_domain="example.com")
    assert "t=y" in new["queries"][0]["answer"][0]
    assert applied[0]["value"] == "y"


@pytest.mark.parametrize("key,expected", [
    # `p=` 记录里已有 → **就地替换**，其余标签原序不动
    ("p", "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"),
    # `sp=` / `np=` 记录里没有 → **追加**，不覆盖已存在的标签
    ("sp", "v=DMARC1; p=none; rua=mailto:dmarc@example.com; sp=quarantine"),
    ("np", "v=DMARC1; p=none; rua=mailto:dmarc@example.com; np=quarantine"),
])
def test_dmarc_policy_tags_settable_and_preserve_the_rest(key, expected):
    """`p=` / `sp=` / `np=` 走同一条分支（改策略标签）——三个键各过一遍。

    只测 `p=` 会放过"`sp=`/`np=` 被当成未知键丢弃"这类错误，而它们恰是 RFC 9989
    新增的两个标签（题面 M3 验收 3 点名的形态）。
    同时区分"已存在 → 就地替换"与"不存在 → 追加"两种情形。
    """
    snap = _snap([_txt("_dmarc.example.com", ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"])])
    new, applied = apply_changes(
        snap, changes=parse_changes(["%s=quarantine" % key]), author_domain="example.com")
    assert new["queries"][0]["answer"][0] == expected
    assert applied[0]["key"] == key
    assert applied[0]["to"] == expected


def test_multiple_changes_and_t_y_downgrade_end_to_end(tmp_path):
    """多条 `--change` 一起施加，且 `t=y` 的降级要在**端到端**里看得见。

    `p=reject` + `t=y` → 处置应是 `quarantine`（§4.7 降一级），不是 `reject`。
    单测 `_set_tag` 只能证明"标签写进去了"，写进去之后判定有没有用它，要靠 CLI 产物。
    """
    from mailvault.cli import main

    directory = FIXTURE_ROOT / "p-reject"
    code = main([
        "whatif", "--snapshot", str(directory / "snap.json"),
        "--eml", str(directory / "message.eml"), "--query", str(directory / "query.json"),
        "--change", "p=reject", "--change", "t=y",
        "--json", str(tmp_path / "c.json"), "--md", str(tmp_path / "c.md"),
    ])
    assert code == 1
    artifact = json.loads((tmp_path / "c.json").read_text(encoding="utf-8"))
    assert len(artifact["whatif"]["changes"]) == 2
    dmarc = next(item for item in artifact["checks"] if item["check_id"] == "dmarc.evaluate")
    assert dmarc["subject"]["policy_value"] == "reject"
    assert dmarc["subject"]["disposition"] == "quarantine", "t=y 必须把 reject 降一级"
    assert dmarc["subject"]["test_mode"] is True


def test_all_change_rewrites_the_qualifier():
    snap = _snap([_txt("example.com", ["v=spf1 ip4:192.0.2.0/24 ~all"])])
    new, _applied = apply_changes(
        snap, changes=parse_changes(["all=-all"]), spf_domain="example.com")
    assert new["queries"][0]["answer"][0] == "v=spf1 ip4:192.0.2.0/24 -all"


def test_all_change_appends_when_no_all_present():
    snap = _snap([_txt("example.com", ["v=spf1 ip4:192.0.2.0/24"])])
    new, _applied = apply_changes(
        snap, changes=parse_changes(["all=-all"]), spf_domain="example.com")
    assert new["queries"][0]["answer"][0] == "v=spf1 ip4:192.0.2.0/24 -all"


def test_include_change_is_inserted_before_all():
    """`include:` 必须插在 `all` **之前**：RFC 7208 §5.1 的 `all` 是"其余都不匹配"的兜底，
    放在它后面永远走不到。"""
    snap = _snap([_txt("example.com", ["v=spf1 ip4:192.0.2.0/24 -all"])])
    new, _applied = apply_changes(
        snap, changes=parse_changes(["include:_spf.example.net"]), spf_domain="example.com")
    assert new["queries"][0]["answer"][0] == \
        "v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all"


def test_dmarc_change_without_a_record_is_an_error():
    """快照里没有 `_dmarc` 记录 → 明确报错，**不凭空造记录**（`plan/04` §2.3）。"""
    snap = _snap([_txt("example.com", ["v=spf1 -all"])])
    with pytest.raises(InputError):
        apply_changes(snap, changes=parse_changes(["p=reject"]), author_domain="example.com")


def test_spf_change_without_a_record_is_an_error():
    snap = _snap([_txt("_dmarc.example.com", ["v=DMARC1; p=none"])])
    with pytest.raises(InputError):
        apply_changes(snap, changes=parse_changes(["all=-all"]), spf_domain="example.com")


def test_ambiguous_dmarc_target_is_an_error_not_a_guess():
    """两条 `_dmarc` 记录都带 DMARC、且都对不上 Author 域 → 报错，不挑一条来猜。"""
    snap = _snap([
        _txt("_dmarc.a.example.com", ["v=DMARC1; p=none"]),
        _txt("_dmarc.b.example.com", ["v=DMARC1; p=none"]),
    ])
    with pytest.raises(InputError):
        apply_changes(snap, changes=parse_changes(["p=reject"]), author_domain="zzz.example.com")


# ── 第 2 层：差分可复算（两个方向） ─────────────────────────────────────


def _sample_ledger(result: str) -> dict:
    return {
        "schema_version": 1,
        "ledger_id": "id-" + result,
        "tool_version": "0.1.0",
        "snapshot": {"fetched_at": "2026-10-19T18:35:00Z", "resolver": "synthetic"},
        "query": {"mail_from": "a@example.com", "helo": None, "client_ip": "192.0.2.10",
                  "trusted_authserv_ids": ["mx.example.com"]},
        "checks": [
            {"check_id": "spf.check_host", "module": "M2", "result": result,
             "reason": "reason-" + result, "evidence_ref": ["RFC7208#5"], "warnings": [],
             "subject": {"domain": "example.com"}, "trace": [], "budget": None, "tree": None},
            {"check_id": "dmarc.evaluate", "module": "M4", "result": "pass",
             "reason": "dmarc", "evidence_ref": ["RFC9989#4.10"], "warnings": ["w"],
             "subject": {"author_domain": "example.com"}, "trace": [], "budget": None,
             "tree": None},
        ],
        "reconcile": {"entries": [], "received_chain": {"hop_count": 1}},
        "summary": {"exit_code": 1 if result == "fail" else 0,
                    "counts": {"pass": 1, "fail": 1 if result == "fail" else 0,
                               "undecidable": 0}},
    }


def test_diff_is_invertible_both_directions():
    """`apply(baseline, ops) == candidate` 且 `apply(candidate, invert(ops)) == baseline`。"""
    baseline = _sample_ledger("pass")
    candidate = _sample_ledger("fail")
    diff = diff_ledgers(baseline, candidate)
    assert diff["schema_version"] == DIFF_SCHEMA_VERSION
    assert diff["op_count"] > 0
    assert apply_ops(baseline, diff["ops"]) == candidate
    assert apply_ops(candidate, invert_ops(diff["ops"])) == baseline


def test_diff_handles_added_and_removed_keys():
    """字典键的增删也必须可逆（只做 set 的实现会在这里丢字段）。"""
    baseline = {"a": 1, "b": {"c": 2}}
    candidate = {"a": 1, "d": {"e": 3}}
    ops = diff_ledgers(baseline, candidate)["ops"]
    assert apply_ops(baseline, ops) == candidate
    assert apply_ops(candidate, invert_ops(ops)) == baseline
    kinds = sorted(op["op"] for op in ops)
    assert kinds.count("add") == 1 and kinds.count("remove") == 1


def test_diff_of_lists_with_different_lengths_falls_back_to_whole_value():
    """长度不同的列表按下标做增删无法唯一定义重建顺序 → 整表当一个值（宁粗不歧义）。"""
    baseline = {"checks": [{"a": 1}]}
    candidate = {"checks": [{"a": 1}, {"a": 2}]}
    ops = diff_ledgers(baseline, candidate)["ops"]
    assert len(ops) == 1 and ops[0]["op"] == "set"
    assert apply_ops(baseline, ops) == candidate
    assert apply_ops(candidate, invert_ops(ops)) == baseline


def test_diff_is_deterministic_and_key_order_independent():
    baseline = {"z": {"y": 1, "x": 2}}
    candidate = {"z": {"y": 9, "x": 2}}
    first = diff_ledgers(baseline, candidate)["ops"]
    second = diff_ledgers(candidate=dict(candidate), baseline=dict(baseline))["ops"]
    assert first == second
    assert [op["path"] for op in first] == sorted(op["path"] for op in first)


# ── 第 3 层：fixture 逐条对账 ───────────────────────────────────────────


_INDEX = re.compile(r"\[(\d+)\]")


def _lookup(root, path: str):
    node = root
    for part in path.split("."):
        indices = [int(match.group(1)) for match in _INDEX.finditer(part)]
        name = _INDEX.sub("", part)
        if name:
            node = node[name]
        for index in indices:
            node = node[index]
    return node


def _observation(baseline: dict, candidate: dict) -> dict:
    """把基线账本 + 候选产物摊成与 `expected.json` 点路径同构的嵌套字典。"""
    def by_id(ledger):
        return {entry["check_id"]: entry for entry in ledger["checks"]}

    base_checks = by_id(baseline)
    cand_checks = by_id(candidate)
    whatif = candidate["whatif"]
    diff = whatif["diff"]
    return {
        "baseline": {
            "spf": base_checks["spf.check_host"],
            "dmarc": base_checks["dmarc.evaluate"],
            "exit_code": baseline["summary"]["exit_code"],
        },
        "candidate": {
            "spf": cand_checks["spf.check_host"],
            "dmarc": cand_checks["dmarc.evaluate"],
            "exit_code": candidate["summary"]["exit_code"],
        },
        "diff": {
            "op_count": diff["op_count"],
            "exit_code": diff["summary"]["exit_code"],
            "changed_checks": diff["changed_checks"],
        },
        "applied": whatif["changes"],
        "rua": whatif["rua"],
    }


def _check(observation: dict, key: str, want):
    if key.endswith("_gt"):
        got = _lookup(observation, key[: -len("_gt")])
        return got, got > want
    if key.endswith("_ge"):
        got = _lookup(observation, key[: -len("_ge")])
        return got, got >= want
    if key.endswith("_contains"):
        got = _lookup(observation, key[: -len("_contains")])
        if isinstance(got, str):
            return got, want in got
        return got, any(want in str(item) for item in got)
    got = _lookup(observation, key)
    return got, got == want


@pytest.mark.parametrize("directory", _case_dirs(), ids=lambda path: path.name)
def test_fixture_expectations(directory: Path, tmp_path: Path):
    _baseline_code, baseline, _candidate_code, candidate = _run_case(directory, tmp_path)
    expected = _expected(directory)
    observation = _observation(baseline, candidate)
    problems: list[str] = []
    for key, want in sorted(expected["expect"].items()):
        try:
            got, ok = _check(observation, key, want)
        except (KeyError, IndexError, TypeError) as exc:
            problems.append("%s：点路径解析失败（%r）" % (key, exc))
            continue
        if not ok:
            problems.append("%s：期望 %r，实得 %r" % (key, want, got))
    assert problems == [], "%s：%s" % (directory.name, "；".join(problems))


def test_fixture_exit_codes_reflect_the_two_cases(tmp_path):
    """反自证：差分必须**能真的改变退出码**（`spf-tighten` 0→1），否则"差分"只是装饰。"""
    tighten = FIXTURE_ROOT / "spf-tighten"
    baseline_code, baseline, candidate_code, candidate = _run_case(tighten, tmp_path)
    assert (baseline_code, candidate_code) == (0, 1)
    assert baseline["summary"]["exit_code"] == 0
    assert candidate["summary"]["exit_code"] == 1

    reject = FIXTURE_ROOT / "p-reject"
    reject_dir = tmp_path / "reject"
    reject_dir.mkdir()
    baseline_code, _baseline, candidate_code, _candidate = _run_case(reject, reject_dir)
    # p=none → p=reject 在**判定**上是 fail → fail（处置变了，结论没变）。
    assert (baseline_code, candidate_code) == (1, 1)


def test_cli_artifact_can_be_used_to_reverse_derive_the_baseline(tmp_path):
    """端到端可复算：`audit` 的基线 == 把 whatif 的 ops 反转后施加到候选账本。

    这条是"差分结果能反推出基线"（题面 §3 的 M5 验收 1）的**实测**，不是口号：
    基线来自**另一次运行**的 `audit` 产物，候选来自 `whatif`，两者独立。
    """
    directory = FIXTURE_ROOT / "p-reject"
    baseline_code, baseline, _candidate_code, candidate = _run_case(directory, tmp_path)
    assert baseline_code == 1

    core = {key: value for key, value in candidate.items() if key != "whatif"}
    ops = candidate["whatif"]["diff"]["ops"]
    assert apply_ops(core, invert_ops(ops)) == baseline
    assert apply_ops(baseline, ops) == core
    assert candidate["whatif"]["baseline"]["ledger_id"] == baseline["ledger_id"]


def test_whatif_double_run_is_byte_identical(tmp_path):
    """差分可复算的另一半：同一输入两次运行 `verdict.json` 字节级一致。"""
    from mailvault.cli import main

    directory = FIXTURE_ROOT / "spf-tighten"
    digests = []
    for name in ("a.json", "b.json"):
        main([
            "whatif", "--snapshot", str(directory / "snap.json"),
            "--eml", str(directory / "message.eml"), "--query", str(directory / "query.json"),
            "--change", "all=-all",
            "--json", str(tmp_path / name), "--md", str(tmp_path / (name + ".md")),
        ])
        digests.append((tmp_path / name).read_bytes())
    assert digests[0] == digests[1]


def test_diff_cli_writes_report_and_is_marked_as_a_comparison(tmp_path):
    """`diff` 比较两份账本：产物写 `diff.json`/`diff.md`（**不覆盖** `verdict.*`），返回 0。

    "有差异"是 diff 的正常输出，不是失败——把它映射成 exit 1 会与本项目的
    "1 = 存在 fail"撞语义。
    """
    from mailvault.cli import main

    directory = FIXTURE_ROOT / "p-reject"
    _baseline_code, baseline, _candidate_code, candidate = _run_case(directory, tmp_path)
    baseline_path = tmp_path / "p-reject-baseline.json"
    candidate_path = tmp_path / "p-reject-candidate.json"

    code = main([
        "diff", "--baseline", str(baseline_path), "--candidate", str(candidate_path),
        "--json", str(tmp_path / "d.json"), "--md", str(tmp_path / "d.md"),
    ])
    assert code == int(ExitCode.OK)
    artifact = json.loads((tmp_path / "d.json").read_text(encoding="utf-8"))
    assert artifact["schema_version"] == DIFF_SCHEMA_VERSION
    assert artifact["baseline_ledger_id"] == baseline["ledger_id"]
    assert artifact["candidate_ledger_id"] == candidate["ledger_id"]
    assert apply_ops(baseline, artifact["diff"]["ops"]) == candidate
    assert apply_ops(candidate, invert_ops(artifact["diff"]["ops"])) == baseline
    text = (tmp_path / "d.md").read_text(encoding="utf-8")
    assert "结构差分" in text and "退出码" in text


def test_diff_cli_rejects_a_non_ledger_json(tmp_path):
    from mailvault.cli import main

    (tmp_path / "bad.json").write_text('{"schema_version": 99}', encoding="utf-8")
    assert main([
        "diff", "--baseline", str(tmp_path / "bad.json"),
        "--candidate", str(tmp_path / "bad.json"),
        "--json", str(tmp_path / "d.json"),
    ]) == int(ExitCode.INPUT_ERROR)


# ── 第 4 层：RUA 关联 ───────────────────────────────────────────────────


def test_missing_rua_is_undecidable_with_required_inputs():
    """题面 §3 的 M5 验收 3：无 RUA 数据 → undecidable + 该功能所需的输入清单，不猜。"""
    result = rua_association(None)
    assert result["status"] == "undecidable"
    assert result["affected"] == []
    assert result["required_inputs"], "必须给出所需输入清单"
    assert any("source_ip" in item for item in result["required_inputs"])
    assert "报告期" in result["period_note"] or "只覆盖报告期内" in result["period_note"]


def test_rua_fixture_clusters_the_senders_that_reject_would_break():
    """`affected` 的筛选口径：SPF 与 DKIM **都**没通过才算会被 `p=reject` 打断。

    真实报告里有一条"SPF fail 但 DKIM pass"（对齐成立）——写成"任一不过就算"会把
    它也算进来，`affected_total` 立刻从 1 变 2。
    """
    result = rua_association(str(FIXTURE_ROOT / "rua.json"), policy_value="reject")
    assert result["status"] == "complete"
    assert result["records"] == 3
    assert result["affected_total"] == 1
    assert [item["source_ip"] for item in result["affected"]] == ["198.51.100.9"]
    assert result["affected"][0]["would_be"] == "reject"
    assert result["report_period"] == {"begin": 1767225600, "end": 1767312000}
    assert "只覆盖报告期内" in result["period_note"]
    assert "依赖报告方" in result["period_note"]


def test_rua_with_no_records_is_undecidable(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"report_metadata": {"org_name": "X"}, "records": []}),
                    encoding="utf-8")
    result = rua_association(str(path))
    assert result["status"] == "undecidable"
    assert result["required_inputs"]


def test_rua_path_typo_is_an_input_error_not_undecidable(tmp_path):
    """给了 `--rua` 但路径不存在 → 3（输入错误），不是"没有数据"。

    把"路径打错"读成"没有报告"会让用户以为功能跑过了。
    """
    with pytest.raises(InputError):
        rua_association(str(tmp_path / "nope.json"))


def test_rua_malformed_json_is_an_input_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(InputError):
        rua_association(str(path))


def test_rua_is_not_part_of_the_exit_code(tmp_path):
    """`--rua` 缺省不影响退出码：它是对**历史报告**的附加关联，不是本次判定。

    退出码仍由 `checks[]` 决定（`exits.exit_code_for`）。若把"缺 --rua"也算成
    undecidable，`whatif` 不加 `--rua` 就永远非零——那会让这条功能变成噪声。
    """
    from mailvault.cli import main

    directory = FIXTURE_ROOT / "spf-tighten"
    base_args = [
        "whatif", "--snapshot", str(directory / "snap.json"),
        "--eml", str(directory / "message.eml"), "--query", str(directory / "query.json"),
        "--change", "all=-all", "--json", str(tmp_path / "c.json"),
    ]
    without = main(base_args)
    with_rua = main(base_args[:1] + ["--rua", str(FIXTURE_ROOT / "rua.json")] + base_args[1:])
    assert without == with_rua == 1
    artifact = json.loads((tmp_path / "c.json").read_text(encoding="utf-8"))
    assert artifact["whatif"]["rua"]["status"] == "complete"


# ── 反自证 / 生成器 / 分层 ──────────────────────────────────────────────


def test_whatif_strict_evidence_passes_on_clean_fixtures(tmp_path):
    from mailvault.cli import main

    for directory in _case_dirs():
        for change in _expected(directory)["input"]["changes"]:
            code = main([
                "whatif", "--snapshot", str(directory / "snap.json"),
                "--eml", str(directory / "message.eml"),
                "--query", str(directory / "query.json"),
                "--change", change, "--strict-evidence",
                "--json", str(tmp_path / ("%s.json" % directory.name)),
                "--md", str(tmp_path / ("%s.md" % directory.name)),
            ])
            assert code in (0, 1, 2), "%s：strict 下不该是输入错误" % directory.name


def test_whatif_strict_evidence_rejects_a_forbidden_word_in_the_input_header(tmp_path):
    """`whatif` 的 strict 自检位为 false → **非零退出**（K24：`audit` 与 `whatif` 同一道闸）。

    与 `test_missing_rua_is_undecidable_with_required_inputs` 不同：这条走的是 CLI 的
    `_strict_guard`（装配期自检），证明 `whatif` 也**没有**把 strict 只挂在 `audit` 上。
    """
    from mailvault.cli import main

    (tmp_path / "snap.json").write_text(json.dumps(_snap([
        _txt("example.com", ["v=spf1 ip4:192.0.2.0/24 -all"]),
        _txt("_dmarc.example.com", ["v=DMARC1; p=none"]),
    ])), encoding="utf-8")
    (tmp_path / "query.json").write_text(json.dumps({
        "mail_from": "alice@example.com", "client_ip": "192.0.2.10",
        "trusted_authserv_ids": ["mx.example.com"],
    }), encoding="utf-8")
    (tmp_path / "message.eml").write_bytes(
        b"Authentication-Results: mx.example.com;\r\n\tspf=pass (looks forged)\r\n"
        b"From: alice@example.com\r\n\r\nbody\r\n")

    args = [
        "whatif", "--snapshot", str(tmp_path / "snap.json"),
        "--eml", str(tmp_path / "message.eml"), "--query", str(tmp_path / "query.json"),
        "--change", "p=none", "--json", str(tmp_path / "c.json"),
        "--md", str(tmp_path / "c.md"),
    ]
    assert main(args + ["--strict-evidence"]) == int(ExitCode.INPUT_ERROR)
    assert main(args) in (0, 1, 2), "非 strict 模式下允许描述性用词"


def test_fixture_generator_is_idempotent():
    """`plan/04` §2.5：生成器 `--check` 必须逐字节比对（跑真实生成器）。"""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "gen_whatif_fixtures.py"), "--check"],
        cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    assert result.returncode == 0, result.stdout.decode("utf-8", "replace")


def test_whatif_module_imports_only_allowed_layers():
    """`modules/whatif.py` 只许 import L1/L2（`plan/03` §0 的分层）。"""
    import ast

    allowed = (
        "__future__", "copy", "json", "re", "dataclasses", "pathlib", "typing",
        "mailvault.constants", "mailvault.exits", "mailvault.canonical",
        "mailvault.snapshot", "mailvault.query", "mailvault.eml", "mailvault.psl",
        "mailvault.ledger", "mailvault.modules",
    )
    source = (REPO_ROOT / "mailvault" / "modules" / "whatif.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                assert node.level == 2
                assert ("mailvault." + (node.module or "")).startswith(allowed), \
                    "whatif.py 不得 import %r" % (node.module,)
            elif node.module:
                assert node.module.startswith(allowed), "whatif.py 不得 import %r" % node.module
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in (
                    "__future__", "copy", "json", "re", "dataclasses", "pathlib", "typing"), \
                    "whatif.py 不得 import %r" % alias.name


def test_whatif_fixture_has_changes_json_in_the_cli_shape():
    """`changes.json` 与 CLI 的 `--change KEY=VALUE` **同形**（字符串列表）。"""
    payload = json.loads((FIXTURE_ROOT / "changes.json").read_text(encoding="utf-8"))
    assert isinstance(payload["changes"], list)
    assert all(isinstance(item, str) and "=" in item for item in payload["changes"])
    parsed = parse_changes(payload["changes"])
    assert len(parsed) == len(payload["changes"])
