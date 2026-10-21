"""RFC 7208 测试集接入（M1）：**断网可读、可跑、可逐条定位**。

M1 的验收面是"测试集能被本地 runner 读取、断网下能跑（内置 DNS 桩）"——
求值器本体是 M2 的事，所以这里**不断言通过率**。断言的是三件更容易腐坏的事：

1. 上游文件原样在位（sha256 + LICENSE + 203 用例 / 16 分组）；
2. 桩的语义与 pyspf driver 一致（TIMEOUT / NONE / 自动合成 TXT / CNAME 跟一跳）；
3. 每条用例都能转成**标准 `snap.json` 快照**——即测试集不需要为测试开新字段。

第 3 条最有价值：它证明 `plan/03` §3.1 的 schema 能承载真实测试集，
而不是"生产一张表、测试另一张表"。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import rfc7208_suite as suite_mod

REPO_ROOT = Path(__file__).resolve().parent.parent
SUITE = REPO_ROOT / "fixtures" / "spf" / "rfc7208-tests.yml"
LICENSE = REPO_ROOT / "fixtures" / "spf" / "rfc7208-tests.LICENSE"


@pytest.fixture(scope="module")
def suite():
    return suite_mod.load_suite()


# ── 上游文件在位 ────────────────────────────────────────────────────────


def test_suite_and_license_present():
    assert SUITE.is_file(), "RFC 7208 测试集未入仓"
    assert LICENSE.is_file(), "上游许可未入仓（BSD 式许可要求保留）"


def test_license_keeps_upstream_copyright():
    """许可第 1 条要求保留版权声明——文件在不够，内容还得在。"""
    text = LICENSE.read_text(encoding="utf-8")
    assert "Stuart D Gathman" in text
    assert "Redistribution and use in source and binary forms" in text


def test_suite_sha256_is_stable(suite):
    """测试集的字节即"上游哪一版"的证据；归一化会改变它。"""
    actual = hashlib.sha256(SUITE.read_bytes()).hexdigest()
    assert suite.sha256 == actual


def test_gitattributes_freezes_suite_bytes():
    """.gitattributes 必须标 -text，否则克隆时换行归一 → sha 变。"""
    text = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "fixtures/spf/rfc7208-tests.yml -text" in text
    assert "mailvault/data/public_suffix_list.dat -text" in text


# ── 用例结构 ────────────────────────────────────────────────────────────


def test_case_count_and_sections(suite):
    assert suite.case_count == 203, "上游测试集是 203 个 spec 用例"
    sections = suite.by_section()
    assert len(sections) == 16, "上游测试集分 16 组"


def test_every_case_has_the_five_inputs(suite):
    for case in suite.cases:
        assert case.spec, case.case_id
        assert case.helo is not None
        assert case.host, case.case_id
        assert case.mailfrom is not None
        assert case.result, case.case_id


def test_case_ids_are_unique(suite):
    ids = [case.case_id for case in suite.cases]
    assert len(ids) == len(set(ids))


def test_multi_valued_expectations_are_preserved(suite):
    """上游允许"两种结果都可接受"（如 `[fail, permerror]`）——不得被折叠成一个。"""
    multi = [case for case in suite.cases if len(case.result) > 1]
    assert multi, "上游测试集里确实有多值期望"
    for case in multi:
        assert len(case.acceptable) == len(case.result)
        assert case.accepts(case.result[0])


def test_non_strict_case_is_flagged(suite):
    """上游有一条 `strict: 2`（bytes-bug）：非 strict 语义必须被保留下来。"""
    non_strict = [case.case_id for case in suite.cases if not case.is_strict]
    assert non_strict == ["Test cases from implementation bugs/bytes-bug"]
    # 原值也要保留（压成 bool 会丢掉"上游写的是 2"这件事）
    flagged = suite.find(non_strict[0])
    assert flagged.strict == 2


# ── 离线 DNS 桩 ─────────────────────────────────────────────────────────


def test_stub_answers_txt_from_zonedata():
    stub = suite_mod.StubResolver({"a.example.com": [{"TXT": "v=spf1 -all"}]})
    response = stub.txt("a.example.com")
    assert response.is_noerror
    assert response.answer == ("v=spf1 -all",)


def test_stub_unknown_name_is_nxdomain():
    stub = suite_mod.StubResolver({})
    assert stub.txt("absent.example.com").rcode == "NXDOMAIN"


def test_stub_error_prefix_times_out():
    """上游约定：`error.*` 开头的名字必须超时（不是 NXDOMAIN）。"""
    stub = suite_mod.StubResolver({})
    assert stub.txt("error.example.com").rcode == suite_mod.TIMEOUT


def test_stub_whole_zone_timeout():
    stub = suite_mod.StubResolver({"slow.example.com": ["TIMEOUT"]})
    assert stub.txt("slow.example.com").rcode == suite_mod.TIMEOUT


def test_stub_none_sentinel_means_empty_answer_not_nxdomain():
    """"查了但没有" 必须是 NOERROR + 空答案，不能是 NXDOMAIN。"""
    stub = suite_mod.StubResolver({"n.example.com": [{"TXT": "NONE"}]})
    response = stub.txt("n.example.com")
    assert response.rcode == "NOERROR"
    assert response.answer == ()


def test_stub_synthesizes_txt_from_spf_like_upstream():
    """上游 driver：有 SPF 无 TXT 时合成同名 TXT（测试集有分组依赖这一性质）。"""
    stub = suite_mod.StubResolver({"s.example.com": [{"SPF": "v=spf1 -all"}]})
    response = stub.txt("s.example.com")
    assert response.is_noerror
    assert response.answer == ("v=spf1 -all",)


def test_stub_does_not_synthesize_when_txt_present():
    stub = suite_mod.StubResolver({
        "s.example.com": [{"SPF": "v=spf1 -all"}, {"TXT": "v=spf1 -ip4:192.0.2.1 -all"}],
    })
    assert stub.txt("s.example.com").answer == ("v=spf1 -ip4:192.0.2.1 -all",)


def test_stub_follows_cname_one_hop():
    stub = suite_mod.StubResolver({
        "b.example.org": [{"CNAME": "a.example.org"}],
        "a.example.org": [{"TXT": "v=spf1 -all"}],
    })
    response = stub.txt("b.example.org")
    assert response.is_noerror
    assert response.answer == ("v=spf1 -all",)


def test_stub_formats_mx():
    stub = suite_mod.StubResolver({"e.example.com": [{"MX": [10, "mail.example.com"]}]})
    assert stub.query("e.example.com", "MX").answer == ("10 mail.example.com",)


def test_stub_records_calls_for_assertions():
    stub = suite_mod.StubResolver({"a.example.com": [{"TXT": "v=spf1 -all"}]})
    stub.txt("a.example.com")
    assert stub.calls == [("a.example.com", "TXT")]


# ── 转成标准快照 ────────────────────────────────────────────────────────


def test_every_case_converts_to_a_valid_snapshot(suite):
    """203 条全部要能变成 schema 合法、可 resolve 的快照——不为测试开字段。"""
    for case in suite.cases:
        snap = suite_mod.to_snapshot(case)
        assert snap.schema_version == 1
        assert snap.resolver == "synthetic"
        assert snap.psl_version and snap.psl_date
        # 快照要能被重新校验一遍（构造期与加载期同一套判据）
        from mailvault.snapshot import from_dict

        from_dict(snap.to_dict())


def test_snapshot_carries_the_sender_domain_query(suite):
    case = suite.find("Record lookup/both")
    snap = suite_mod.to_snapshot(case)
    resolved = snap.resolve("both.example.net", "TXT")
    assert resolved.found is True
    assert resolved.answer == ("v=spf1 -all",)


def test_snapshot_preserves_timeout_as_its_own_rcode(suite):
    """超时不能落成 NXDOMAIN——那会把"没问到"读成"没有记录"。"""
    case = suite.find("Record lookup/alltimeout")
    snap = suite_mod.to_snapshot(case)
    resolved = snap.resolve("alltimeout.example.net", "TXT")
    assert resolved.rcode == suite_mod.TIMEOUT
    assert resolved.answer == ()


def test_snapshot_includes_expanded_include_targets(suite):
    """include 目标要落进快照，否则 M2 求值时会被当成"数据缺口"。"""
    case = suite.find("Record lookup/both")
    snap = suite_mod.to_snapshot(case)
    assert snap.query_count > 1


def test_suite_is_readable_offline(suite):
    """读测试集与造快照全程不碰 socket。

    这里不替换 socket：M1 相关的模块（`tests/rfc7208_suite.py` / `snapshot.py`）
    在 AST 层面就不可能联网（`tools/check_no_network.py` 守）。这条断言的是
    "读文件能得到 203 条"，即数据面自足。
    """
    assert suite.case_count == 203
    assert suite_mod.case_summary(suite)["section_count"] == 16
