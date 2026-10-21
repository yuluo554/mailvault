"""账本契约：`evidence_ref` 构造期校验、渲染零外链、strict 禁词。

这些是"证据与账本质量"栏（题面 §5 栏 3，20 分）的骨架期保障。
"""

from __future__ import annotations

import re

import pytest

from mailvault import canonical
from mailvault.ledger import assemble, check_entry, summarize
from mailvault.render import find_forbidden, render


def _entry(**overrides):
    base = dict(
        check_id="spf.check_host",
        module="M1",
        subject={"domain": "example.invalid"},
        result="pass",
        reason="机制匹配",
        evidence_ref=["RFC7208#4.6.4"],
    )
    base.update(overrides)
    return check_entry(**base)


def _ledger(checks=None, reconcile=None):
    return assemble(
        snapshot_meta={
            "fetched_at": "2026-10-19T18:35:00Z",
            "resolver": "synthetic",
            "psl_version": "2026-10-01",
            "psl_date": "2026-10-01",
        },
        query={"mail_from": "sender@example.invalid", "client_ip": "192.0.2.1"},
        checks=checks if checks is not None else [_entry()],
        reconcile=reconcile,
    )


# ── evidence_ref 构造期校验 ─────────────────────────────────────────────


def test_entry_without_evidence_ref_degrades_not_dropped():
    """缺条款的判定**降级为 undecidable**，不是丢弃——丢弃会让"没判定"长得像"通过了"。"""
    entry = _entry(evidence_ref=[])
    assert entry["result"] == "undecidable"
    assert any("缺 evidence_ref" in w for w in entry["warnings"])
    assert "缺条款支撑" in entry["reason"]


def test_already_undecidable_without_ref_does_not_double_report():
    entry = _entry(result="undecidable", evidence_ref=[])
    assert entry["result"] == "undecidable"
    assert not any("降级" in w for w in entry["warnings"])


def test_unknown_result_raises():
    with pytest.raises(Exception):
        _entry(result="totally-made-up")


def test_assemble_rejects_entry_without_ref():
    """绕过 check_entry 直接塞条目 → 装配期必须拒绝。"""
    with pytest.raises(Exception):
        assemble(
            snapshot_meta={"fetched_at": "x"},
            query={},
            checks=[{"check_id": "a.b", "module": "M1", "result": "pass",
                     "reason": "r", "evidence_ref": []}],
        )


def test_summary_counts():
    ledger = _ledger([
        _entry(check_id="spf.a", result="pass"),
        _entry(check_id="dkim.b", result="fail"),
        _entry(check_id="dmarc.c", result="undecidable"),
    ])
    counts = ledger["summary"]["counts"]
    assert counts == {"pass": 1, "fail": 1, "undecidable": 1}
    assert ledger["summary"]["exit_code"] == 2  # undecidable 优先于 fail


def test_ledger_id_excludes_itself():
    ledger = _ledger()
    recomputed = canonical.digest({k: v for k, v in ledger.items() if k != "ledger_id"})
    assert ledger["ledger_id"] == recomputed


def test_summarize_surfaces_snapshot_metadata():
    meta = summarize(_ledger())
    assert meta["psl_version"] == "2026-10-01"
    assert meta["fetched_at"] == "2026-10-19T18:35:00Z"


# ── 渲染三律 ────────────────────────────────────────────────────────────


def test_render_is_deterministic():
    first = render(_ledger())
    second = render(_ledger())
    assert first == second


def test_render_has_no_external_links():
    """零外链：账本可离线归档，读者不该依赖任何 URL 才能读懂。"""
    text = render(_ledger())
    assert re.search(r"https?://", text) is None


def test_render_has_no_absolute_paths():
    text = render(_ledger())
    assert re.search(r"[A-Za-z]:[\\/]", text) is None


def test_render_ends_with_single_newline():
    text = render(_ledger())
    assert text.endswith("\n") and not text.endswith("\n\n")
    assert "\r" not in text


def test_render_includes_evidence_and_budget():
    entry = _entry(
        check_id="spf.check_host",
        budget={"terms": {"used": 3, "limit": 10, "ref": "RFC7208#4.6.4"}},
        trace=[{"node": "n0", "note": "根记录"}],
    )
    text = render(_ledger([entry]))
    assert "RFC7208#4.6.4" in text
    assert "terms" in text and "n0" in text


def test_render_includes_the_include_tree():
    """SPF 的 include 树要渲染成人读列表，且标出切点（题面 M2 输出要求）。"""
    tree = {
        "node_id": "n0", "parent": None, "domain": "example.invalid",
        "record": "v=spf1 include:_spf.example.invalid -all", "mechanism": None,
        "child_result": None, "consumes_term": False,
        "terminates_parent": False, "receiver_would_stop_here": False,
        "children": [{
            "node_id": "n1", "parent": "n0", "domain": "_spf.example.invalid",
            "record": "v=spf1 -all", "mechanism": "include", "child_result": "fail",
            "consumes_term": True, "terminates_parent": False,
            "receiver_would_stop_here": True, "children": [],
        }],
    }
    entry = _entry(tree=tree)
    text = render(_ledger([entry]))
    assert "include 树" in text
    assert "n1" in text and "_spf.example.invalid" in text
    assert "切点" in text


def test_render_tree_is_absent_when_null():
    """没有树的条目不该出现树小节——`tree: null` 不是空树。"""
    text = render(_ledger([_entry()]))
    assert "include 树" not in text


def test_render_undecidable_section_lists_reasons():
    entry = _entry(check_id="dkim.x", result="undecidable", reason="快照无 selector 的 key")
    text = render(_ledger([entry]))
    assert "灰区声明" in text
    assert "快照无 selector 的 key" in text


# ── strict-evidence 禁词 ────────────────────────────────────────────────


def test_find_forbidden_detects_words():
    assert find_forbidden("这封邮件被攻击了") == ["攻击"]
    assert find_forbidden("plain text") == []


def test_render_strict_raises_on_forbidden_word():
    entry = _entry(check_id="reconcile.x", result="undecidable",
                   reason="报文头疑似伪造")
    with pytest.raises(ValueError) as exc:
        render(_ledger([entry]), strict_evidence=True)
    assert "禁词" in str(exc.value)


def test_render_non_strict_allows_descriptive_word():
    entry = _entry(check_id="reconcile.x", result="undecidable",
                   reason="报文头疑似伪造")
    text = render(_ledger([entry]), strict_evidence=False)
    assert "伪造" in text


def test_render_strict_clean_text_passes():
    entry = _entry(check_id="reconcile.x", result="undecidable",
                   reason="与重算不一致，可能解释为转发改写或快照时点不同")
    text = render(_ledger([entry]), strict_evidence=True)
    assert "与重算不一致" in text


def test_render_reconcile_requires_two_explanations_shape():
    reconcile = {
        "entries": [{
            "class": "contradiction",
            "claimed": {"source": "Authentication-Results", "method": "spf", "result": "pass"},
            "recomputed": {"result": "fail", "ref": "RFC7208#4.6.4"},
            "explanations": [
                {"hypothesis": "转发导致信封发件人被改写", "verify": "检查 Received 链是否有转发跳"},
                {"hypothesis": "快照与接收时刻的 DNS 不同", "verify": "取接收前后两个快照重跑"},
            ],
        }],
    }
    text = render(_ledger([_entry()], reconcile), strict_evidence=True)
    assert "可能解释与验证方法" in text
    assert "转发导致信封发件人被改写" in text
    assert "取接收前后两个快照重跑" in text
