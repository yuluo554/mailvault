"""卫生门（`tools/check_fixture_hygiene.py`）的判据规则测试（M6 扩充）。

M6 把扫描面从 `fixtures/` 扩到 `fixtures/ + examples/`，并新增两条**结构性剥离**：

1. **标识符命名空间**（`check_id` / `trace[].node`）：`dmarc.evaluate` / `dkim.bh` 与域名同形，
   但它们是本项目自己的标识符。剥掉首段命名空间后**路径部分照旧被扫**——
   `walk.mail.google.com.0` 会剥成 `mail.google.com` 并**照样报红**（不是盲区）。
2. **RFC 引用**（`RFC5322.From`）：条款引用不是域名。

这里把"该绿的绿、该红的红"逐条钉死。**阴性对照与阳性对照成对出现**：
只测"该绿的绿"会让"把整行都剥掉"的实现也通过。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from check_fixture_hygiene import scan as hygiene_scan  # noqa: E402


def _probe(tmp_path: Path, relative: str, payload: dict) -> tuple[list[str], int]:
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload), encoding="utf-8")
    violations, scanned, _exempt = hygiene_scan(tmp_path)
    return violations, scanned


# ── 扫描面：fixtures/ 与 examples/ 都管 ────────────────────────────────


def test_examples_directory_is_scanned_too(tmp_path: Path) -> None:
    """`examples/` 是 M6 新增的扫描面：样例产物夹带真实域名必须报红。"""
    violations, scanned = _probe(
        tmp_path, "examples/probe/verdict.json",
        {"snapshot": {"queries": [{"qname": "mx.mail.google.com", "answer": []}]}},
    )
    assert scanned == 1
    assert any("mail.google.com" in item for item in violations), \
        "examples/ 里的真实域名必须被卫生门抓到：%r" % (violations,)


def test_fixture_directory_is_still_scanned(tmp_path: Path) -> None:
    violations, scanned = _probe(
        tmp_path, "fixtures/probe/snap.json",
        {"queries": [{"qname": "mx.mail.google.com", "answer": []}]},
    )
    assert scanned == 1
    assert violations, "fixtures/ 的判据不得因扩充扫描面而被削弱"


# ── 标识符命名空间剥离（fail-closed） ──────────────────────────────────


@pytest.mark.parametrize("node_id", ["dkim.bh", "dmarc.evaluate", "snap.resolve", "align.spf",
                                     "dmarc.org", "reconcile.cross_check", "n0", "n0.1"])
def test_node_identifiers_are_not_domains(tmp_path: Path, node_id: str) -> None:
    """本项目自己的标识符不该被判成域名（否则每加一个节点 id 就要改白名单）。"""
    violations, scanned = _probe(
        tmp_path, "examples/probe/verdict.json",
        {"checks": [{"check_id": node_id, "trace": [{"node": node_id, "note": ""}]}]},
    )
    assert scanned == 1
    assert violations == [], "%r 是标识符，不该报红：%r" % (node_id, violations)


def test_domain_inside_a_walk_node_id_is_still_caught(tmp_path: Path) -> None:
    """**阳性对照**：命名空间剥掉之后，路径里的真实域名必须照样报红。

    节点 id 的形态是 `walk.<domain>.<跳数>`（K12：走查 id 带起点域名）。
    剥掉 `walk` 与下标后剩下 `mail.google.com` —— 它必须被抓到。否则"剥前缀"
    就悄悄退化成"node 字段一律放行"，正好漏掉最该抓的那一类。
    """
    violations, scanned = _probe(
        tmp_path, "examples/probe/verdict.json",
        {"checks": [{"trace": [{"node": "walk.mail.google.com.0", "note": ""}]}]},
    )
    assert scanned == 1
    assert any("mail.google.com" in item for item in violations), \
        "node id 路径里的真实域名必须报红：%r" % (violations,)


def test_unknown_namespace_is_not_stripped(tmp_path: Path) -> None:
    """首段不在闭集里 → **不剥**（fail-closed）：新命名空间不得自动变成"标识符"。"""
    violations, scanned = _probe(
        tmp_path, "examples/probe/verdict.json",
        {"checks": [{"trace": [{"node": "zzz.mail.google.com.0", "note": ""}]}]},
    )
    assert scanned == 1
    assert violations, "未登记命名空间必须 fail-closed 地当成域名候选：%r" % (violations,)


def test_reserved_domain_inside_a_walk_node_id_stays_green(tmp_path: Path) -> None:
    """阴性对照：保留域即使在 node id 里也应绿（剥离不是为了制造假红）。"""
    violations, scanned = _probe(
        tmp_path, "examples/probe/verdict.json",
        {"checks": [{"trace": [{"node": "walk.example.com.0", "note": ""}]}]},
    )
    assert scanned == 1
    assert violations == []


# ── RFC 引用剥离 ──────────────────────────────────────────────────────


def test_rfc_citation_in_free_text_is_not_a_domain(tmp_path: Path) -> None:
    violations, scanned = _probe(
        tmp_path, "examples/probe/verdict.json",
        {"checks": [{"trace": [{"node": "dmarc.author",
                                "note": "RFC5322.From 提取到 1 个域：example.com"}]}]},
    )
    assert scanned == 1
    assert violations == [], "RFC 引用不是域名：%r" % (violations,)


def test_real_domain_in_free_text_is_still_caught(tmp_path: Path) -> None:
    """阳性对照：剥 RFC 引用不得连带把自由文本里的真域名放行。"""
    violations, scanned = _probe(
        tmp_path, "examples/probe/verdict.json",
        {"checks": [{"trace": [{"node": "dmarc.author",
                                "note": "RFC5322.From 提取到 1 个域：mail.google.com"}]}]},
    )
    assert scanned == 1
    assert any("mail.google.com" in item for item in violations), \
        "自由文本里的真实域名必须报红：%r" % (violations,)