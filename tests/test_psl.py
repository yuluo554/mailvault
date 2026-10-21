"""PSL 冻结件与 Organizational Domain（M1）。

判据分两层：

1. **算法层**：用一组手工构造的规则表跑 publicsuffix.org 的 5 条匹配语义
   （普通 / 通配 / 例外 / 默认 / 本身就是后缀）。用自造规则表而不是真 PSL，
   是为了让"这条断言测的是算法，不是某天 PSL 恰好长什么样"。
2. **冻结件层**：真 PSL 的版本/日期/sha256 必须与元数据对得上，且能算出几个
   **长期稳定**的 Organizational Domain（`.co.uk`、`.com` 这类不会随版本漂移）。

题面 §2.5 灰区 3 要求输出带 PSL 版本与日期——这两件事在这里被断言成**结构**：
`PSL.version_block()` 永远两个键都在。
"""

from __future__ import annotations

import json

import pytest

from mailvault import psl as psl_module
from mailvault.exits import InputError

#: 自造规则表：覆盖五条匹配语义。
RULES = """\
// ===BEGIN ICANN DOMAINS===
com
uk
co.uk
jp
ac.jp
!city.kawasaki.jp
*.kawasaki.jp
*.ck
!www.ck
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
blogspot.com
// ===END PRIVATE DOMAINS===
"""

RULES_SHA = None  # 在 _write_psl 里现算


def _write_psl(tmp_path, rules: str = RULES, *, meta_overrides=None, sha=None):
    import hashlib

    tmp_path.mkdir(parents=True, exist_ok=True)
    dat = tmp_path / "public_suffix_list.dat"
    dat.write_bytes(rules.encode("utf-8"))
    meta = {
        "version": "test-version",
        "date": "2026-01-01",
        "source_url": "https://publicsuffix.org/list/public_suffix_list.dat",
        "sha256": sha if sha is not None else hashlib.sha256(rules.encode("utf-8")).hexdigest(),
    }
    if meta_overrides:
        meta.update(meta_overrides)
    meta_path = tmp_path / "psl.meta.json"
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    return dat, meta_path


@pytest.fixture()
def psl(tmp_path):
    dat, meta = _write_psl(tmp_path)
    return psl_module.load_psl(dat, meta)


# ── 算法：五条匹配语义 ─────────────────────────────────────────────────


def test_normal_rule(psl):
    info = psl.analyze("www.example.co.uk")
    assert info.public_suffix == "co.uk"
    assert info.organizational_domain == "example.co.uk"
    assert info.rule.kind == psl_module.RULE_NORMAL


def test_longest_match_wins(psl):
    """.co.uk 比 .uk 长，必须取更长的那个。"""
    assert psl.analyze("a.b.example.co.uk").public_suffix == "co.uk"
    assert psl.analyze("example.co.uk").organizational_domain == "example.co.uk"


def test_wildcard_rule(psl):
    """`*.kawasaki.jp`：`*` 匹配恰好一个标签。"""
    info = psl.analyze("www.foo.kawasaki.jp")
    assert info.public_suffix == "foo.kawasaki.jp"
    assert info.organizational_domain == "www.foo.kawasaki.jp"
    assert info.rule.kind == psl_module.RULE_WILDCARD


def test_exception_rule_beats_wildcard(psl):
    """`!city.kawasaki.jp` 是例外：公共后缀退回 `kawasaki.jp`。"""
    info = psl.analyze("www.city.kawasaki.jp")
    assert info.public_suffix == "kawasaki.jp"
    assert info.organizational_domain == "city.kawasaki.jp"
    assert info.rule.kind == psl_module.RULE_EXCEPTION


def test_exception_rule_beats_wildcard_second_case(psl):
    info = psl.analyze("www.ck")
    assert info.public_suffix == "ck"
    assert info.organizational_domain == "www.ck"
    assert info.rule.kind == psl_module.RULE_EXCEPTION


def test_default_rule_when_nothing_matches(psl):
    """没有规则命中 → 默认规则：顶层标签本身即公共后缀。"""
    info = psl.analyze("a.b.example.zzz")
    assert info.public_suffix == "zzz"
    assert info.organizational_domain == "example.zzz"
    assert info.rule.kind == psl_module.RULE_DEFAULT


def test_domain_that_is_itself_a_public_suffix_has_no_org_domain(psl):
    """"com" 本身没有注册域这一层——必须回 None，不能编造一个。"""
    assert psl.organizational_domain("com") is None
    assert psl.organizational_domain("co.uk") is None


def test_private_section_can_be_excluded():
    """`blogspot.com` 在 PRIVATE 段：默认包含，显式排除后按默认规则切。"""
    assert psl_module.PSL  # 存在性
    # 用同一份规则重建，验证 include_private 开关
    import hashlib

    dat_text = RULES
    rules, exceptions = psl_module._parse_rules(dat_text)
    view = psl_module.PSL(rules, exceptions, {
        "version": "t", "date": "d", "source_url": "u",
        "sha256": hashlib.sha256(dat_text.encode()).hexdigest(),
    }, source="<memory>")

    with_private = view.analyze("a.blogspot.com")
    assert with_private.public_suffix == "blogspot.com"
    assert with_private.organizational_domain == "a.blogspot.com"

    icann_only = view.analyze("a.blogspot.com", include_private=False)
    assert icann_only.public_suffix == "com"
    assert icann_only.organizational_domain == "blogspot.com"


def test_matching_is_case_and_trailing_dot_insensitive(psl):
    assert psl.organizational_domain("WWW.Example.CO.UK.") == "example.co.uk"


def test_empty_domain_is_input_error(psl):
    with pytest.raises(InputError):
        psl.analyze("")


def test_rule_order_does_not_matter(tmp_path):
    """确定性要求：结果只由"最长匹配"决定，与文件里规则行的顺序无关。"""
    forward = _write_psl(tmp_path / "forward")
    reversed_text = "\n".join(reversed(RULES.split("\n")))
    backward = _write_psl(tmp_path / "backward", rules=reversed_text)

    left = psl_module.load_psl(*forward)
    right = psl_module.load_psl(*backward)
    for domain in ("www.example.co.uk", "www.foo.kawasaki.jp", "www.city.kawasaki.jp",
                   "a.b.example.zzz", "www.ck"):
        assert left.organizational_domain(domain) == right.organizational_domain(domain)


# ── 冻结件校验 ─────────────────────────────────────────────────────────


def test_sha_mismatch_is_input_error(tmp_path):
    """冻结件被归一化/误改时必须当场报错，而不是悄悄给出不同切分。"""
    dat, meta = _write_psl(tmp_path, sha="0" * 64)
    with pytest.raises(InputError) as exc:
        psl_module.load_psl(dat, meta)
    assert "sha256 不匹配" in str(exc.value)


@pytest.mark.parametrize("field", ["version", "date", "source_url", "sha256"])
def test_meta_required_fields(tmp_path, field):
    dat, meta = _write_psl(tmp_path, meta_overrides={field: ""})
    with pytest.raises(InputError) as exc:
        psl_module.load_psl(dat, meta)
    assert field in str(exc.value)


def test_missing_dat_is_input_error(tmp_path):
    _dat, meta = _write_psl(tmp_path)
    with pytest.raises(InputError) as exc:
        psl_module.load_psl(tmp_path / "absent.dat", meta)
    assert "不存在" in str(exc.value)


# ── 随包冻结件（真 PSL） ───────────────────────────────────────────────


def test_bundled_psl_loads_and_verifies():
    view = psl_module.default_psl()
    assert view.version
    assert view.date
    assert view.rule_count > 1000  # 真 PSL 有上万条规则，这里只做量级下限


def test_bundled_psl_version_block_always_has_both_keys():
    """题面 §2.5 灰区 3：输出必须带 PSL 版本与日期——这是结构断言。"""
    block = psl_module.default_psl().version_block()
    assert set(block) == {"psl_version", "psl_date"}
    assert all(isinstance(value, str) and value for value in block.values())


@pytest.mark.parametrize("domain,expected", [
    ("www.example.co.uk", "example.co.uk"),
    ("mail.example.com", "example.com"),
    ("a.b.c.example.org", "example.org"),
])
def test_bundled_psl_stable_org_domains(domain, expected):
    """这几条属于 PSL 的长期稳定面，不随版本漂移。"""
    assert psl_module.default_psl().organizational_domain(domain) == expected


def test_bundled_psl_meta_has_provenance():
    meta = psl_module.default_psl().meta
    assert meta["source_url"].startswith("https://publicsuffix.org/")
    assert len(meta["sha256"]) == 64
