#!/usr/bin/env python3
"""生成 `fixtures/dmarc/` 的 tree-walk 样本与期望值（**开发期工具，不进运行时**）。

为什么需要生成器而不是手搓：

1. **B.4.1–B.4.3 的逐跳查询清单是 RFC 原文给定的**，但"每跳分别答复什么"要落到具体
   快照里。手写 6 份 `snap.json` 时，"漏一条查询"会静默变成数据缺口（``not_queried``），
   而数据缺口恰好会让判定变 ``undecidable``——看上去"实现保守"，实际是夹具写漏了。
   生成器把"逐条钉死"变成机械动作。
2. **DKIM 侧的对齐必须由真实签名驱动**。手写一条 `DKIM-Signature` 头只会让 DKIM 判
   fail，于是"DKIM 与 Author 对齐"这条路径永远走不到——fixture 会静默只覆盖 SPF 侧。
   本生成器复用 :mod:`tools.gen_dkim_fixtures` 的签名器（`cryptography`，仅开发期），
   用**仓库内同一把私钥**签出真实可验的签名，`d=` 落在需要的域上。
3. 幂等性（`plan/04` §2.5）：`--check` 重生成后逐字节比对已入仓文件。

样本集（6 个）：

| 目录 | 形态 | 依据 |
|---|---|---|
| `b41` | Appendix B.4.1 简单示例（SPF 与 DKIM 都 relaxed 对齐 → pass） | 逐跳 |
| `b42` | Appendix B.4.2 深树走（13 标签 → 8 次查询） | 逐跳 |
| `b43` | Appendix B.4.3 `psd=y` 示例（DKIM 不对齐） | 逐跳 |
| `psd-n` | `psd=n` 让子域自成 Organizational Domain | 归属 |
| `np` | 子域不存在 → 用 `np=`（与 `sp=` 不同值） | 归属 |
| `pct` | 旧标签 `pct=` / `rf=` / `ri=` 必须告警 | 告警 |

**域映射**：RFC 原文 B.4.3 用 `giant.bank.example`（`example` 是保留 TLD）。
卫生门白名单只认 `example.com` / `.net` / `.org` / `.invalid` 及其子域，
所以示例域落到 `.example.com` 下（`giant.bank.example` → `giant.bank.example.com`），
每个 `expected.json` 的 `why` 里写明映射关系。**不放宽卫生门**——每放宽一次，
"fixture 引用了真实域名"这条红线就少一道护栏。

用法：

    py -3.12 tools/gen_dmarc_fixtures.py            # 生成/覆盖
    py -3.12 tools/gen_dmarc_fixtures.py --check    # 只比对，不写盘；不一致 → 退出码 1

退出码：0 成功 / 1 `--check` 不一致 / 2 缺 `cryptography`。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURE_DIR = ROOT / "fixtures" / "dmarc"

#: 快照元数据统一口径（与 `fixtures/dkim/` 一致，便于跨模块比对）。
PSL_VERSION = "2026-10-20_08-40-56_UTC"
PSL_DATE = "2026-10-20"
FETCHED_AT = "2026-10-19T18:35:00Z"

#: 记录模板：全部落在保留域（K11）。
RUA = "rua=mailto:dmarc@example.com"
R_NONE = "v=DMARC1; p=none; " + RUA
R_REJECT = "v=DMARC1; p=reject; " + RUA
R_QUARANTINE = "v=DMARC1; p=quarantine; " + RUA

#: SPF 记录模板：`ip4` 段覆盖 `query.client_ip`（192.0.2.10）。
SPF_PASS = "v=spf1 ip4:192.0.2.0/24 -all"

#: 签名选择器（与 `fixtures/dkim` 的私钥对同一把钥匙，公钥记录见 :data:`_DKIM_KEY`）。
SELECTOR = "sel"


# ── 构造小工具 ──────────────────────────────────────────────────────────


def _q(qname: str, answer: list[str] | None = None, *, rcode: str = "NOERROR",
       qtype: str = "TXT") -> dict:
    return {
        "qname": qname,
        "qtype": qtype,
        "rcode": rcode,
        "answer": list(answer or []),
        "ttl": 300,
    }


def _nx(qname: str, *, qtype: str = "TXT") -> dict:
    return _q(qname, [], rcode="NXDOMAIN", qtype=qtype)


def _snap(queries: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "fetched_at": FETCHED_AT,
        "resolver": "synthetic",
        "psl_version": PSL_VERSION,
        "psl_date": PSL_DATE,
        "queries": queries,
    }


def _query(mail_from: str, helo: str = "mail.example.com") -> dict:
    return {
        "mail_from": mail_from,
        "client_ip": "192.0.2.10",
        "helo": helo,
        "trusted_authserv_ids": ["mx.example.com"],
    }


def _expected(case_id: str, expect: dict, why: str) -> dict:
    return {
        "case_id": case_id,
        "input": {"snapshot": "snap.json", "query": "query.json", "eml": "message.eml"},
        "expect": expect,
        "why": why,
    }


#: 报文正文（所有样本共用；签名覆盖它）。
BODY = b"Hello Bob,\r\n\r\nDMARC tree walk fixture body.\r\n"


def _headers(from_address: str) -> list[tuple[bytes, bytes]]:
    return [
        (b"From", b" <%s>" % from_address.encode("ascii")),
        (b"To", b" <bob@example.net>"),
        (b"Subject", b" dmarc tree walk fixture"),
        (b"Date", b" Thu, 1 Jan 2026 00:00:00 +0000"),
        (b"Message-ID", b" <dmarc-fixture@example.com>"),
    ]


def _signed_message(from_address: str, *, signing_domain: str | None,
                    keys: dict) -> bytes:
    """构造报文；给了 ``signing_domain`` 就插入一条**真实可验**的 DKIM 签名。

    签名覆盖 ``from:to:subject:date``（`h=` 含 ``from``，RFC 6376 §3.5 的 MUST）。
    """
    from gen_dkim_fixtures import _fold_value, _render, _sign

    headers = _headers(from_address)
    if signing_domain is None:
        return _render(headers, BODY)

    signature = _sign(
        headers=headers, body=BODY, private_key=keys["main"]["private"],
        selector=SELECTOR, domain=signing_domain,
        identity="@" + signing_domain,
        canon_header="relaxed", canon_body="relaxed",
        signed_names=["from", "to", "subject", "date"],
    )
    return _render(
        [headers[0], (b"DKIM-Signature", _fold_value(signature))] + headers[1:], BODY)


# ── 六个用例 ────────────────────────────────────────────────────────────


def build_cases() -> dict[str, dict]:
    """返回 ``case_id -> {message, snap, query, expected}``。

    ``expect`` 用**点路径 → 值**（`plan/04` §2.1）。点路径只出现在**键**位置，
    卫生门不扫键（K15），所以 `dmarc.spf_align.relaxed` 这类写法不会被误判成域名。
    """
    from gen_dkim_fixtures import _load_keys

    keys = _load_keys()
    cases: dict[str, dict] = {}

    # ══ b41：Appendix B.4.1 简单示例 ═════════════════════════════════
    # 原文：Author = example.com；MAIL FROM = example.com；
    #       DKIM 标识 = signing.example.com；
    #       `_dmarc.example.com` 与 `_dmarc.signing.example.com` 有记录，`_dmarc.com` 没有。
    #       → SPF 与 DKIM 都 relaxed 对齐 → pass。
    cases["b41"] = {
        "message": _signed_message("alice@example.com",
                                   signing_domain="signing.example.com", keys=keys),
        "snap": _snap([
            _q("_dmarc.example.com", [R_REJECT]),
            _q("_dmarc.signing.example.com", [R_QUARANTINE]),
            _nx("_dmarc.com"),
            _q("example.com", [SPF_PASS]),
            _q("example.com", ["192.0.2.10"], qtype="A"),
            _q("%s._domainkey.signing.example.com" % SELECTOR, [_DKIM_KEY]),
        ]),
        "query": _query("alice@example.com"),
        "expected": _expected(
            "dmarc-b41-simple",
            {
                "dmarc.result": "pass",
                "dmarc.author_domain": "example.com",
                "dmarc.organizational_domain": "example.com",
                "dmarc.walk_queries": 2,
                "dmarc.walk[0].qname": "_dmarc.example.com",
                "dmarc.walk[0].status": "record",
                "dmarc.walk[1].qname": "_dmarc.com",
                "dmarc.walk[1].status": "nxdomain",
                "dmarc.spf_align.relaxed": True,
                "dmarc.spf_align.strict": True,
                "dmarc.dkim_align.relaxed": True,
                "dmarc.dkim_align.strict": False,
                "dmarc.disposition": None,
                "dmarc.disposition_status": "not_applicable",
            },
            "RFC 9989 Appendix B.4.1：Author 与 MAIL FROM 同域 → SPF 两种模式都对齐；"
            "DKIM 标识是子域 signing.example.com，与 Author 同 Organizational Domain "
            "example.com（§4.10.2 步骤 3：取标签最少的那条记录）→ relaxed 对齐、strict 不对齐。"
            "§5.3.5：有对齐的 Authenticated Identifier → pass，处置 not_applicable。"
            "`_dmarc.com` 用 NXDOMAIN 表达原文的'没有记录'（§3.2.13 口径）",
        ),
    }

    # ══ b42：Appendix B.4.2 深树走 ══════════════════════════════════
    # 原文 Author = a.b.c.d.e.f.g.h.i.j.k.example.com（13 标签）。
    # 查询 8 次：_dmarc.<author> → g.h.i.j.k.example.com（跳步）→ h → i → j → k →
    #            example.com → com
    deep = "a.b.c.d.e.f.g.h.i.j.k.example.com"
    cases["b42"] = {
        "message": _signed_message("alice@" + deep,
                                   signing_domain="signing.example.com", keys=keys),
        "snap": _snap([
            _nx("_dmarc." + deep),
            _nx("_dmarc.g.h.i.j.k.example.com"),
            _nx("_dmarc.h.i.j.k.example.com"),
            _nx("_dmarc.i.j.k.example.com"),
            _nx("_dmarc.j.k.example.com"),
            _nx("_dmarc.k.example.com"),
            _q("_dmarc.example.com", [R_REJECT]),
            _nx("_dmarc.com"),
            _q("_dmarc.signing.example.com", [R_QUARANTINE]),
            _q("example.com", [SPF_PASS]),
            _q("%s._domainkey.signing.example.com" % SELECTOR, [_DKIM_KEY]),
            _q(deep, ["192.0.2.10"], qtype="A"),
        ]),
        "query": _query("alice@example.com"),
        "expected": _expected(
            "dmarc-b42-deep",
            {
                "dmarc.result": "pass",
                "dmarc.author_domain": deep,
                "dmarc.organizational_domain": "example.com",
                "dmarc.walk_queries": 8,
                "dmarc.walk[0].qname": "_dmarc." + deep,
                "dmarc.walk[0].status": "nxdomain",
                "dmarc.walk[1].qname": "_dmarc.g.h.i.j.k.example.com",
                "dmarc.walk[1].status": "nxdomain",
                "dmarc.walk[6].qname": "_dmarc.example.com",
                "dmarc.walk[6].status": "record",
                "dmarc.walk[7].qname": "_dmarc.com",
                "dmarc.walk[7].status": "nxdomain",
                "dmarc.spf_align.relaxed": True,
                "dmarc.dkim_align.relaxed": True,
            },
            "RFC 9989 Appendix B.4.2。**关键在逐跳**：Author 有 13 个标签（≥8），"
            "§4.10 步骤 4 要求一次删到只剩 7 个，于是第 2 跳直接跳到 "
            "g.h.i.j.k.example.com——中间的 h/i/j 层在**前两跳**里根本不查。"
            "此后逐级删一个标签，到 _dmarc.com 共 8 次查询（§4.10 的反滥用上限）。"
            "**反自证**：若实现漏了跳步，第 2 跳会是 h.i.j.k.example.com 且总查询数 >8，"
            "本用例的 walk[1] 与 walk_queries 两条断言会同时变红",
        ),
    }

    # ══ b43：Appendix B.4.3 psd=y 示例 ══════════════════════════════
    # 原文 Author = giant.bank.example；`_dmarc.bank.example` 带 psd=y；
    #      `_dmarc.giant.bank.example` 有记录但**没有** psd 标签；
    #      `_dmarc.example` 没有记录。
    #      → Author 的 Organizational Domain = giant.bank.example（psd=y 的下一层）
    author43 = "giant.bank.example.com"
    psd_record = "v=DMARC1; p=reject; psd=y; rua=mailto:dmarc@bank.example.com"
    cases["b43"] = {
        "message": _signed_message(
            "alice@" + author43,
            signing_domain="mail.mega.bank.example.com", keys=keys),
        "snap": _snap([
            _q("_dmarc." + author43, [R_QUARANTINE]),
            _q("_dmarc.bank.example.com", [psd_record]),
            _nx("_dmarc.example.com"),
            _q(author43, [SPF_PASS]),
            _q(author43, ["192.0.2.10"], qtype="A"),
            _nx("_dmarc.mail.mega.bank.example.com"),
            _nx("_dmarc.mega.bank.example.com"),
            _q("%s._domainkey.mail.mega.bank.example.com" % SELECTOR, [_DKIM_KEY]),
        ]),
        "query": _query("alice@" + author43),
        "expected": _expected(
            "dmarc-b43-psd",
            {
                "dmarc.result": "pass",
                "dmarc.author_domain": author43,
                "dmarc.organizational_domain": author43,
                "dmarc.policy_source": "author",
                "dmarc.psd": "u",
                "dmarc.walk_queries": 2,
                "dmarc.walk[1].qname": "_dmarc.bank.example.com",
                "dmarc.walk[1].psd": "y",
                "dmarc.spf_align.relaxed": True,
                "dmarc.dkim_align.relaxed": False,
                "dmarc.dkim_align.strict": False,
            },
            "RFC 9989 Appendix B.4.3 的映射形态（原文的示例域用裸保留 TLD `example`，"
            "卫生门只认 example.com/.net/.org 及其子域，故整体落到 .example.com 下）。"
            "Author 自己有记录且无 psd 标签 "
            "→ psd=u，第一跳不因 psd 停；第二跳在 bank.example.com 命中 psd=y → 走查停。"
            "**§4.10.2 步骤 2**：Organizational Domain 是 psd=y 记录**下面一层**，"
            "所以 Author 的 Organizational Domain 就是它自己。DKIM 标识 "
            "mail.mega.bank.example.com 的 Organizational Domain 是 mega.bank.example.com"
            "（同样是 psd=y 的下一层），与 Author 不同 → relaxed **也不**对齐；"
            "SPF 与 Author 同域 → 对齐 → pass。"
            "**反自证**：若实现把 psd=y 记录本身的域当成 Organizational Domain，"
            "Author 的 org 会变成 bank.example.com，与 DKIM 侧相同 → dkim_align.relaxed "
            "会错成 true，本用例会红",
        ),
    }

    # ══ psd-n：`psd=n` 让子域自成 Organizational Domain ═════════════
    cases["psd-n"] = {
        "message": _signed_message("alice@dept.mail.example.com",
                                   signing_domain=None, keys=keys),
        "snap": _snap([
            _nx("_dmarc.dept.mail.example.com"),
            _q("_dmarc.mail.example.com",
               ["v=DMARC1; p=reject; psd=n; rua=mailto:dmarc@mail.example.com"]),
            _q("_dmarc.example.com", [R_NONE]),
            _q("dept.mail.example.com", [SPF_PASS]),
            _q("dept.mail.example.com", ["192.0.2.10"], qtype="A"),
        ]),
        "query": _query("alice@dept.mail.example.com"),
        "expected": _expected(
            "dmarc-psd-n",
            {
                "dmarc.result": "pass",
                "dmarc.author_domain": "dept.mail.example.com",
                "dmarc.organizational_domain": "mail.example.com",
                "dmarc.policy_source": "organizational",
                "dmarc.psd": "n",
                "dmarc.walk_queries": 2,
                "dmarc.walk[1].qname": "_dmarc.mail.example.com",
                "dmarc.walk[1].status": "record",
                "dmarc.walk[1].psd": "n",
                "dmarc.spf_align.relaxed": True,
            },
            "RFC 9989 §4.10.2 步骤 1：带 `psd=n` 的记录所在一跳即 Organizational Domain，"
            "选择过程就地结束（不再往上看）。所以 dept.mail.example.com 的 Organizational "
            "Domain 是 mail.example.com，**不是** example.com——即使 example.com 也有记录、"
            "标签更少。走查在 mail.example.com 因 psd=n 停下，故只查了 2 跳。"
            "SPF 与 Author 同域 → pass。题面 M3 验收 3 的 `psd` 独立样本",
        ),
    }

    # ══ np：子域不存在 → `np=`（与 `sp=` 不同值） ═══════════════════
    cases["np"] = {
        "message": _signed_message("alice@nosuch.example.com",
                                   signing_domain=None, keys=keys),
        "snap": _snap([
            _nx("_dmarc.nosuch.example.com"),
            _q("_dmarc.example.com",
               ["v=DMARC1; p=none; sp=reject; np=quarantine; " + RUA]),
            _nx("_dmarc.com"),
            # §3.2.13：Author 域存在与否以**该名字**的查询答复为准。
            _nx("nosuch.example.com", qtype="A"),
            # SPF：MAIL FROM 换个域且 SPF pass，但与 Author 不对齐 → 判 fail
            _q("bounce.example.net", [SPF_PASS]),
            _nx("_dmarc.bounce.example.net"),
            _nx("_dmarc.example.net"),
        ]),
        "query": _query("bounce@bounce.example.net"),
        "expected": _expected(
            "dmarc-np-nonexistent",
            {
                "dmarc.result": "fail",
                "dmarc.author_domain": "nosuch.example.com",
                "dmarc.organizational_domain": "example.com",
                "dmarc.policy_source": "organizational",
                "dmarc.policy_tag": "np",
                "dmarc.policy_value": "quarantine",
                "dmarc.disposition": "quarantine",
                "dmarc.disposition_status": "determined",
                "dmarc.spf_align.relaxed": False,
                "dmarc.dkim_align.relaxed": False,
                "dmarc.walk_queries": 3,
            },
            "RFC 9989 §4.10.1：Author 域**不存在**（快照对该名字的 A 查询答复 NXDOMAIN，"
            "§3.2.13 的口径）时用 `np=`，存在时用 `sp=`。本样本刻意让 "
            "sp=reject / np=quarantine **不同**——若两者相同，'用错了哪个标签'看不出来。"
            "SPF 虽 pass 但 MAIL FROM 是 bounce.example.net、与 Author 不对齐 → fail。"
            "题面 M3 验收 3 的 `np` 独立样本",
        ),
    }

    # ══ pct：旧标签告警（题面 M3 验收 2） ═══════════════════════════
    cases["pct"] = {
        "message": _signed_message("alice@example.com",
                                   signing_domain=None, keys=keys),
        "snap": _snap([
            _q("_dmarc.example.com",
               ["v=DMARC1; p=reject; pct=25; rf=afrf; ri=86400; " + RUA]),
            _nx("_dmarc.com"),
            _q("example.com", ["192.0.2.10"], qtype="A"),
            _q("other.example.net", [SPF_PASS]),
            _nx("_dmarc.other.example.net"),
            _nx("_dmarc.example.net"),
        ]),
        "query": _query("alice@other.example.net"),
        "expected": _expected(
            "dmarc-removed-tags",
            {
                "dmarc.result": "fail",
                "dmarc.policy_tag": "p",
                "dmarc.policy_value": "reject",
                "dmarc.disposition": "reject",
                "dmarc.disposition_status": "determined",
                "dmarc.warning_contains.pct": "已被 RFC 9989 删除",
                "dmarc.warning_contains.rf": "已被 RFC 9989 删除",
                "dmarc.warning_contains.ri": "已被 RFC 9989 删除",
            },
            "RFC 9989 Appendix C.5.2 把 pct / rf / ri 列为已删除标签（pct 另见 A.6）。"
            "题面 M3 验收 2 要求 pct= 出现即告警、不得静默忽略。"
            "pct=25 的语义本工具**不解释**：按完整策略 reject 施加，同时在 warnings 里"
            "明写'已删除、不按百分比处理'——这样读者不会以为 pct=25 被尊重了。"
            "三个标签各出一条告警，逐条断言",
        ),
    }

    return cases


#: DKIM 公钥（与 `fixtures/dkim/keys/rsa2048-main.pem` 同一把，SPKI 编码）。
#: 内联而不在运行时读 PEM：本生成器要能只靠仓库内文件跑起来，
#: `--check` 的字节比对也不该依赖另一组 fixture 的解析结果。
_DKIM_KEY = (
    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtlnGVHmaUMrAxi1MBxSz"
    "largS6j0csjMH6OYGeRvxXHalWixI5PTP7D9SqoiSSZR/zsedLiNymPO9OSkvjsdkq881tFdh6qVhQU0rQERAF8"
    "jHuJnIU+GP/cgzSK9RRJbRlqbNMx6yBQ0j4/klZe0Ui7QUaul+la0iI+bjyJ2UXVrKspgcYPNZeHt4MCOJ2XyBq"
    "CA3CE9k6knEsnepY+jmHCI5JCOFT/3h0fO6rF4eX26uYtSAuDUq+y953wP/lWyxnvzFIY+gvV5j7Kirb+EZuH2w"
    "ymOQour+1yWmuWB49xIty+2skbTZgsecM9VieOhOPfivds+EdwG1qosVa7yTwIDAQAB"
)


# ── 落盘 ────────────────────────────────────────────────────────────────


def _json(obj: dict) -> bytes:
    from mailvault import canonical

    return (canonical.dumps_pretty(obj) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="生成 fixtures/dmarc 样本")
    parser.add_argument("--check", action="store_true",
                        help="只比对已入仓文件，不写盘（plan/04 §2.5 的幂等检查）")
    args = parser.parse_args(argv)

    try:
        import cryptography
    except ImportError:
        print("FAIL  需要开发期依赖 cryptography（签名用；不进运行时）")
        return 2
    del cryptography  # 只探可用性

    cases = build_cases()
    mismatches: list[str] = []
    written = 0
    for case_id in sorted(cases):
        case = cases[case_id]
        directory = FIXTURE_DIR / case_id
        artifacts = {
            "message.eml": case["message"],
            "snap.json": _json(case["snap"]),
            "query.json": _json(case["query"]),
            "expected.json": _json(case["expected"]),
        }
        for name, payload in artifacts.items():
            target = directory / name
            if args.check:
                if not target.is_file():
                    mismatches.append("%s/%s 缺失" % (case_id, name))
                elif target.read_bytes() != payload:
                    mismatches.append("%s/%s 字节不一致" % (case_id, name))
            else:
                directory.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
                written += 1

    print("DMARC fixture 生成器 · %d 个用例" % len(cases))
    print("=" * 60)
    for case_id in sorted(cases):
        print("  %s" % case_id)
    print("=" * 60)
    if args.check:
        if mismatches:
            for item in mismatches:
                print("FAIL  %s" % item)
            print("结论: %d 处不一致（生成器不幂等）" % len(mismatches))
            return 1
        print("PASS  %d 个用例 × 4 份产物逐字节一致" % len(cases))
        return 0
    print("已写入 %d 份文件" % written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
