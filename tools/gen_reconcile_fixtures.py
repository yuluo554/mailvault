#!/usr/bin/env python3
"""生成 `fixtures/reconcile/` 的三个对账样本与期望值（**开发期工具，不进运行时**）。

三个样本对应题面 §3 的 M4 验收三条，各证一侧：

| 目录 | 形态 | 期望 |
|---|---|---|
| `r1-forwarded` | 报文头声称 `spf=fail`、`dkim=pass`；本工具重算也是 SPF fail + DKIM pass | `consistent`（**一致**也要有样本：只测矛盾会放过一个"永远判矛盾"的实现） |
| `r2-gateway-body` | 报文头声称 `dkim=pass`；网关改过正文 → 本工具重算 DKIM fail（`bh` 不符） | `contradiction`，≥2 解释 |
| `r3-untrusted-ar` | 报文带一张 `Authentication-Results`，但 authserv-id 不在可信列表里 | `undecidable`（fail-closed） |

为什么需要生成器：

1. **R2 的 DKIM 侧必须是真实签名**。手写一条 `DKIM-Signature` 只会让 DKIM 判
   `header_syntax`/验签失败，"`bh` 不匹配"这条特定路径（网关改正文）根本走不到。
   本生成器复用 :mod:`tools.gen_dkim_fixtures` 的签名器（`cryptography`，仅开发期）：
   先对**原始正文**签一条真签名，再把正文改成网关改写后的样子——于是失败点精确地
   落在 `bh`（正文哈希）上，而不是头部哈希。
2. **`Authentication-Results` 头必须与重算结果逐条钉死**（声称 pass 还是 fail、
   authserv-id 写谁）。生成器把"头里写什么"与"期望分类"放在同一处，改一处不会漏另一处。
3. 幂等性（`plan/04` §2.5）：`--check` 重生成后逐字节比对已入仓文件。

**域映射**：全部落在保留域 `example.com` / `example.net` / `example.org`（K11）。

用法：

    py -3.12 tools/gen_reconcile_fixtures.py            # 生成/覆盖
    py -3.12 tools/gen_reconcile_fixtures.py --check    # 只比对，不写盘；不一致 → 退出码 1

退出码：0 成功 / 1 `--check` 不一致 / 2 缺 `cryptography`。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

FIXTURE_DIR = ROOT / "fixtures" / "reconcile"

#: 快照元数据统一口径（与 `fixtures/dkim` / `fixtures/dmarc` 一致）。
PSL_VERSION = "2026-10-20_08-40-56_UTC"
PSL_DATE = "2026-10-20"
FETCHED_AT = "2026-10-19T18:35:00Z"

SELECTOR = "selrec"

#: 被评估的域与来源 IP（全部保留域 / 文档 IP 段）。
AUTHOR = "example.com"
MAILING_LIST = "list.example.org"
RELAY = "relay.example.org"
GATEWAY = "gateway.example.net"
TRUSTED_MX = "mx.example.com"

#: 报文正文：签名覆盖**原始**版本；R2 里把正文改成 `GATEWAY_BODY` 造成 `bh` 不符。
ORIGINAL_BODY = (
    b"Hello Bob,\r\n"
    b"\r\n"
    b"Please see the attached quarterly report.\r\n"
    b"\r\n"
    b"Regards,\r\n"
    b"Alice\r\n"
)
GATEWAY_BODY = (
    b"Hello Bob,\r\n"
    b"\r\n"
    b"Please see the attached quarterly report.\r\n"
    b"\r\n"
    b"Regards,\r\n"
    b"Alice\r\n"
    b"\r\n"
    b"[external gateway notice: links rewritten]\r\n"
)

FROM_HEADER = b" Alice <alice@example.com>"
TO_HEADER = b" Bob <bob@example.net>"
SUBJECT_HEADER = b" quarterly report"
DATE_HEADER = b" Thu, 1 Jan 2026 00:00:00 +0000"
MESSAGE_ID = b" <reconcile-fixture@example.com>"

#: DKIM 公钥（与 `fixtures/dkim/keys/rsa2048-main.pem` 同一把，SPKI 编码）。
#: 内联的理由与 `gen_dmarc_fixtures.py` 相同：`--check` 的字节比对不该依赖另一组 fixture。
_DKIM_KEY = (
    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtlnGVHmaUMrAxi1MBxSz"
    "largS6j0csjMH6OYGeRvxXHalWixI5PTP7D9SqoiSSZR/zsedLiNymPO9OSkvjsdkq881tFdh6qVhQU0rQERAF8"
    "jHuJnIU+GP/cgzSK9RRJbRlqbNMx6yBQ0j4/klZe0Ui7QUaul+la0iI+bjyJ2UXVrKspgcYPNZeHt4MCOJ2XyBq"
    "CA3CE9k6knEsnepY+jmHCI5JCOFT/3h0fO6rF4eX26uYtSAuDUq+y953wP/lWyxnvzFIY+gvV5j7Kirb+EZuH2w"
    "ymOQour+1yWmuWB49xIty+2skbTZgsecM9VieOhOPfivds+EdwG1qosVa7yTwIDAQAB"
)

#: 收件方**当时**验签的那把密钥选择器（与签名里的 s= 一致）。
KEY_RECORD = "%s._domainkey.%s" % (SELECTOR, AUTHOR)


def _headers(*, received: list[bytes]) -> list[tuple[bytes, bytes]]:
    return (
        [(b"Received", value) for value in received]
        + [(b"From", FROM_HEADER), (b"To", TO_HEADER), (b"Subject", SUBJECT_HEADER),
           (b"Date", DATE_HEADER), (b"Message-ID", MESSAGE_ID)]
    )


def _message(*, auth_results: bytes | None, signature: bytes | None,
             received: list[bytes], body: bytes) -> bytes:
    """按"顶层 = 最新"的物理顺序拼报文。

    顺序照真实报文的形态：``Authentication-Results``（收件 MTA 写的，最靠上）
    → ``DKIM-Signature`` → ``Received``（前插，最新在前）→ 原始头。

    签名覆盖 ``from:to:subject:date``（`h=` 含 ``from``，RFC 6376 §3.5 的 MUST），
    这三个头在报文里的**相对顺序**与签名时一致——顺序改了签名就验不过。
    """
    from gen_dkim_fixtures import _fold_value

    headers: list[tuple[bytes, bytes]] = []
    if auth_results is not None:
        headers.append((b"Authentication-Results", auth_results))
    if signature is not None:
        headers.append((b"DKIM-Signature", _fold_value(signature)))
    headers.extend((b"Received", value) for value in received)
    headers.extend([
        (b"From", FROM_HEADER), (b"To", TO_HEADER), (b"Subject", SUBJECT_HEADER),
        (b"Date", DATE_HEADER), (b"Message-ID", MESSAGE_ID),
    ])
    return _render(headers, body)


def _q(qname: str, answer: list[str] | None = None, *, rcode: str = "NOERROR",
       qtype: str = "TXT") -> dict:
    return {"qname": qname, "qtype": qtype, "rcode": rcode,
            "answer": list(answer or []), "ttl": 300}


def _snap(queries: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "fetched_at": FETCHED_AT,
        "resolver": "synthetic",
        "psl_version": PSL_VERSION,
        "psl_date": PSL_DATE,
        "queries": queries,
    }


def _query(mail_from: str, *, trusted: list[str] | None = None) -> dict:
    return {
        "mail_from": mail_from,
        "client_ip": "192.0.2.10",
        "helo": "mail.%s" % AUTHOR,
        "trusted_authserv_ids": list(trusted if trusted is not None else [TRUSTED_MX]),
    }


def _expected(case_id: str, expect: dict, why: str) -> dict:
    return {
        "case_id": case_id,
        "input": {"snapshot": "snap.json", "query": "query.json", "eml": "message.eml"},
        "expect": expect,
        "why": why,
    }


def _render(headers: list[tuple[bytes, bytes]], body: bytes) -> bytes:
    from gen_dkim_fixtures import _render as render

    return render(headers, body)


def build_cases() -> dict[str, dict]:
    """返回 ``case_id -> {message, snap, query, expected}``。"""
    from gen_dkim_fixtures import _fold_value, _load_keys, _render, _sign

    keys = _load_keys()
    cases: dict[str, dict] = {}

    # ══ R1：转发导致 SPF fail，DKIM 仍然过 —— 一致（不是矛盾）══════
    # 列表转发器用 SRS 改写信封发件人为 list.example.org 下的地址，
    # 于是本工具的 SPF 用 MAIL FROM 域（list.example.org）查 → 该域无 SPF 记录 → fail；
    # DKIM 的签名域是 example.com，签名未被改动 → pass。
    # 报文头里收件 MTA 也如实写了 spf=fail / dkim=pass → **一致**。
    #
    # 这条样本存在的意义：**只测矛盾**会放过一个"永远判 contradiction"的实现。
    r1_signature = _sign(
        headers=_headers(received=[]), body=ORIGINAL_BODY,
        private_key=keys["main"]["private"],
        selector=SELECTOR, domain=AUTHOR, identity="@" + AUTHOR,
        canon_header="relaxed", canon_body="relaxed",
        signed_names=["from", "to", "subject", "date"],
    )
    r1_message = _message(
        auth_results=(
            b" mx.example.com;\r\n\tspf=fail smtp.mailfrom=alice@list.example.org;\r\n"
            b"\tdkim=pass header.d=example.com header.s=" + SELECTOR.encode("ascii")),
        signature=r1_signature,
        received=[
            b" from relay.example.org by mx.example.com with ESMTP id R1B; Thu, 1 Jan 2026 00:00:03 +0000",
            b" from list.example.org by relay.example.org with ESMTP id R1A; Thu, 1 Jan 2026 00:00:02 +0000",
            b" from mail.example.com by list.example.org with ESMTP id R1C; Thu, 1 Jan 2026 00:00:01 +0000",
        ],
        body=ORIGINAL_BODY,
    )

    cases["r1-forwarded"] = {
        "message": r1_message,
        "snap": _snap([
            _q("list.example.org", ["v=spf1 -all"]),
            _q("list.example.org", ["192.0.2.10"], qtype="A"),
            _q(KEY_RECORD, [_DKIM_KEY]),
            _q("_dmarc.example.com", ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]),
            _q("_dmarc.com", [], rcode="NXDOMAIN"),
            _q("_dmarc.list.example.org", [], rcode="NXDOMAIN"),
            _q("_dmarc.example.org", [], rcode="NXDOMAIN"),
            _q("_dmarc.example.net", [], rcode="NXDOMAIN"),
        ]),
        "query": _query("alice@list.example.org"),
        "expected": _expected(
            "reconcile-forwarded-01",
            {
                "reconcile.entries": 2,
                "reconcile.class[0]": "consistent",
                "reconcile.claimed[0].method": "spf",
                "reconcile.claimed[0].result": "fail",
                "reconcile.recomputed[0].result": "fail",
                "reconcile.class[1]": "consistent",
                "reconcile.claimed[1].method": "dkim",
                "reconcile.claimed[1].result": "pass",
                "reconcile.recomputed[1].result": "pass",
                "reconcile.received.hop_count": 3,
                "reconcile.received.monotonic": True,
                "recon.cross_check.result": "pass",
            },
            "题面 §3 的 M4 验收 ①：转发器导致 SPF fail 但 DKIM 过。"
            "列表转发器把信封发件人改写为 list.example.org 下的地址（SRS 形态），"
            "本工具的 SPF 按 §4.4.2『只认 MAIL FROM』用该域求值 → 该域 SPF 为 -all → fail；"
            "DKIM 的签名域仍是 example.com 且报文未改 → pass。"
            "报文头里收件 MTA 也如实写了 spf=fail / dkim=pass，所以两侧**一致**。"
            "这条样本专门证『一致』一侧：只测矛盾会放过一个永远判 contradiction 的实现。"
            "Received 三跳时间沿链递减 → monotonic=True（RFC 5321 §4.4 的接收顺序）",
        ),
    }

    # ══ R2：网关改正文导致 bh 不符 —— 矛盾（≥2 解释）══════════════
    # 签名是对**原始正文**做的；报文里的正文却是网关改写后的版本 → bh 不匹配。
    # 报文头声称 dkim=pass（那是网关验签时看到的，那时正文还没被改）→ **矛盾**。
    r2_signature = _sign(
        headers=_headers(received=[]), body=ORIGINAL_BODY,
        private_key=keys["main"]["private"],
        selector=SELECTOR, domain=AUTHOR, identity="@" + AUTHOR,
        canon_header="relaxed", canon_body="relaxed",
        signed_names=["from", "to", "subject", "date"],
    )
    r2_message = _message(
        auth_results=(
            b" mx.example.com;\r\n\tdkim=pass header.d=example.com header.s="
            + SELECTOR.encode("ascii")),
        signature=r2_signature,
        received=[
            b" from gateway.example.net by mx.example.com with ESMTP id R2B; Thu, 1 Jan 2026 00:00:03 +0000",
            b" from mail.example.com by gateway.example.net with ESMTP id R2A; Thu, 1 Jan 2026 00:00:01 +0000",
        ],
        body=GATEWAY_BODY,
    )

    cases["r2-gateway-body"] = {
        "message": r2_message,
        "snap": _snap([
            _q("example.com", ["v=spf1 ip4:192.0.2.0/24 -all"]),
            _q("example.com", ["192.0.2.10"], qtype="A"),
            _q(KEY_RECORD, [_DKIM_KEY]),
            _q("_dmarc.example.com", ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]),
            _q("_dmarc.com", [], rcode="NXDOMAIN"),
        ]),
        "query": _query("alice@example.com"),
        "expected": _expected(
            "reconcile-gateway-body-01",
            {
                "reconcile.entries": 1,
                "reconcile.class[0]": "contradiction",
                "reconcile.claimed[0].method": "dkim",
                "reconcile.claimed[0].result": "pass",
                "reconcile.recomputed[0].result": "fail",
                "reconcile.min_explanations_ge": 2,
                "reconcile.explanation[0][0].hypothesis_contains": "网关",
                "reconcile.explanation[0][0].verify_nonempty": True,
                "reconcile.explanation[0][1].verify_nonempty": True,
                "reconcile.dkim.failure_at_kind": "body_hash",
                "recon.cross_check.result": "undecidable",
            },
            "题面 §3 的 M4 验收 ②：网关重写正文导致 bh 不匹配。"
            "签名是对**原始正文**做的（`ORIGINAL_BODY`），报文里的正文却是网关改写后的版本"
            "（`GATEWAY_BODY`：尾部追加了一行网关声明）→ RFC 6376 §6.1.3 的 bh= 不匹配。"
            "报文头声称 dkim=pass——那是网关**验签时**看到的（那时正文还没被改），"
            "所以与本工具的重算结果**不一致** → contradiction。"
            "矛盾必须给 ≥2 条解释且每条带 verify（题面 M4 硬性要求）。"
            "汇总条目判 undecidable：矛盾不等于 fail——本工具不知道哪一侧描述的是现实",
        ),
    }

    # ══ R3：注入伪造 AR（authserv-id 不可信）—— 无法判定 ═════════════
    # 报文里带一张 Authentication-Results，authserv-id 写的是 relay.example.org，
    # 而 query.json 的 trusted_authserv_ids 只有 mx.example.com。
    # 不认识的 authserv-id → fail-closed 判 undecidable（authres_status #86 的教训）。
    r3_message = _message(
        auth_results=(
            b" relay.example.org;\r\n\tspf=pass smtp.mailfrom=alice@example.com;\r\n"
            b"\tdkim=pass header.d=example.com"),
        signature=None,
        received=[
            b" from relay.example.org by mx.example.com with ESMTP id R3A; Thu, 1 Jan 2026 00:00:01 +0000",
        ],
        body=ORIGINAL_BODY,
    )

    cases["r3-untrusted-ar"] = {
        "message": r3_message,
        "snap": _snap([
            _q("example.com", ["v=spf1 -all"]),
            _q("example.com", ["192.0.2.10"], qtype="A"),
            _q("_dmarc.example.com", ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]),
            _q("_dmarc.com", [], rcode="NXDOMAIN"),
        ]),
        "query": _query("alice@example.com"),
        "expected": _expected(
            "reconcile-untrusted-ar-01",
            {
                "reconcile.entries": 2,
                "reconcile.class[0]": "undecidable",
                "reconcile.claimed[0].authserv_id": "relay.example.org",
                "reconcile.trusted_authserv_ids": ["mx.example.com"],
                "reconcile.warning[0].contains": "fail-closed",
                "reconcile.class[1]": "undecidable",
                "recon.cross_check.result": "undecidable",
            },
            "题面 §3 的 M4 验收 ③：注入伪造 Authentication-Results。"
            "报文的 authserv-id 是 relay.example.org，而 query.json 只把 mx.example.com "
            "列为可信 MTA → authserv-id 不在可信列表里 → **fail-closed 判 undecidable**"
            "（authres_status #86 的教训：不可信/不可解析时 fail-**open** 会把他人写的头"
            "当成有效证据）。注意本样本的重算结果与头里写的**恰好一致**（都是 pass），"
            "但『一致』本身不构成证据——一张不可信的头说什么都不算数。"
            "trusted_authserv_ids 为空**不等于**全部可信：空列表时任何 AR 都判 undecidable",
        ),
    }

    return cases


# ── 落盘 ────────────────────────────────────────────────────────────────


def _json(obj: dict) -> bytes:
    from mailvault import canonical

    return (canonical.dumps_pretty(obj) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="生成 fixtures/reconcile 样本")
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

    print("reconcile fixture 生成器 · %d 个用例" % len(cases))
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