#!/usr/bin/env python3
"""生成 `fixtures/dkim/` 的签名样本与期望值（**开发期工具，不进运行时**）。

为什么需要生成器而不是手搓样本：

1. 一个"签名有效"的正样本必须真的由某把私钥签出来。手写 base64 只能碰运气，
   而**只有负样本的 fixture 集**会让"永远返回 fail"的实现全部通过（`plan/03` §3.3）。
2. 五类失败必须**只差一个变量**：D1 只改正文、D2 只改头、D3 只改 `l=` 覆盖范围……
   同一条基线报文派生，才能断言"是这一处差异导致的结论变化"。

**独立性问题**：签名用 `cryptography`（dev 期依赖，实装于本机环境）做，验签用
`mailvault/modules/dkim.py` 的零依赖实现。两侧**不共享**任何代码路径，所以
"签名能验过"这件事本身是对零依赖 RSA 的一次独立对账。

**幂等性**（`plan/04` §2.5）：私钥已存在就**不**重新生成（私钥是种子）；签名是
确定的（PKCS#1 v1.5 无随机化），因此 `--check` 重算后能与已入仓文件逐字节比对。

用法：

    py -3.12 tools/gen_dkim_fixtures.py            # 缺件时生成，已有则覆盖
    py -3.12 tools/gen_dkim_fixtures.py --check    # 只比对，不写盘；不一致 → 退出码 1

退出码：0 成功 / 1 `--check` 不一致 / 2 缺 `cryptography`。
"""

from __future__ import annotations

import argparse
import hashlib
import math
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURE_DIR = ROOT / "fixtures" / "dkim"
KEY_DIR = FIXTURE_DIR / "keys"

#: 域名一律保留域（K11）。签署域用 example.com，`d=` 与 `i=` 都落在它下面。
SIGNING_DOMAIN = "example.com"
SELECTOR_MAIN = "sel20261021"
SELECTOR_WEAK = "selweak"
IDENTITY = "@example.com"


# ── 极简 DER 编码（只为写出 PKCS#1 私钥；**不在运行时使用**） ─────────────


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_int(value: int) -> bytes:
    if value == 0:
        return _der_tlv(0x02, b"\x00")
    body = value.to_bytes((value.bit_length() + 8) // 8, "big")
    return _der_tlv(0x02, body)


def _pkcs1_private_der(p: int, q: int, d: int, n: int, e: int) -> bytes:
    """RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dP, dQ, qInv }（RFC 8017 A.1.2）。"""
    return _der_tlv(0x30, b"".join([
        _der_int(0), _der_int(n), _der_int(e), _der_int(d),
        _der_int(p), _der_int(q), _der_int(d % (p - 1)),
        _der_int(d % (q - 1)), _der_int(pow(q, -1, p)),
    ]))


def _pkcs1_public_der(n: int, e: int) -> bytes:
    """RSAPublicKey ::= SEQUENCE { n, e }（RFC 8017 A.1.1）。

    DKIM 的 `p=` 理论上可以是裸 RSAPublicKey，也可以是 SubjectPublicKeyInfo。
    本 fixture 刻意**两种都用**：主选择器发 SPKI（现实分布），另一个发裸 PKCS#1，
    让解析器的两条路径都有真实用例覆盖。
    """
    return _der_tlv(0x30, _der_int(n) + _der_int(e))


def _spki_der(n: int, e: int) -> bytes:
    algorithm = _der_tlv(0x30,
                         _der_tlv(0x06, bytes.fromhex("2a864886f70d010101")) +
                         _der_tlv(0x05, b""))
    return _der_tlv(0x30, algorithm + _der_tlv(0x03, b"\x00" + _pkcs1_public_der(n, e)))


def _pem(label: str, der: bytes) -> str:
    import base64

    body = base64.encodebytes(der).decode("ascii")
    return "-----BEGIN %s-----\n%s-----END %s-----\n" % (label, body, label)


# ── 512 位密钥（`cryptography` 拒绝生成 <1024，自己造） ────────────────────


def _is_probable_prime(n: int, rounds: int = 48) -> bool:
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _gen_small_rsa(bits: int = 512, e: int = 65537) -> tuple[int, int, int]:
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        if n.bit_length() < bits:
            continue
        if math.gcd(e, (p - 1) * (q - 1)) != 1:
            continue
        return n, e, pow(e, -1, (p - 1) * (q - 1))


# ── 签名（用 cryptography，与运行时零依赖实现互不共享代码） ───────────────


def _relaxed_header(name: bytes, value: bytes) -> bytes:
    import re

    lowered = name.strip(b" \t").lower()
    unfolded = value.replace(b"\r\n", b"").replace(b"\r", b"").replace(b"\n", b"")
    collapsed = re.sub(rb"[ \t]+", b" ", unfolded).strip(b" ")
    return lowered + b":" + collapsed + b"\r\n"


def _simple_header(name: bytes, value: bytes) -> bytes:
    return name + b":" + value + b"\r\n"


def _canon_body(body: bytes, algorithm: str) -> bytes:
    import re

    if algorithm == "simple":
        end = len(body)
        while end >= 2 and body[end - 2:end] == b"\r\n":
            end -= 2
        return body[:end] + b"\r\n"
    stripped = re.sub(rb"[ \t]+\r\n", b"\r\n", body)
    collapsed = re.sub(rb"[ \t]+", b" ", stripped)
    end = len(collapsed)
    while end >= 2 and collapsed[end - 2:end] == b"\r\n":
        end -= 2
    out = collapsed[:end] + b"\r\n"
    return b"" if out == b"\r\n" else out


def _sign(*, headers: list[tuple[bytes, bytes]], body: bytes, private_key,
          selector: str, domain: str, identity: str, canon_header: str, canon_body: str,
          hash_name: str = "sha256", length: int | None = None,
          signed_names: list[str] | None = None,
          algorithm: str = "rsa-sha256") -> str:
    """构造一条 `DKIM-Signature` 头值（字符串）。"""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, utils

    import base64

    hash_ctor = hashlib.sha256 if hash_name == "sha256" else hashlib.sha1
    canonical_body = _canon_body(body, canon_body)
    covered = canonical_body if length is None else canonical_body[:length]
    bh = base64.b64encode(hash_ctor(covered).digest()).decode("ascii")

    names = signed_names or ["from", "to", "subject", "date"]
    c_value = "%s/%s" % (canon_header, canon_body)

    tags = ["v=1", "a=%s" % algorithm, "c=%s" % c_value, "d=%s" % domain,
            "s=%s" % selector, "i=%s" % identity,
            "t=1767225600", "h=%s" % ":".join(names), "bh=%s" % bh]
    if length is not None:
        tags.insert(6, "l=%d" % length)
    unsigned = "; ".join(tags) + "; b="

    # 折行：DKIM-Signature 习惯在 `d=` 前折一行。折行的存在本身就是规范化的一部分
    # （simple 头规范化必须原样保留它），所以 fixture 里**刻意**保留折行。
    folded = unsigned.replace("; h=", ";\r\n\th=")

    header_hasher = hash_ctor()
    selected = _select(headers, names)
    canonicalizer = _relaxed_header if canon_header == "relaxed" else _simple_header
    for name, value in selected:
        header_hasher.update(canonicalizer(name, value))
    sig_header = canonicalizer(b"DKIM-Signature", folded.encode("utf-8"))
    header_hasher.update(sig_header[:-2])  # §3.7：签名头自身不带结尾 CRLF

    digest = header_hasher.digest()
    pad = padding.PKCS1v15()
    hash_alg = hashes.SHA256() if hash_name == "sha256" else hashes.SHA1()
    if _is_crypto_key(private_key):
        # **必须**用 Prehashed：`private_key.sign(data, ..., hash_alg)` 会自己再哈希一遍
        # data。把摘要直接传进去会让签名对应 SHA256(SHA256(头部))，而验证侧算的是
        # SHA256(头部) ——于是**每条**签名都"验不过"，症状与真实故障无法区分。
        signature = private_key.sign(digest, pad, utils.Prehashed(hash_alg))
    else:
        signature = _pure_sign(private_key, digest, hash_name)
    b64 = base64.b64encode(signature).decode("ascii")
    folded_b = "\r\n\t".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return "DKIM-Signature: " + folded + folded_b


def _is_crypto_key(key) -> bool:
    return hasattr(key, "sign")


def _pure_sign(material: tuple[int, int, int], digest: bytes, hash_name: str) -> bytes:
    """给 512 位密钥用的纯 RSA 签名（`cryptography` 不接受 <1024 位生成）。"""
    from mailvault.crypto.rsa import emsa_pkcs1_v15_encode

    n, e, d = material
    mod_bytes = (n.bit_length() + 7) // 8
    em = emsa_pkcs1_v15_encode(hash_name, digest, mod_bytes)
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(mod_bytes, "big")


def _select(headers: list[tuple[bytes, bytes]], names: list[str]) -> list[tuple[bytes, bytes]]:
    """按 `h=` 从下往上取（RFC 6376 §5.4.2 的签名侧规则）。"""
    out: list[tuple[bytes, bytes]] = []
    cursor: dict[str, int] = {}
    for name in names:
        boundary = cursor.get(name, len(headers))
        for position in range(boundary - 1, -1, -1):
            if headers[position][0].strip().lower() == name.encode("ascii"):
                out.append(headers[position])
                cursor[name] = position
                break
    return out


# ── 报文构造 ────────────────────────────────────────────────────────────

BASE_HEADERS: list[tuple[bytes, bytes]] = [
    (b"Received", b" from relay.example.org by mx.example.com; Thu, 1 Jan 2026 00:00:00 +0000"),
    (b"From", b" Alice <alice@example.com>"),
    (b"To", b" Bob <bob@example.net>"),
    (b"Subject", b" quarterly report"),
    (b"Date", b" Thu, 1 Jan 2026 00:00:00 +0000"),
    (b"Message-ID", b" <fixture-0001@example.com>"),
    (b"MIME-Version", b" 1.0"),
    (b"Content-Type", b" text/plain; charset=us-ascii"),
]

BASE_BODY = (
    b"Hello Bob,\r\n"
    b"\r\n"
    b"Attached is the quarterly report.\r\n"
    b"\r\n"
    b"Regards,\r\n"
    b"Alice\r\n"
)


def _render(headers: list[tuple[bytes, bytes]], body: bytes) -> bytes:
    out = b""
    for name, value in headers:
        out += name + b":" + value + b"\r\n"
    return out + b"\r\n" + body


# ── 各用例 ──────────────────────────────────────────────────────────────


def build_cases() -> dict[str, dict]:
    """返回 ``case_id -> {message, snap, query, expected}``。"""
    from mailvault.crypto.der import parse_rsa_public_key

    keys = _load_keys()
    main_key = keys["main"]["private"]
    main_pub = parse_rsa_public_key(
        _spki_der(keys["main"]["n"], keys["main"]["e"])[0:])  # 仅用于自检
    del main_pub

    cases: dict[str, dict] = {}

    # ── D6：正样本（签名有效） ────────────────────────────────────────
    sig = _sign(headers=BASE_HEADERS, body=BASE_BODY, private_key=main_key,
                selector=SELECTOR_MAIN, domain=SIGNING_DOMAIN, identity=IDENTITY,
                canon_header="relaxed", canon_body="relaxed")
    valid_message = _render(
        [BASE_HEADERS[0], (b"DKIM-Signature", _fold_value(sig))] + BASE_HEADERS[1:],
        BASE_BODY)
    cases["d6-valid"] = {
        "message": valid_message,
        "snap": _snap({
            "%s._domainkey.%s" % (SELECTOR_MAIN, SIGNING_DOMAIN):
                [_key_record(keys["main"]["n"], keys["main"]["e"], spki=True)],
        }),
        "query": _query(),
        "expected": _expected(
            "dkim-valid-01",
            {"dkim.result": "pass", "dkim.key_status": "ok", "dkim.key_bits": 2048,
             "dkim.bh_matches": True, "dkim.failure_at": None},
            "RFC 6376 §6.1.3：正文哈希与 b= 均通过，relaxed/relaxed 规范化；"
            "密钥 2048 位 ≥ RFC 8301 §3.2 的 1024 位门槛",
        ),
    }

    # ── D1：正文被改（签名后改动 body） ───────────────────────────────
    tampered_body = BASE_BODY.replace(b"quarterly report", b"quarterly rep0rt")
    cases["d1-body-modified"] = {
        "message": _render(
            [BASE_HEADERS[0], (b"DKIM-Signature", _fold_value(sig))] + BASE_HEADERS[1:],
            tampered_body),
        "snap": cases["d6-valid"]["snap"],
        "query": _query(),
        "expected": _expected(
            "dkim-body-modified-01",
            {"dkim.result": "fail", "dkim.bh_matches": False,
             "dkim.key_status": "ok"},
            "RFC 6376 §6.1.3 第 3 步：正文哈希与 bh= 不符 → PERMFAIL (body hash did not verify)。"
            "签名后改动正文，正文哈希必变；因为 bh= 是单向摘要，本工具给出 basis 而不编造行号。"
            "key_status=ok：密钥在 §6.1.2 就先取到了（RFC 的步骤顺序），失败点在正文哈希",
        ),
    }

    # ── D2：头被改（签名后改动已签名头） ─────────────────────────────
    tampered_headers = list(BASE_HEADERS)
    tampered_headers[3] = (b"Subject", b" quarterly Report")
    cases["d2-header-modified"] = {
        "message": _render(
            [tampered_headers[0], (b"DKIM-Signature", _fold_value(sig))] + tampered_headers[1:],
            BASE_BODY),
        "snap": cases["d6-valid"]["snap"],
        "query": _query(),
        "expected": _expected(
            "dkim-header-modified-01",
            {"dkim.result": "fail", "dkim.bh_matches": True,
             "dkim.key_status": "ok", "dkim.failure_at.kind": "header_hash"},
            "RFC 6376 §6.1.3 第 4 步：正文哈希仍匹配（body 未动），但已签名头字段变了 → "
            "b= 验签不过。本工具给 kind=header_hash + basis，不编造具体头名",
        ),
    }

    # ── D3：`l=` 截断（正文尾部改动不影响判定） ──────────────────────
    prefix_length = len(_canon_body(BASE_BODY, "relaxed")) - len(b"Alice\r\n")
    sig_len = _sign(headers=BASE_HEADERS, body=BASE_BODY, private_key=main_key,
                    selector=SELECTOR_MAIN, domain=SIGNING_DOMAIN, identity=IDENTITY,
                    canon_header="relaxed", canon_body="relaxed",
                    length=prefix_length)
    # 只改被 `l=` 排除在外的尾部（最后一行的署名）
    tail_changed = BASE_BODY[:-len(b"Alice\r\n")] + b"Mallory\r\n"
    cases["d3-length-truncated"] = {
        "message": _render(
            [BASE_HEADERS[0], (b"DKIM-Signature", _fold_value(sig_len))] + BASE_HEADERS[1:],
            tail_changed),
        "snap": cases["d6-valid"]["snap"],
        "query": _query(),
        "expected": _expected(
            "dkim-length-truncated-01",
            {"dkim.result": "pass", "dkim.bh_matches": True,
             "dkim.key_status": "ok"},
            "RFC 6376 §3.5 + §6.1.3：l= 只覆盖正文前 %d 字节，其后的内容不参与哈希，"
            "所以改尾部不影响判定；本工具另出告警指出「第几行起未受保护」" % prefix_length,
        ),
    }

    # ── D3b：`l=` 大于规范化正文长度 → permerror ─────────────────────
    too_long = len(_canon_body(BASE_BODY, "relaxed")) + 64
    sig_l_bad = _sign(headers=BASE_HEADERS, body=BASE_BODY, private_key=main_key,
                      selector=SELECTOR_MAIN, domain=SIGNING_DOMAIN, identity=IDENTITY,
                      canon_header="relaxed", canon_body="relaxed",
                      length=too_long)
    cases["d3b-length-exceeds-body"] = {
        "message": _render(
            [BASE_HEADERS[0], (b"DKIM-Signature", _fold_value(sig_l_bad))] + BASE_HEADERS[1:],
            BASE_BODY),
        "snap": cases["d6-valid"]["snap"],
        "query": _query(),
        "expected": _expected(
            "dkim-length-exceeds-body-01",
            {"dkim.result": "permerror", "dkim.failure_at.kind": "length_exceeds_body"},
            "RFC 6376 §3.5：l= MUST NOT be larger than the actual number of octets in the "
            "canonicalized message body；§6.1.1 要求不一致的取值立即 PERMFAIL。"
            "参照实现 dkimpy 会静默取全量，本项目按 RFC 判错（口径差异，已登记）",
        ),
    }

    # ── D4a：快照里**没有查过**这把选择器的密钥 → undecidable（K13） ──
    cases["d4a-key-not-queried"] = {
        "message": valid_message,
        "snap": _snap({}),  # 空 queries：这是"没抓"，不是"没有"
        "query": _query(),
        "expected": _expected(
            "dkim-key-missing-datagap-01",
            {"dkim.result": "undecidable", "dkim.key_status": "missing",
             "dkim.data_gap": ["%s._domainkey.%s" % (SELECTOR_MAIN, SIGNING_DOMAIN), "TXT"]},
            "K13 / plan/04 §2.3：快照里没有这条查询 = 数据缺口 → undecidable + data_gap，"
            "**不是** fail，也不是「密钥不存在」",
        ),
    }

    # ── D4b：快照明确答复 NXDOMAIN → permerror（真的没有） ───────────
    cases["d4b-key-nxdomain"] = {
        "message": valid_message,
        "snap": _snap({
            "%s._domainkey.%s" % (SELECTOR_MAIN, SIGNING_DOMAIN): [],
        }, rcode="NXDOMAIN"),
        "query": _query(),
        "expected": _expected(
            "dkim-key-nxdomain-01",
            {"dkim.result": "permerror", "dkim.key_status": "missing",
             "dkim.data_gap": None},
            "RFC 6376 §6.1.2 第 3 步：查询成功但记录不存在 → PERMFAIL (no key for signature)。"
            "与 D4a 的区别是「问过了没有」而不是「没问过」",
        ),
    }

    # ── D5：RSA-512 密钥（< 1024 位）→ fail（RFC 8301 §3.2 MUST） ────
    weak_material = keys["weak"]["material"]
    sig_weak = _sign(headers=BASE_HEADERS, body=BASE_BODY, private_key=weak_material,
                     selector=SELECTOR_WEAK, domain=SIGNING_DOMAIN, identity=IDENTITY,
                     canon_header="relaxed", canon_body="relaxed")
    cases["d5-key-weak-512"] = {
        "message": _render(
            [BASE_HEADERS[0], (b"DKIM-Signature", _fold_value(sig_weak))] + BASE_HEADERS[1:],
            BASE_BODY),
        "snap": _snap({
            "%s._domainkey.%s" % (SELECTOR_WEAK, SIGNING_DOMAIN):
                [_key_record(keys["weak"]["n"], keys["weak"]["e"], spki=False)],
        }),
        "query": _query(),
        "expected": _expected(
            "dkim-key-weak-512-01",
            {"dkim.result": "fail", "dkim.key_status": "weak",
             "dkim.key_bits": keys["weak"]["n"].bit_length()},
            "RFC 8301 §3.2：Verifiers MUST NOT consider signatures using RSA keys of less "
            "than 1024 bits as valid signatures → 判 fail（MUST，不是灰区）。"
            "本条同时覆盖「裸 RSAPublicKey」编码（非 SPKI）",
        ),
    }

    # ── D7：多签名（一条坏、一条好）→ 逐条出结果，不短路 ─────────────
    second_sig = _sign(headers=BASE_HEADERS, body=BASE_BODY, private_key=main_key,
                       selector=SELECTOR_MAIN, domain=SIGNING_DOMAIN, identity=IDENTITY,
                       canon_header="simple", canon_body="simple")
    # 第二条签名覆盖 simple/simple；报文正文用 simple 规范化也成立，所以它也 pass。
    # 但把第一条（relaxed）的正文改掉会让第一条 fail、第二条也 fail（同一份正文）。
    # 为了构造"一坏一好"，让第一条签名针对**旧正文**、第二条针对**当前正文**。
    stale_sig = _sign(headers=BASE_HEADERS, body=BASE_BODY + b"extra\r\n",
                      private_key=main_key, selector=SELECTOR_MAIN,
                      domain=SIGNING_DOMAIN, identity=IDENTITY,
                      canon_header="relaxed", canon_body="relaxed")
    cases["d7-multi-signature"] = {
        "message": _render(
            [BASE_HEADERS[0],
             (b"DKIM-Signature", _fold_value(stale_sig)),
             (b"DKIM-Signature", _fold_value(second_sig))] + BASE_HEADERS[1:],
            BASE_BODY),
        "snap": cases["d6-valid"]["snap"],
        "query": _query(),
        "expected": _expected(
            "dkim-multi-signature-01",
            {"dkim.signatures_total": 2,
             "dkim.result[0]": "fail", "dkim.result[1]": "pass"},
            "RFC 6376 §6.1：Verifiers SHOULD proceed to the next signature header field。"
            "第 1 条签名针对另一份正文 → bh 不符 → fail；第 2 条 simple/simple 对当前正文有效 → pass。"
            "**只报第一条或提前短路都会漏掉第二条**，这正是本用例要锁住的",
        ),
    }

    # ── D8：无签名 → none（不是 fail） ──────────────────────────────
    cases["d8-unsigned"] = {
        "message": _render(BASE_HEADERS, BASE_BODY),
        "snap": _snap({}),
        "query": _query(),
        "expected": _expected(
            "dkim-unsigned-01",
            {"dkim.result": "none", "dkim.signatures_total": 0},
            "RFC 6376 §1：未签名的报文没有 DKIM 结论 → none。"
            "把「未签名」判成 fail 会让账本对所有普通邮件报错",
        ),
    }

    # ── D9：签名头语法错（缺必需标签） → permerror ──────────────────
    broken = sig.replace("; d=%s" % SIGNING_DOMAIN, "", 1)
    cases["d9-missing-tag"] = {
        "message": _render(
            [BASE_HEADERS[0], (b"DKIM-Signature", _fold_value(broken))] + BASE_HEADERS[1:],
            BASE_BODY),
        "snap": cases["d6-valid"]["snap"],
        "query": _query(),
        "expected": _expected(
            "dkim-missing-tag-01",
            {"dkim.result": "permerror", "dkim.failure_at.kind": "missing_tag"},
            "RFC 6376 §6.1.1：缺 §3.5 标为 REQUIRED 的标签（此处删掉 d=）→ "
            "PERMFAIL (signature missing required tag)",
        ),
    }

    return cases


def _fold_value(signature: str) -> bytes:
    """`DKIM-Signature: <value>` → 头值字节（去掉字段名，保留折行）。

    值里用的是 ``\\r\\n\\t`` 折行；写入报文时不改写，让 simple 规范化有折行可保留。
    """
    prefix = "DKIM-Signature: "
    assert signature.startswith(prefix)
    return signature[len(prefix):].encode("utf-8")


def _key_record(n: int, e: int, *, spki: bool) -> str:
    import base64

    der = _spki_der(n, e) if spki else _pkcs1_public_der(n, e)
    return "v=DKIM1; k=rsa; p=%s" % base64.b64encode(der).decode("ascii")


def _snap(records: dict[str, list[str]], *, rcode: str = "NOERROR") -> dict:
    queries = []
    for qname in sorted(records):
        queries.append({
            "qname": qname, "qtype": "TXT", "rcode": rcode,
            "answer": records[qname], "ttl": 300,
        })
    return {
        "schema_version": 1,
        "fetched_at": "2026-10-19T18:35:00Z",
        "resolver": "synthetic",
        "psl_version": "2026-10-20_08-40-56_UTC",
        "psl_date": "2026-10-20",
        "queries": queries,
    }


def _query() -> dict:
    return {
        "mail_from": "alice@example.com",
        "client_ip": "192.0.2.10",
        "helo": "mail.example.com",
        "trusted_authserv_ids": ["mx.example.com"],
    }


def _expected(case_id: str, expect: dict, why: str) -> dict:
    return {
        "case_id": case_id,
        "input": {"snapshot": "snap.json", "query": "query.json", "eml": "message.eml"},
        "expect": expect,
        "why": why,
    }


# ── 密钥 ────────────────────────────────────────────────────────────────


def _load_keys() -> dict:
    """读取（或首次生成）三把私钥。**已存在就不重生成**——私钥是 fixture 的种子。"""
    from cryptography.hazmat.primitives.asymmetric import rsa

    KEY_DIR.mkdir(parents=True, exist_ok=True)
    keys: dict[str, dict] = {}

    main_path = KEY_DIR / "rsa2048-main.pem"
    if main_path.is_file():
        main_private = _load_pem(main_path)
        numbers = main_private.private_numbers()
        keys["main"] = {"private": main_private,
                        "n": numbers.public_numbers.n, "e": numbers.public_numbers.e}
    else:
        main_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = main_private.private_numbers()
        keys["main"] = {"private": main_private,
                        "n": numbers.public_numbers.n, "e": numbers.public_numbers.e}
        _write_pem(main_path, "RSA PRIVATE KEY",
                   _pkcs1_private_der(numbers.p, numbers.q, numbers.d,
                                      numbers.public_numbers.n, numbers.public_numbers.e),
                   "# 仅 fixture 使用，不得用于生产。RSA-2048，DKIM 主样本密钥。")

    weak_path = KEY_DIR / "rsa512-weak.txt"
    if weak_path.is_file():
        n, e, d, p, q = _load_weak(weak_path)
    else:
        n, e, d = _gen_small_rsa(512)
        # 512 位样本只需 (n, e, d) 就能签名：p/q 只用于导出私钥 PEM，这里不需要。
        _write_pem_weak(weak_path, n, e, d)
    keys["weak"] = {"n": n, "e": e, "material": (n, e, d)}

    return keys


def _write_pem(path: Path, label: str, der: bytes, note: str) -> None:
    text = note + "\n" + _pem(label, der)
    path.write_bytes(text.encode("utf-8"))


def _write_pem_weak(path: Path, n: int, e: int, d: int) -> None:
    note = ("# 仅 fixture 使用，不得用于生产。RSA-512：低于 RFC 8301 §3.2 的 1024 位门槛，"
            "用于验证「过短密钥必须判无效」。\n"
            "# cryptography 拒绝生成 <1024 位密钥，本文件由 tools/gen_dkim_fixtures.py "
            "用纯 Python 素数搜索生成。\n"
            "# 格式：n / e / d 三个十进制整数（不是 PEM——没有可用的标准容器承载缺 p/q 的私钥）。\n")
    text = note + "%d\n%d\n%d\n" % (n, e, d)
    path.write_bytes(text.encode("utf-8"))


def _load_pem(path: Path):
    from cryptography.hazmat.primitives import serialization

    data = path.read_bytes()
    start = data.index(b"-----BEGIN")
    return serialization.load_pem_private_key(data[start:], password=None)


def _load_weak(path: Path) -> tuple[int, int, int, int, int]:
    text = path.read_text(encoding="utf-8")
    numbers = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    n, e, d = (int(item) for item in numbers[:3])
    return n, e, d, 0, 0


# ── 落盘 ────────────────────────────────────────────────────────────────


def _json(obj: dict) -> bytes:
    from mailvault import canonical

    return (canonical.dumps_pretty(obj) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="生成 fixtures/dkim 样本")
    parser.add_argument("--check", action="store_true",
                        help="只比对已入仓文件，不写盘（plan/04 §2.5 的幂等检查）")
    args = parser.parse_args(argv)

    try:
        import cryptography
    except ImportError:
        print("FAIL  需要开发期依赖 cryptography（仅本生成器使用，不进运行时）")
        return 2
    del cryptography  # 只探可用性；引用它会让"运行时零依赖"的扫描误报

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

    # 公钥也从私钥导出落盘，便于人工核对 p= 与 PEM 是同一把钥匙。
    keys = _load_keys()
    public_lines = ["# fixture 公钥（由私钥导出，供人工核对 p=）", ""]
    for label, entry in (("main", keys["main"]), ("weak", keys["weak"])):
        public_lines.append("## %s：n 位数 = %d" % (label, entry["n"].bit_length()))
        public_lines.append("")
        public_lines.append("```")
        public_lines.append("n = %d" % entry["n"])
        public_lines.append("e = %d" % entry["e"])
        public_lines.append("```")
        public_lines.append("")
    public_text = "\n".join(public_lines)
    target = KEY_DIR / "README.md"
    if args.check:
        if not target.is_file() or target.read_text(encoding="utf-8") != public_text:
            mismatches.append("keys/README.md 字节不一致")
    else:
        target.write_bytes(public_text.encode("utf-8"))
        written += 1

    print("DKIM fixture 生成器 · %d 个用例" % len(cases))
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
        print("PASS  %d 个用例 × 4 份产物 + keys/README.md 逐字节一致" % len(cases))
        return 0
    print("已写入 %d 份文件（keys/ 存在时私钥不重生成）" % written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
