"""DKIM 验签（RFC 6376 §3.4/§3.5/§3.7/§6.1 + RFC 8301 §3.1/§3.2）：多签名逐条独立求值。

本模块是 M3 的交付面。五条设计约束：

1. **遍历全部 ``DKIM-Signature``，逐条独立求值，不短路**（`plan/03` §3.3）。
   一条签名验过不代表下一条没坏——"只报第一条"会把多签名邮件里真正失败的那条藏起来。
   上游 RFC 6376 §6.1 明确允许实现连续尝试，"成功即停"是实现自由，但**诊断工具**
   不能停：用户要的是"每条签名的结论"。
2. **只从快照取密钥**。``found=False``（快照里没查过这条选择器）**不得**被读成
   "密钥不存在"（K13）：前者是数据缺口 → ``undecidable`` + ``data_gap``，
   后者（快照明确答复 NXDOMAIN / 空答复）才是真的没有密钥 → ``permerror``（RFC 6376 §6.1.2 第 3 步）。
3. **零依赖验签**：DER 解析 + PKCS#1 v1.5 由 :mod:`mailvault.crypto` 完成，
   运行时零第三方依赖（`plan/02` §4）。
4. **判定路径零时钟**（K7）：``t=`` / ``x=`` **不**参与判定——校验 ``x=`` 过期需要"现在几点"，
   那会让同一输入在不同时刻得出不同账本。带 ``x=`` 时给告警，先验证签名本身。
   这是纪律的直接后果，不是遗漏（同 SPF 的 ``%{t}``，见 `plan/06` G7）。
5. **不猜不可判定的定位**：``bh`` / ``b=`` 都是单向哈希，**没有原文就无法指出**
   "哪一行 / 哪个头被改了"。能判定时给确切位置（``l=`` 边界、``From`` 未签名、
   标签语法错），不能判定时给 ``null`` + ``basis`` 说明原因，并在 ``plan/06`` 登记。
   编一个行号比不说更糟——用户会照着错的方向去查。

### 与参照实现（dkimpy 1.1.8）的两处口径差异（均有意为之）

- **``l=`` 大于规范化正文长度**：dkimpy 用 ``body[:l]`` 静默取全量，签名仍可能通过。
  RFC 6376 §3.5 写的是 "MUST NOT be larger"，§6.1.1 要求任何 "inconsistent or unexpected
  values" 立即 PERMFAIL（signature syntax error）。本模块判 ``permerror``。
- **``rsa-sha1``**：RFC 8301 §3.1 已把 ``rsa-sha1`` 从"必须支持"改为
  "MUST NOT be used for signing or verifying"，并说这类签名 "have permanently failed
  evaluation"。本模块判 ``permerror``（而不是算出密码学结果后判 pass）。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from ..constants import (
    DKIM_FORBIDDEN_ALGS,
    DKIM_KEY_STATUSES,
    DKIM_MIN_KEY_BITS,
    DKIM_SUPPORTED_ALGS,
    DKIM_UNSUPPORTED_ALGS,
)
from ..crypto.der import DerError, parse_rsa_public_key
from ..crypto.rsa import verify_pkcs1_v15
from ..eml import Message
from ..ledger import check_entry
from ..snapshot import Snapshot

# ── 条款号（`evidence_ref` 的唯一来源；格式见 `docs/ledger-format.md` §2.2） ──
REF_SIMPLE_HEADER = "RFC6376#3.4.1"
REF_RELAXED_HEADER = "RFC6376#3.4.2"
REF_SIMPLE_BODY = "RFC6376#3.4.3"
REF_RELAXED_BODY = "RFC6376#3.4.4"
REF_SIG_FIELD = "RFC6376#3.5"
REF_KEY_RECORD = "RFC6376#3.6.1"
REF_HASHES = "RFC6376#3.7"
REF_ALGS = "RFC6376#3.3"
REF_EXTRACT = "RFC6376#6.1"
REF_VALIDATE = "RFC6376#6.1.1"
REF_GET_KEY = "RFC6376#6.1.2"
REF_COMPUTE = "RFC6376#6.1.3"
REF_RFC8301_ALGS = "RFC8301#3.1"
REF_RFC8301_BITS = "RFC8301#3.2"

#: ``key_status`` 取值（唯一出处 = `constants.DKIM_KEY_STATUSES`）。
_KEY_STATUSES = frozenset(DKIM_KEY_STATUSES)

#: 签名头字段的必需标签（RFC 6376 §3.5 + §6.1.1 的信息性说明）。
REQUIRED_TAGS = ("v", "a", "b", "bh", "d", "h", "s")

#: 签名里允许出现、但本模块**不解释语义**的已知标签（RFC 6376 §3.5）。
#: 未知标签按 §3.7 照样参与哈希——所以"不认识"不影响验签，只进 trace。
_KNOWN_TAGS = frozenset(
    "v a b bh c d h i l q s t x z".split()
)

#: ``a=`` 的哈希部分 → hashlib 名字。
_HASH_BY_NAME = {"sha1": "sha1", "sha256": "sha256"}

#: ``c=`` 允许的算法名（RFC 6376 §3.4）。
_CANON_ALGOS = ("simple", "relaxed")

#: 正文哈希在 ``failure_at`` 里的 basis 文案（两处复用，避免措辞漂移）。
_BASIS_ONE_WAY_BODY = (
    "bh= 是单向摘要，没有原文无法反推是哪一行被改；本工具不猜行号"
)
_BASIS_ONE_WAY_HEADER = (
    "b= 覆盖的是已签名头字段的整体哈希，没有原文无法反推是哪个头被改；本工具不猜头名"
)


# ── 规范化（RFC 6376 §3.4） ─────────────────────────────────────────────


def canonicalize_header(name: bytes, value: bytes, algorithm: str) -> bytes:
    """规范化一个头字段（含终止 CRLF）。``value`` 保留原始折行。

    - ``simple``（§3.4.1）：一个字节都不改。
    - ``relaxed``（§3.4.2）：名字小写；展开折行（去掉 CRLF、保留其后的 WSP）；
      WSP 串压成一个空格；删掉值首尾空白；冒号两侧空白删掉、冒号保留。
    """
    if algorithm == "simple":
        return name + b":" + value + b"\r\n"
    if algorithm != "relaxed":
        raise ValueError("未知头规范化算法：%r" % (algorithm,))
    lowered = name.strip(b" \t\r\n").lower()
    unfolded = value.replace(b"\r\n", b"").replace(b"\r", b"").replace(b"\n", b"")
    collapsed = re.sub(rb"[ \t]+", b" ", unfolded)
    return lowered + b":" + collapsed.strip(b" ") + b"\r\n"


def canonicalize_body(body: bytes, algorithm: str) -> bytes:
    """规范化正文（RFC 6376 §3.4.3 / §3.4.4）。

    - ``simple``：忽略正文末尾的空行；没有以 CRLF 结尾就补一个；空正文 → 单个 CRLF。
    - ``relaxed``：删每行行尾 WSP、行内 WSP 压成单空格、忽略末尾空行；
      **空正文规范化成零字节**（§3.4.4 的 "null input"）。

    两者的空正文结果不同（2 字节 vs 0 字节），RFC 给了各自的基准哈希值，
    `tests/test_dkim.py` 逐条锁住。
    """
    if algorithm == "simple":
        return _strip_trailing_empty_lines(body)

    if algorithm != "relaxed":
        raise ValueError("未知正文规范化算法：%r" % (algorithm,))
    stripped = re.sub(rb"[ \t]+\r\n", b"\r\n", body)
    collapsed = re.sub(rb"[ \t]+", b" ", stripped)
    canonical = _strip_trailing_empty_lines(collapsed)
    # §3.4.4：空正文 → null input。simple 的 CRLF 占位在这里要还原成零字节。
    if canonical == b"\r\n":
        return b""
    return canonical


def _strip_trailing_empty_lines(body: bytes) -> bytes:
    """删掉末尾的空行（连续 ``CRLF``），再保证恰好以一个 ``CRLF`` 结尾。"""
    end = len(body)
    while end >= 2 and body[end - 2:end] == b"\r\n":
        end -= 2
    return body[:end] + b"\r\n"


# ── 标签列表（RFC 6376 §3.2） ───────────────────────────────────────────


class TagError(ValueError):
    """标签列表语法错（→ ``permerror``）。"""


def parse_tag_list(raw: bytes, *, where: str) -> dict[str, str]:
    """解析 ``tag=value; tag=value`` 形态的标签列表。

    严格口径（§3.2 + §6.1.1 的 "liberal in what you accept is a bad strategy"）：

    - 重复标签 → 错（同一标签给两个值，没有"取哪个"的正确答案）。
    - 缺 ``=`` 的片段 → 错。
    - 标签名必须字母开头，只含字母数字与 ``_-.``。
    - 值两端的 FWS 会被去掉；值内部的空白**保留**（``b=`` 的分段空白由调用方处理）。
    - 末尾允许一个多余的分号（``...;``）。
    """
    tags: dict[str, str] = {}
    parts = raw.split(b";")
    if parts and not parts[-1].strip():
        parts = parts[:-1]  # 末尾空片段（尾分号）是合法的
    for position, part in enumerate(parts):
        text = part.strip()
        if not text:
            raise TagError("%s：第 %d 段是空标签（连续分号）" % (where, position + 1))
        if b"=" not in text:
            raise TagError("%s：第 %d 段缺 '='：%r" % (where, position + 1, text[:60]))
        raw_name, _, raw_value = text.partition(b"=")
        name = raw_name.strip().decode("ascii", "replace").lower()
        if not name or not re.fullmatch(r"[a-z][a-z0-9_.\-]*", name):
            raise TagError("%s：第 %d 段标签名非法：%r" % (where, position + 1, raw_name))
        if name in tags:
            raise TagError("%s：标签 %s= 出现两次" % (where, name))
        tags[name] = raw_value.strip().decode("ascii", "replace")
    return tags


def _decode_base64(value: str, *, where: str) -> bytes:
    """解 ``b=`` / ``bh=`` 的 base64（忽略空白；宽松补齐 padding 但不忽略其它字符）。"""
    compact = re.sub(r"\s+", "", value)
    if not compact:
        raise TagError("%s：base64 值为空" % where)
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        # 有些发布者省略末尾 '='；补到 4 的倍数再试一次，仍失败才判错。
        padding = (-len(compact)) % 4
        try:
            return base64.b64decode(compact + "=" * padding, validate=True)
        except (binascii.Error, ValueError):
            raise TagError("%s：base64 解不开（长度 %d）" % (where, len(compact))) from None


# ── 密钥记录（RFC 6376 §3.6.1） ─────────────────────────────────────────


@dataclass(frozen=True)
class _KeyRecord:
    """一次 ``<selector>._domainkey.<d>`` 的求值结果。"""

    status: str
    """``constants.DKIM_KEY_STATUSES`` 里的值。"""
    bits: int | None = None
    encoding: str | None = None
    """``spki`` / ``rsapublickey``（写进 trace）。"""
    key: Any = None
    """解析出的 :class:`mailvault.crypto.der.RsaPublicKey`；不可用时为 ``None``。"""
    note: str = ""
    data_gap: tuple[str, str] | None = None
    """非空表示"快照里没查过"——待补的输入，不是结论（K13）。"""
    ref: str = REF_KEY_RECORD


def _load_key(snapshot: Snapshot, *, selector: str, domain: str, hash_name: str,
              trace: list[dict[str, Any]]) -> _KeyRecord:
    """按 §3.6.1 / §6.1.2 取密钥并定 ``key_status``。"""
    qname = "%s._domainkey.%s" % (selector, domain)
    resolved = snapshot.resolve(qname, "TXT", trace)
    trace.append({"node": "dkim.key", "note": "%s 的选择器 %s → 查询 %s"
                  % (domain, selector, qname)})

    if not resolved.found:
        # K13：没查过 ≠ 没有。这是数据缺口，结论是"判不了"。
        return _KeyRecord(
            status="missing",
            note="快照里没有 %s/TXT 这条查询（数据缺口，不等同于密钥不存在）" % qname,
            data_gap=(qname, "TXT"),
        )
    if resolved.rcode != "NOERROR" or not resolved.answer:
        # 查过了、确实没有：RFC 6376 §6.1.2 第 3 步 → PERMFAIL（no key for signature）。
        return _KeyRecord(
            status="missing",
            note="快照答复 %s：%s 没有可用密钥记录" % (resolved.rcode, qname),
        )

    # 多个 TXT 记录时 RFC 说"结果未定义"（§3.6.2）。取第一条能解析的并记进 trace，
    # 而不是静默取 [0]——"为什么用这一条"必须可复算。
    problems: list[str] = []
    for position, record in enumerate(resolved.answer):
        parsed = _parse_key_record(record, hash_name=hash_name)
        if isinstance(parsed, _KeyRecord):
            if position:
                trace.append({"node": "dkim.key",
                              "note": "取第 %d 条 TXT 记录（前 %d 条不可用）"
                                      % (position + 1, position)})
            return parsed
        problems.append("记录 #%d：%s" % (position + 1, parsed))
    return _KeyRecord(status="invalid", note="密钥记录不可用（%s）" % "；".join(problems))


def _parse_key_record(record: str, *, hash_name: str) -> _KeyRecord | str:
    """解析一条密钥 TXT 记录。成功返回 :class:`_KeyRecord`，失败返回原因字符串。"""
    raw = record.encode("utf-8", "surrogateescape")
    try:
        tags = parse_tag_list(raw, where="密钥记录")
    except TagError as exc:
        return str(exc)

    if "p" not in tags:
        return "缺 p=（RFC 6376 §3.6.1 标为 REQUIRED）"

    version = tags.get("v")
    if version is not None and version != "DKIM1":
        # §3.6.1："Records beginning with a v= tag with any other value MUST be discarded."
        return "v=%r 不是 DKIM1（记录必须丢弃）" % (version,)

    key_type = (tags.get("k") or "rsa").lower()
    if key_type != "rsa":
        # §3.6.1："Unrecognized key types MUST be ignored."
        return "k=%r 不是 rsa（本工具只验 RSA：RFC 6376 §3.6.1）" % (key_type,)

    services = tags.get("s") or "*"
    service_types = {item.strip().lower() for item in services.split(":") if item.strip()}
    if "*" not in service_types and "email" not in service_types:
        return "s=%r 不含 email/*（§3.6.1：服务类型不匹配的记录必须忽略）" % (services,)

    hashes = tags.get("h")
    if hashes:
        allowed = {item.strip().lower() for item in hashes.split(":") if item.strip()}
        if hash_name not in allowed:
            return "h=%r 不含 %s（§6.1.2 第 6 步 → PERMFAIL）" % (hashes, hash_name)

    if not tags["p"].strip():
        # §3.6.1："An empty value means that this public key has been revoked."
        return _KeyRecord(status="revoked", note="p= 为空：该密钥已撤销（RFC 6376 §3.6.1）")

    try:
        der = _decode_base64(tags["p"], where="p=")
    except TagError as exc:
        return str(exc)
    try:
        key = parse_rsa_public_key(der)
    except DerError as exc:
        return "p= 不是合法的 RSA 公钥 DER（%s）" % (exc,)

    bits = key.bit_length
    if bits < DKIM_MIN_KEY_BITS:
        # RFC 8301 §3.2："Verifiers MUST NOT consider signatures using RSA keys of
        # less than 1024 bits as valid signatures." → 这是 MUST，判 fail 而不是灰区。
        return _KeyRecord(
            status="weak", bits=bits, encoding=key.encoding, key=key,
            note="RSA 密钥 %d 位 < %d 位（RFC 8301 §3.2 MUST NOT 视为有效）"
                 % (bits, DKIM_MIN_KEY_BITS),
            ref=REF_RFC8301_BITS,
        )
    return _KeyRecord(
        status="ok", bits=bits, encoding=key.encoding, key=key,
        note="RSA %d 位（%s 编码）" % (bits, key.encoding),
    )


# ── 单条签名的结果 ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class SignatureResult:
    """一条 ``DKIM-Signature`` 的完整结论（`plan/03` §3.3 的十个字段全在其中）。"""

    index: int
    selector: str | None
    domain: str | None
    identity: str | None
    algorithm: str | None
    canonicalization: str | None
    bh_matches: bool | None
    failure_at: dict[str, Any] | None
    key_bits: int | None
    key_status: str | None
    result: str
    reason: str
    evidence_ref: tuple[str, ...]
    trace: tuple[dict[str, Any], ...]
    warnings: tuple[str, ...]
    data_gap: tuple[str, str] | None = None

    @property
    def signed_headers(self) -> list[str]:
        """这条签名覆盖的头字段名（从 trace 里取，避免再加一个字段）。"""
        for node in self.trace:
            if node.get("node") == "dkim.h=":
                return list(node.get("note", "").split())
        return []

    def to_dict(self) -> dict[str, Any]:
        """人读/测试用的扁平视图（**不**进账本；账本走 :meth:`to_check_entry`）。"""
        return {
            "index": self.index,
            "selector": self.selector,
            "d": self.domain,
            "i": self.identity,
            "a": self.algorithm,
            "c": self.canonicalization,
            "bh_matches": self.bh_matches,
            "failure_at": self.failure_at,
            "key_bits": self.key_bits,
            "key_status": self.key_status,
            "result": self.result,
            "reason": self.reason,
            "warnings": list(self.warnings),
            "data_gap": list(self.data_gap) if self.data_gap else None,
        }


@dataclass(frozen=True)
class DkimResult:
    """一封报文的全部签名结论（``signatures`` 按物理顺序，**不短路**）。"""

    signatures: tuple[SignatureResult, ...]
    message_has_signatures: bool
    trace: tuple[dict[str, Any], ...] = ()
    warnings: tuple[str, ...] = ()
    data_gaps: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    @property
    def results(self) -> list[str]:
        return [item.result for item in self.signatures]

    @property
    def summary(self) -> str:
        """一句话摘要（CLI stderr 用）。"""
        if not self.signatures:
            return "无 DKIM-Signature（none）"
        counts: dict[str, int] = {}
        for item in self.signatures:
            counts[item.result] = counts.get(item.result, 0) + 1
        parts = ["%s×%d" % (key, counts[key]) for key in sorted(counts)]
        return "%d 条签名：%s" % (len(self.signatures), "、".join(parts))

    def to_check_entries(self) -> list[dict[str, Any]]:
        """转成账本 ``checks[]`` 条目：**一条签名一条目**（多签名时逐条可读）。"""
        if not self.signatures:
            return [check_entry(
                check_id="dkim.verify_signature",
                module="M3",
                subject={"signatures_total": 0},
                result="none",
                reason="报文里没有 DKIM-Signature 头字段，本项判 none（不是 fail）",
                evidence_ref=[REF_EXTRACT],
                trace=list(self.trace),
                warnings=list(self.warnings) + ["报文未签名：dkim 判 none"],
                tree=None,
            )]

        entries: list[dict[str, Any]] = []
        total = len(self.signatures)
        for signature in self.signatures:
            entries.append(check_entry(
                check_id="dkim.verify_signature",
                module="M3",
                subject={
                    "index": signature.index,
                    "signatures_total": total,
                    "selector": signature.selector,
                    "d": signature.domain,
                    "a": signature.algorithm,
                    "c": signature.canonicalization,
                    "key_status": signature.key_status,
                    "key_bits": signature.key_bits,
                    "bh_matches": signature.bh_matches,
                    "failure_at": signature.failure_at,
                    "h": signature.signed_headers,
                },
                result=signature.result,
                reason=signature.reason,
                evidence_ref=list(signature.evidence_ref),
                trace=list(signature.trace),
                warnings=list(signature.warnings),
                tree=None,  # M3 无判定树；键仍存在（`docs/ledger-format.md` §2）
            ))
        return entries


# ── 主求值 ──────────────────────────────────────────────────────────────


def verify_message(message: Message, snapshot: Snapshot, *,
                   trace: list[dict[str, Any]] | None = None) -> DkimResult:
    """验一封报文的**全部**签名。

    ``trace`` 是共享轨迹列表（CLI 让 SPF 与 DKIM 写在同一条轨迹上）。
    本函数只追加、不清空。
    """
    shared = trace if trace is not None else []
    raw_fields = message.header_fields()
    body = message.body_crlf

    signature_indexes = [
        position for position, (name, _) in enumerate(raw_fields)
        if name.strip().lower() == b"dkim-signature"
    ]
    shared.append({"node": "dkim.extract",
                   "note": "报文头 %d 个，其中 DKIM-Signature %d 条（逐条独立求值，不短路）"
                           % (len(raw_fields), len(signature_indexes))})

    results: list[SignatureResult] = []
    gaps: list[tuple[str, str]] = []
    warnings: list[str] = []
    for ordinal, position in enumerate(signature_indexes):
        local_trace: list[dict[str, Any]] = []
        result = _verify_one(
            ordinal=ordinal,
            position=position,
            raw_fields=raw_fields,
            body=body,
            snapshot=snapshot,
            trace=local_trace,
        )
        shared.extend(local_trace)
        results.append(result)
        if result.data_gap:
            gaps.append(result.data_gap)
        for warning in result.warnings:
            if warning not in warnings:
                warnings.append(warning)

    return DkimResult(
        signatures=tuple(results),
        message_has_signatures=bool(signature_indexes),
        trace=tuple(shared),
        warnings=tuple(warnings),
        data_gaps=tuple(gaps),
    )


def _verify_one(*, ordinal: int, position: int,
                raw_fields: list[tuple[bytes, bytes]], body: bytes,
                snapshot: Snapshot, trace: list[dict[str, Any]]) -> SignatureResult:
    """验一条签名。按 RFC 6376 §6.1.1 → §6.1.2 → §6.1.3 的顺序走。

    任何一步失败都**只**结束这一条（`return` 带结论），不影响后续签名。
    """
    name, raw_value = raw_fields[position]
    warnings: list[str] = []
    base = dict(index=ordinal)
    trace.append({"node": "dkim.sig", "note": "#%d 位于报文第 %d 个头字段" % (ordinal, position + 1)})

    # ── §6.1.1 校验签名头字段 ──────────────────────────────────────────
    try:
        tags = parse_tag_list(raw_value, where="DKIM-Signature #%d" % ordinal)
    except TagError as exc:
        return _bail(base, trace, "permerror", "签名头语法错误：%s" % exc,
                     REF_VALIDATE, warnings,
                     failure_at={"kind": "header_syntax", "header": "DKIM-Signature",
                                 "offset": _first_bad_offset(raw_value)})

    missing = [tag for tag in REQUIRED_TAGS if tag not in tags]
    if missing:
        return _bail(base, trace, "permerror",
                     "缺必需标签 %s（RFC 6376 §3.5 REQUIRED）"
                     % "、".join("%s=" % tag for tag in missing),
                     REF_VALIDATE, warnings,
                     failure_at={"kind": "missing_tag", "header": "DKIM-Signature",
                                 "offset": 0, "tags": missing})

    version = tags.get("v")
    if version != "1":
        # §6.1.1："MUST return PERMFAIL (incompatible version)"。
        return _bail(base, trace, "permerror", "v=%r 与本规范不兼容（要求 v=1）" % (version,),
                     REF_VALIDATE, warnings,
                     failure_at={"kind": "header_syntax", "header": "DKIM-Signature",
                                 "offset": _tag_offset(raw_value, "v")},
                     selector=tags.get("s"), domain=tags.get("d"),
                     algorithm=tags.get("a"), canonicalization=tags.get("c"))

    algorithm = tags["a"].strip().lower()
    domain = tags["d"].strip().rstrip(".").lower()
    selector = tags["s"].strip()
    canonical = _parse_canonicalization(tags.get("c"), warnings)
    if canonical is None:
        return _bail(base, trace, "permerror",
                     "c=%r 不是合法的规范化组合（允许 simple/relaxed）" % (tags.get("c"),),
                     REF_VALIDATE, warnings,
                     failure_at={"kind": "header_syntax", "header": "DKIM-Signature",
                                 "offset": _tag_offset(raw_value, "c")},
                     selector=selector, domain=domain, algorithm=algorithm,
                     canonicalization=tags.get("c"))
    canon_header, canon_body = canonical

    identity = tags.get("i") or ("@%s" % domain)
    if not _identity_under_domain(identity, domain):
        # §6.1.1："d= ... MUST be the same as or a parent domain of ... i="。
        return _bail(base, trace, "permerror",
                     "i=%s 不在 d=%s 之下（RFC 6376 §6.1.1 domain mismatch）"
                     % (identity, domain),
                     REF_VALIDATE, warnings,
                     failure_at={"kind": "domain_mismatch", "header": "DKIM-Signature",
                                 "offset": _tag_offset(raw_value, "i")},
                     selector=selector, domain=domain, algorithm=algorithm,
                     identity=identity)
    if tags.get("i") is None:
        trace.append({"node": "dkim.i", "note": "无 i=，按 §6.1.1 取默认值 @%s" % domain})

    signed_names = [item.strip().lower() for item in tags["h"].split(":") if item.strip()]
    if not signed_names:
        return _bail(base, trace, "permerror",
                     "h= 为空（RFC 6376 §3.5：列表 MUST NOT be empty）",
                     REF_VALIDATE, warnings,
                     failure_at={"kind": "header_syntax", "header": "DKIM-Signature",
                                 "offset": _tag_offset(raw_value, "h")},
                     selector=selector, domain=domain, algorithm=algorithm,
                     identity=identity)
    trace.append({"node": "dkim.h=", "note": " ".join(signed_names)})

    if "from" not in signed_names:
        # §6.1.1："MUST ignore ... return PERMFAIL (From field not signed)"。
        return _bail(base, trace, "permerror",
                     "h= 未包含 From（RFC 6376 §6.1.1 要求 From 必须被签名）",
                     REF_VALIDATE, warnings,
                     failure_at={"kind": "from_not_signed", "header": "From", "offset": 0},
                     selector=selector, domain=domain, algorithm=algorithm,
                     identity=identity, canonicalization=tags.get("c"))

    # 时间标签：判定路径零时钟（K7）。不校验，但要告警——静默跳过会让用户以为查过了。
    if "x" in tags:
        warnings.append("含 x=（签名过期时间）：本工具判定路径零时钟（K7），未校验是否过期；"
                        "如需判断请对照报文接收时间人工核对")
        trace.append({"node": "dkim.x", "note": "x=%s 未校验（K7：判定不读系统时钟）"
                                                % tags["x"]})
    if "t" in tags:
        trace.append({"node": "dkim.t", "note": "t=%s（仅记录，不参与判定）" % tags["t"]})

    unknown = sorted(set(tags) - _KNOWN_TAGS)
    if unknown:
        trace.append({"node": "dkim.tags",
                      "note": "未知标签 %s：按 §3.7 照样参与哈希，本模块不解释其语义"
                              % "、".join("%s=" % item for item in unknown)})

    # ── 算法门（RFC 8301 §3.1 更新了 RFC 6376 的算法矩阵） ─────────────
    key_type, hash_name, algorithm_problem = _split_algorithm(algorithm)
    if algorithm_problem:
        return _bail(base, trace, "permerror", algorithm_problem, REF_SIG_FIELD, warnings,
                     failure_at={"kind": "header_syntax", "header": "DKIM-Signature",
                                 "offset": _tag_offset(raw_value, "a")},
                     selector=selector, domain=domain, algorithm=algorithm,
                     identity=identity, canonicalization=tags.get("c"))

    if algorithm in DKIM_UNSUPPORTED_ALGS:
        # 标准库无 Ed25519。判"判不了"，**不判 fail**（`plan/02` §4）。
        return _bail(base, trace, "undecidable",
                     "a=%s 本工具不支持（标准库无 Ed25519），未做判定" % algorithm,
                     REF_ALGS, warnings + ["本工具不支持 %s 算法：该签名的强弱未知" % algorithm],
                     selector=selector, domain=domain, algorithm=algorithm,
                     identity=identity, canonicalization=tags.get("c"))

    if algorithm in DKIM_FORBIDDEN_ALGS:
        # RFC 8301 §3.1："rsa-sha1 MUST NOT be used for signing or verifying"，
        # 且 §3 收尾指出这类签名 "have permanently failed evaluation"。
        return _bail(base, trace, "permerror",
                     "a=%s 已被 RFC 8301 §3.1 禁止用于签名与验签（永久失败）" % algorithm,
                     REF_RFC8301_ALGS, warnings,
                     selector=selector, domain=domain, algorithm=algorithm,
                     identity=identity, canonicalization=tags.get("c"))

    if algorithm not in DKIM_SUPPORTED_ALGS:
        # 形如 `k-h` 合法、但不在白名单：**本工具没有判定能力**，不是"签名坏了"。
        return _bail(base, trace, "undecidable",
                     "a=%s 不在本工具支持的算法清单内（%s），未做判定"
                     % (algorithm, "、".join(DKIM_SUPPORTED_ALGS)),
                     REF_ALGS, warnings + ["本工具不判 %s：该签名的强弱未知" % algorithm],
                     selector=selector, domain=domain, algorithm=algorithm,
                     identity=identity, canonicalization=tags.get("c"))

    # ── 取密钥（§6.1.2，先于 §6.1.3 的哈希计算） ───────────────────────
    #
    # 顺序是 RFC 的原文顺序，不是实现偏好：先确定"有没有能用的密钥"，
    # 再算正文哈希。反过来的坏处是真实的——密钥已撤销 + 正文也被改时，
    # 只报"正文哈希不符"会把"密钥已撤销"这条独立事实藏起来。
    key_record = _load_key(snapshot, selector=selector, domain=domain,
                           hash_name=hash_name, trace=trace)
    trace.append({"node": "dkim.key_status",
                  "note": "%s：%s" % (key_record.status, key_record.note)})
    if key_record.encoding:
        trace.append({"node": "dkim.key_encoding",
                      "note": "p= 编码为 %s" % key_record.encoding})

    if key_record.status == "missing":
        if key_record.data_gap:
            warnings.append("缺 %s/TXT：本次无法判定该签名（数据缺口，不是密钥不存在）"
                            % key_record.data_gap[0])
            return SignatureResult(
                **base,
                selector=selector, domain=domain, identity=identity,
                algorithm=algorithm, canonicalization=tags.get("c"),
                bh_matches=None, failure_at=None,
                key_bits=None, key_status="missing",
                result="undecidable",
                reason="%s；没有公钥就无法完成验证，正文与头部哈希均未参与判定"
                       % key_record.note,
                evidence_ref=(REF_GET_KEY,),
                trace=tuple(trace),
                warnings=tuple(warnings),
                data_gap=key_record.data_gap,
            )
        return SignatureResult(
            **base,
            selector=selector, domain=domain, identity=identity,
            algorithm=algorithm, canonicalization=tags.get("c"),
            bh_matches=None, failure_at=None,
            key_bits=None, key_status="missing",
            result="permerror",
            reason="%s（RFC 6376 §6.1.2 第 3 步：no key for signature）" % key_record.note,
            evidence_ref=(REF_GET_KEY,),
            trace=tuple(trace),
            warnings=tuple(warnings),
        )

    if key_record.status == "revoked":
        return SignatureResult(
            **base,
            selector=selector, domain=domain, identity=identity,
            algorithm=algorithm, canonicalization=tags.get("c"),
            bh_matches=None, failure_at=None,
            key_bits=None, key_status="revoked",
            result="permerror",
            reason="%s（RFC 6376 §6.1.2 第 7 步：key revoked）" % key_record.note,
            evidence_ref=(REF_GET_KEY, REF_KEY_RECORD),
            trace=tuple(trace),
            warnings=tuple(warnings),
        )

    if key_record.status == "weak":
        # RFC 8301 §3.2 是 MUST：不验签也要判 fail——"密钥太短"本身就是结论。
        return SignatureResult(
            **base,
            selector=selector, domain=domain, identity=identity,
            algorithm=algorithm, canonicalization=tags.get("c"),
            bh_matches=None, failure_at=None,
            key_bits=key_record.bits, key_status="weak",
            result="fail",
            reason="%s；按 RFC 8301 §3.2 MUST NOT 视为有效签名，未再验签" % key_record.note,
            evidence_ref=(REF_RFC8301_BITS,),
            trace=tuple(trace),
            warnings=tuple(warnings),
        )

    if key_record.status != "ok" or key_record.key is None:
        return SignatureResult(
            **base,
            selector=selector, domain=domain, identity=identity,
            algorithm=algorithm, canonicalization=tags.get("c"),
            bh_matches=None, failure_at=None,
            key_bits=key_record.bits, key_status=key_record.status,
            result="permerror",
            reason="%s（RFC 6376 §6.1.2：密钥不可用）" % key_record.note,
            evidence_ref=(REF_GET_KEY,),
            trace=tuple(trace),
            warnings=tuple(warnings),
        )

    # ── 正文哈希（§3.7 第 1 步 / §6.1.3 第 3 步） ────────────────────────
    bh_raw = _decode_base64_soft(tags["bh"])
    if bh_raw is None:
        return SignatureResult(
            **base,
            selector=selector, domain=domain, identity=identity,
            algorithm=algorithm, canonicalization=tags.get("c"),
            bh_matches=None,
            failure_at={"kind": "header_syntax", "header": "DKIM-Signature",
                        "offset": _tag_offset(raw_value, "bh")},
            key_bits=key_record.bits, key_status=key_record.status,
            result="permerror",
            reason="bh= 不是合法 base64（RFC 6376 §3.5）",
            evidence_ref=(REF_SIG_FIELD,),
            trace=tuple(trace),
            warnings=tuple(warnings),
        )

    canonical_body = canonicalize_body(body, canon_body)
    limit, limit_error = _parse_length(tags.get("l"))
    if limit_error:
        return _bail(base, trace, "permerror", limit_error, REF_SIG_FIELD, warnings,
                     failure_at={"kind": "header_syntax", "header": "DKIM-Signature",
                                 "offset": _tag_offset(raw_value, "l")},
                     selector=selector, domain=domain, algorithm=algorithm,
                     identity=identity, canonicalization=tags.get("c"))

    if limit is not None and limit > len(canonical_body):
        # RFC 6376 §3.5："This value MUST NOT be larger than the actual number of octets
        # in the canonicalized message body." §6.1.1 要求任何不一致立即 PERMFAIL。
        return _bail(base, trace, "permerror",
                     "l=%d 大于规范化正文长度 %d（RFC 6376 §3.5 MUST NOT），按签名语法错误处理"
                     % (limit, len(canonical_body)),
                     REF_SIG_FIELD, warnings,
                     failure_at={"kind": "length_exceeds_body", "header": "DKIM-Signature",
                                 "offset": _tag_offset(raw_value, "l"),
                                 "body_line": 1, "limit": limit,
                                 "canonical_length": len(canonical_body)},
                     selector=selector, domain=domain, algorithm=algorithm,
                     identity=identity, canonicalization=tags.get("c"))

    covered = canonical_body if limit is None else canonical_body[:limit]
    hasher = hashlib.new(_HASH_BY_NAME[hash_name])
    hasher.update(covered)
    bh_matches = hasher.digest() == bh_raw
    trace.append({"node": "dkim.bh",
                  "note": "正文规范化（%s）%d 字节；覆盖 %d 字节；bh %s"
                          % (canon_body, len(canonical_body), len(covered),
                             "匹配" if bh_matches else "不匹配")})

    # `l=` 把尾部排除在签名之外时，如实说明"从第几行起未受保护"——这是可判定的，
    # 所以给确切行号（不是猜的）。
    if limit is not None:
        if limit < len(canonical_body):
            unsigned_line = _first_line_beyond(canonical_body, limit)
            warnings.append(
                "l=%d 只覆盖前 %d 字节（共 %d 字节）：第 %s 行起的正文未受签名保护"
                "（RFC 6376 §3.5 允许，但 §8.2 建议慎用）"
                % (limit, limit, len(canonical_body),
                   "?" if unsigned_line is None else unsigned_line))

    if not bh_matches:
        return SignatureResult(
            **base,
            selector=selector, domain=domain, identity=identity,
            algorithm=algorithm, canonicalization=tags.get("c"),
            bh_matches=False,
            failure_at={"kind": "body_hash", "body_line": None,
                        "basis": _BASIS_ONE_WAY_BODY,
                        "l": limit, "canonical_length": len(canonical_body)},
            key_bits=key_record.bits, key_status=key_record.status,
            result="fail",
            reason="正文哈希与 bh= 不符（RFC 6376 §6.1.3 第 3 步：body hash did not verify）",
            evidence_ref=(REF_COMPUTE, REF_HASHES),
            trace=tuple(trace),
            warnings=tuple(warnings),
        )

    # ── 头部哈希 + 验签（§3.7 第 2 步、§6.1.3 第 4 步） ───────────────
    selected, selection_problem = _select_headers(
        raw_fields, signed_names, exclude=position)
    if selection_problem:
        return SignatureResult(
            **base,
            selector=selector, domain=domain, identity=identity,
            algorithm=algorithm, canonicalization=tags.get("c"),
            bh_matches=True, failure_at=None,
            key_bits=key_record.bits, key_status="ok",
            result="permerror",
            reason=selection_problem,
            evidence_ref=(REF_VALIDATE, REF_SIG_FIELD),
            trace=tuple(trace),
            warnings=tuple(warnings),
        )

    header_hasher = hashlib.new(_HASH_BY_NAME[hash_name])
    for header_name, header_value in selected:
        header_hasher.update(canonicalize_header(header_name, header_value, canon_header))
    # 签名头自身：删掉 b= 的值，按同一算法规范化，**不带**结尾 CRLF（§3.7）。
    stripped_value = _strip_b_value(raw_value)
    signature_header = canonicalize_header(name, stripped_value, canon_header)
    if signature_header.endswith(b"\r\n"):
        signature_header = signature_header[:-2]
    header_hasher.update(signature_header)
    trace.append({"node": "dkim.headers",
                  "note": "已签名 %d 个头字段（%s 规范化）+ 签名头自身（b= 置空）"
                          % (len(selected), canon_header)})

    try:
        signature_bytes = _decode_base64(tags["b"], where="b=")
    except TagError as exc:
        return SignatureResult(
            **base,
            selector=selector, domain=domain, identity=identity,
            algorithm=algorithm, canonicalization=tags.get("c"),
            bh_matches=True,
            failure_at={"kind": "header_syntax", "header": "DKIM-Signature",
                        "offset": _tag_offset(raw_value, "b")},
            key_bits=key_record.bits, key_status="ok",
            result="permerror",
            reason="b= 不可用：%s" % exc,
            evidence_ref=(REF_SIG_FIELD,),
            trace=tuple(trace),
            warnings=tuple(warnings),
        )

    outcome = verify_pkcs1_v15(
        key_record.key, signature_bytes,
        hash_name=hash_name, digest=header_hasher.digest())

    if not outcome.ok:
        return SignatureResult(
            **base,
            selector=selector, domain=domain, identity=identity,
            algorithm=algorithm, canonicalization=tags.get("c"),
            bh_matches=True,
            failure_at={"kind": "header_hash", "header": None, "offset": None,
                        "basis": _BASIS_ONE_WAY_HEADER},
            key_bits=key_record.bits, key_status="ok",
            result="fail",
            reason="签名验不过：%s（RFC 6376 §6.1.3 第 4 步：signature did not verify）"
                   % outcome.reason,
            evidence_ref=(REF_COMPUTE, REF_VALIDATE),
            trace=tuple(trace),
            warnings=tuple(warnings),
        )

    return SignatureResult(
        **base,
        selector=selector, domain=domain, identity=identity,
        algorithm=algorithm, canonicalization=tags.get("c"),
        bh_matches=True,
        failure_at=None,
        key_bits=key_record.bits, key_status="ok",
        result="pass",
        reason="正文哈希匹配，%s 签名在 %d 位 RSA 公钥上验签通过"
               % (algorithm, key_record.bits),
        evidence_ref=(REF_COMPUTE, REF_HASHES, REF_KEY_RECORD),
        trace=tuple(trace),
        warnings=tuple(warnings),
    )


# ── 小工具 ──────────────────────────────────────────────────────────────


def _bail(base: dict[str, Any], trace: list[dict[str, Any]], result: str, reason: str,
          ref: str, warnings: list[str], *, failure_at: dict[str, Any] | None = None,
          selector: str | None = None, domain: str | None = None,
          algorithm: str | None = None, identity: str | None = None,
          canonicalization: str | None = None) -> SignatureResult:
    """在取到密钥之前就结束一条签名的统一出口（保证字段集一致）。"""
    trace.append({"node": "dkim.stop", "note": "%s：%s" % (result, reason)})
    return SignatureResult(
        **base,
        selector=selector, domain=domain, identity=identity,
        algorithm=algorithm, canonicalization=canonicalization,
        bh_matches=None, failure_at=failure_at,
        key_bits=None, key_status=None,
        result=result, reason=reason,
        evidence_ref=(ref,), trace=tuple(trace), warnings=tuple(warnings),
    )


def _split_algorithm(algorithm: str) -> tuple[str | None, str | None, str | None]:
    """拆 ``a=``。返回 ``(key_type, hash_name, 语法问题说明)``。

    区分两件事（`plan/03` §3.3 的口径）：

    - **语法错**：不是 ``k-h`` 形态 → ``permerror``（§3.5 ABNF 不满足）。
    - **语法对但哈希不认识**（如 ``rsa-sha512``）→ 调用方判 ``undecidable``：
      本工具没有那个哈希的实现，说"签名坏了"是越权。
    """
    key_type, separator, hash_part = algorithm.partition("-")
    if not separator or not key_type or not hash_part:
        return None, None, "a=%r 不是 'k-h' 形态（RFC 6376 §3.5 ABNF）" % (algorithm,)
    if hash_part not in _HASH_BY_NAME:
        return key_type, None, None
    return key_type, _HASH_BY_NAME[hash_part], None


def _parse_canonicalization(value: str | None,
                            warnings: list[str]) -> tuple[str, str] | None:
    """``c=`` → ``(头算法, 正文算法)``。非法 → ``None``。

    §3.5：只给一个名字时，正文按 ``simple``。
    """
    if value is None or not value.strip():
        return "simple", "simple"
    parts = [item.strip().lower() for item in value.split("/")]
    if len(parts) == 1:
        parts.append("simple")
    if len(parts) != 2:
        return None
    if any(part not in _CANON_ALGOS for part in parts):
        return None
    if parts != ["simple", "simple"]:
        warnings.append("规范化 %s/%s：与默认值不同，已按 c= 声明求值" % tuple(parts))
    return parts[0], parts[1]


def _identity_under_domain(identity: str, domain: str) -> bool:
    """``i=`` 的域部分必须等于 ``d=`` 或是其子域（RFC 6376 §6.1.1）。"""
    if "@" not in identity:
        return False
    _, _, identity_domain = identity.rpartition("@")
    identity_domain = identity_domain.strip().rstrip(".").lower()
    if not domain:
        return False
    return identity_domain == domain or identity_domain.endswith("." + domain)


def _parse_length(value: str | None) -> tuple[int | None, str | None]:
    """解析 ``l=``。返回 ``(值, 错误说明)``。"""
    if value is None:
        return None, None
    text = value.strip()
    if not text.isdigit():
        return None, "l=%r 不是十进制无符号整数（RFC 6376 §3.5）" % (value,)
    if len(text) > 76:
        # §3.5 的信息性说明把值限制在 76 个十进制位；超了按语法错误处理。
        return None, "l= 长达 %d 位，超过 RFC 6376 §3.5 的 76 位上限" % len(text)
    return int(text), None


def _first_line_beyond(body: bytes, limit: int) -> int | None:
    """返回"起始偏移 ≥ limit"的第一行的 1-based 行号；没有这样的行 → ``None``。"""
    if limit >= len(body):
        return None
    starts = [0]
    index = body.find(b"\r\n")
    while index >= 0:
        starts.append(index + 2)
        index = body.find(b"\r\n", index + 2)
    for position, start in enumerate(starts):
        if start >= limit:
            return position + 1
    return None


def _select_headers(raw_fields: list[tuple[bytes, bytes]], signed_names: list[str], *,
                    exclude: int) -> tuple[list[tuple[bytes, bytes]], str | None]:
    """按 ``h=`` 选头：每个名字取**最靠下**的未用实例（RFC 6376 §5.4.2）。

    ``exclude`` 是当前正在验的签名头下标——§3.5 明确它不得被自己覆盖。
    返回 ``(选中的 (name, value) 列表, 错误说明)``。
    """
    selected: list[tuple[bytes, bytes]] = []
    #: 每个名字的"下一个搜索上界"（不含）。默认从报文末尾往上找。
    cursor: dict[str, int] = {}
    available: dict[str, int] = {}
    for position, (name, _) in enumerate(raw_fields):
        if position == exclude:
            continue
        lowered = name.strip().lower()
        available[lowered] = available.get(lowered, 0) + 1

    wanted: dict[str, int] = {}
    for name in signed_names:
        wanted[name] = wanted.get(name, 0) + 1
    for name, count in wanted.items():
        if count > available.get(name, 0):
            # 不存在的头字段按"空输入"处理是合法的（§3.5），但**超出实例数**的重复
            # 只可能是在签 dkim-signature（含自身）或笔误。前者 §3.5 明令禁止。
            if name == "dkim-signature":
                return [], ("h= 引用了 %d 个 dkim-signature，但除本签名外只有 %d 个"
                            "（RFC 6376 §3.5：不得包含正在验的签名头自身）"
                            % (count, available.get(name, 0)))
            # 其它名字：多余的实例落到"空输入"，这是 §3.5 允许的（防头字段插入）。
            break

    for name in signed_names:
        boundary = cursor.get(name, len(raw_fields))
        found: int | None = None
        for position in range(boundary - 1, -1, -1):
            if position == exclude:
                continue
            if raw_fields[position][0].strip().lower() == name.encode("ascii"):
                found = position
                break
        if found is None:
            # 不存在的头 → 空输入（RFC 6376 §3.5），不产生哈希输入，也不算错。
            cursor[name] = 0
            continue
        selected.append(raw_fields[found])
        cursor[name] = found
    return selected, None


def _strip_b_value(raw_value: bytes) -> bytes:
    """删掉 ``b=`` 标签的**值**（保留 ``b=`` 与后续的 ``;``/标签）。

    RFC 6376 §3.7：签名头参与哈希时 "with the 'b=' tag value deleted"。
    值与标签一样可以折行，所以这里按字节扫：找到 ``b`` 标签的 ``=`` 之后，
    一直删到下一个 ``;`` 或串尾。
    """
    # 找形如 (开头或 ';' 或空白) b [FWS] = 的位置。
    pattern = re.compile(rb"(^|;)([ \t\r\n]*)(b)([ \t\r\n]*)(=)")
    match = pattern.search(raw_value)
    if match is None:
        # 没有 b= 标签（必填标签校验已在前面拦过）。原样返回，让验签自己失败。
        return raw_value
    value_start = match.end()
    next_semicolon = raw_value.find(b";", value_start)
    value_end = len(raw_value) if next_semicolon < 0 else next_semicolon
    return raw_value[:value_start] + raw_value[value_end:]


def _decode_base64_soft(value: str) -> bytes | None:
    try:
        return _decode_base64(value, where="bh=")
    except TagError:
        return None


def _tag_offset(raw_value: bytes, tag: str) -> int:
    """标签在原始头值里的起始偏移（``permerror`` 时定位用）。找不到 → 0。"""
    match = re.search(rb"(?:^|;)\s*" + tag.encode("ascii") + rb"\s*=", raw_value)
    return match.start() if match else 0


def _first_bad_offset(raw_value: bytes) -> int:
    """语法错的定位：第一个缺 ``=`` 的片段起点。找不到 → 0。"""
    cursor = 0
    for part in raw_value.split(b";"):
        if part.strip() and b"=" not in part:
            return cursor
        cursor += len(part) + 1
    return 0
