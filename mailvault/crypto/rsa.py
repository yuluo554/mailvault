"""零依赖 RSA 验签：PKCS#1 v1.5（RSASSA-PKCS1-v1_5，RFC 8017 §8.2）。

只做**验签**，不做签名、不做填充方案的其它模式。范围收窄到这一件事，是因为
DKIM 只需要它（RFC 6376 §3.3），而"零依赖"是发布件自足的前提（`plan/02` §4）。

验签三步（RFC 8017 §8.2.2）：

1. 把签名整数化：``s < n`` 且长度恰好等于模数字节数，否则直接判无效。
2. ``m = s^e mod n``（标准库 ``pow``，三参数形式自带模幂）。
3. 把 ``m`` 按模数长度写成字节，与 ``EM = 0x00 || 0x01 || PS || 0x00 || T`` 逐字节比较，
   其中 ``T`` 是 DigestInfo（DER：``SEQUENCE{OID, NULL}`` + ``OCTET STRING(摘要)``）。

**为什么第 3 步是逐字节比较，而不是"解出摘要再比"**：后者要自己写一个宽松的解析器，
而宽松解析正是 Bleichenbacher 类签名伪造的入口（填充里多塞几个字节也照样通过）。
逐字节比对一个预先编码好的期望值是严格的——多一个字节就失败。

**为什么返回诊断而不是布尔**：账本要能说清"是签名不对"还是"密钥/参数不对"。
但**对外只暴露** :func:`verify_pkcs1_v15` 的布尔语义 + :class:`SignatureMismatch` 的
原因分类，内部细节不外泄（避免把"填充差在哪"变成攻击者的调试信息）。
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from .der import RsaPublicKey

#: 摘要算法 → (hashlib 名字, DigestInfo 前缀)。
#:
#: DigestInfo 前缀来自 RFC 8017 §9.2 Note 1 的 ASN.1 编码，逐字节固定：
#: ``SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING }`` 的头与 OID 部分是常量，
#: 摘要本身接在后面。把它们写成字面量而不是"运行期拼 DER"，是为了让这串字节可以被
#: 人眼核对——它是整个验签的信任根。
DIGEST_INFO_PREFIX = {
    "sha1": (
        "sha1",
        bytes.fromhex("3021300906052b0e03021a05000414"),
    ),
    "sha256": (
        "sha256",
        bytes.fromhex("3031300d060960864801650304020105000420"),
    ),
}


class SignatureMismatch(Exception):
    """验签不通过。``reason`` 是给账本读的分类原因，不含可利用细节。"""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class VerifyOutcome:
    """验签结果。"""

    ok: bool
    reason: str = ""
    """``ok=False`` 时的分类原因（签名长度不符 / 模幂溢出 / 填充或摘要不符）。"""
    mod_bytes: int = 0
    """模数字节数。``key_bits`` 与它同源，便于对账。"""


def digest_info(hash_name: str, digest: bytes) -> bytes:
    """把摘要包成 PKCS#1 v1.5 的 ``T``。"""
    try:
        _, prefix = DIGEST_INFO_PREFIX[hash_name]
    except KeyError:
        raise ValueError("不支持的摘要算法：%r（允许 %s）"
                         % (hash_name, "、".join(sorted(DIGEST_INFO_PREFIX)))) from None
    return prefix + digest


def emsa_pkcs1_v15_encode(hash_name: str, digest: bytes, modulus_length: int) -> bytes:
    """构造期望的 ``EM``（RFC 8017 §9.2 step 2）。

    ``EM = 0x00 || 0x01 || PS(0xFF...) || 0x00 || T``，总长恰好 ``modulus_length``。

    可用的填充空间不足 → :class:`SignatureMismatch`：这表示**用这个密钥验这个摘要
    在数学上就不可能**（例如 512 位密钥配 SHA-256 只剩 0 字节余量）。
    这条不能判成"签名内容不对"，否则用户会去查报文而不是查密钥。
    """
    t = digest_info(hash_name, digest)
    padding_length = modulus_length - len(t) - 3
    if padding_length < 8:
        # RFC 8017 §9.2 要求 PS 至少 8 字节。
        raise SignatureMismatch(
            "密钥太小：%d 字节模数装不下 %s 的 DigestInfo（需 ≥ %d 字节）"
            % (modulus_length, hash_name, len(t) + 11))
    return b"\x00\x01" + b"\xff" * padding_length + b"\x00" + t


def verify_pkcs1_v15(key: RsaPublicKey, signature: bytes, *, hash_name: str,
                     digest: bytes) -> VerifyOutcome:
    """验一个 PKCS#1 v1.5 签名。

    ``signature`` 是 ``b=`` 解 base64 之后的**原始字节**；``digest`` 是待验摘要的原始字节。
    """
    if not isinstance(signature, (bytes, bytearray)):
        return VerifyOutcome(False, "签名不是字节串", key.modulus_length)
    signature = bytes(signature)
    mod_bytes = key.modulus_length

    if len(signature) != mod_bytes:
        # RFC 8017 §8.2.2 step 1：长度必须等于模数长度。差一位就是不同密钥/不同编码，
        # 提前区分出来，避免用户拿到"填充不符"这种误导性原因。
        return VerifyOutcome(
            False, "签名长度 %d ≠ 模数长度 %d" % (len(signature), mod_bytes), mod_bytes)

    s = int.from_bytes(signature, "big")
    if s >= key.n:
        return VerifyOutcome(False, "签名整数 ≥ 模数（非法值）", mod_bytes)

    try:
        expected = emsa_pkcs1_v15_encode(hash_name, digest, mod_bytes)
    except SignatureMismatch as exc:
        return VerifyOutcome(False, exc.reason, mod_bytes)

    em = pow(s, key.e, key.n).to_bytes(mod_bytes, "big")
    # 定长比较：既避免提前返回泄露差异位置，也省得自己写循环。
    if hmac.compare_digest(em, expected):
        return VerifyOutcome(True, "", mod_bytes)
    return VerifyOutcome(False, "填充或摘要不符（签名与报文/密钥不匹配）", mod_bytes)
