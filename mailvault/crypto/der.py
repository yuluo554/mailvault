"""最小 DER（ASN.1）解析：只为从 DKIM 的 ``p=`` 里取出 RSA 的 ``n`` / ``e``。

为什么自己写而不是引第三方：本项目的卖点之一是**运行时零第三方依赖**
（`plan/02` §4）。这里需要的能力只有"读 TLV"——20 行代码，换来发布件自足。

**两种编码都要能吃**（RFC 6376 §3.6.1 与实现现实）：

1. ``SubjectPublicKeyInfo``（RFC 5280 / X.509）::

       SEQUENCE {                      -- 0x30
         SEQUENCE {                      -- algorithmIdentifier
           OBJECT IDENTIFIER  rsaEncryption (1.2.840.113549.1.1.1)
           NULL                          -- 或省略
         }
         BIT STRING {                    -- 0x03，首字节是"未用位数"，恒为 0
           SEQUENCE { INTEGER n, INTEGER e }
         }
       }

2. 裸 ``RSAPublicKey``（RFC 8017 A.1.1）::

       SEQUENCE { INTEGER n, INTEGER e }

RFC 6376 原文说的是裸 ``RSAPublicKey``，但现实中绝大多数发布者发的是
``SubjectPublicKeyInfo``（openssl 默认导出的就是它，dkimpy 也两种都收）。
只认一种的解析器会在对端换工具时突然全部判 fail——**这种"看起来是签名坏了"
的故障最难查**，所以两种都实现，并在 ``trace`` 里写明吃的是哪一种。

解析严格：标签不对、长度越界、尾部有垃圾字节 → :class:`DerError`（调用方转
``key_status=invalid``，不抛到账本外面）。
"""

from __future__ import annotations

from dataclasses import dataclass

#: DER 标签字节。
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_NULL = 0x05
TAG_OBJECT_IDENTIFIER = 0x06
TAG_SEQUENCE = 0x30

#: ``rsaEncryption`` 的 OID 编码（1.2.840.113549.1.1.1），比字节更不容易看错。
OID_RSA_ENCRYPTION = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"

#: ``SubjectPublicKeyInfo`` 与裸 ``RSAPublicKey`` 的识别结果。
ENCODING_SPKI = "spki"
ENCODING_RSAPUBLICKEY = "rsapublickey"


class DerError(ValueError):
    """DER 结构不合法。**调用方必须把它当成"这条密钥不可用"，不得让异常穿透到账本。**"""


@dataclass(frozen=True)
class RsaPublicKey:
    """一个 RSA 公钥（只有验签需要的两个数）。"""

    n: int
    e: int
    encoding: str
    """``spki`` 或 ``rsapublickey``——写进 ``trace``，便于对端格式变化时定位。"""

    @property
    def bit_length(self) -> int:
        """模数位数。RFC 8301 §3.2 的判据就是它。"""
        return self.n.bit_length()

    @property
    def modulus_length(self) -> int:
        """模数的字节长度（向上取整）。PKCS#1 v1.5 的填充要按它算长度。"""
        return (self.n.bit_length() + 7) // 8


def parse_rsa_public_key(der: bytes) -> RsaPublicKey:
    """解析 ``p=`` 里的 DER，返回 :class:`RsaPublicKey`。

    先按 ``SubjectPublicKeyInfo`` 试，失败再按裸 ``RSAPublicKey``——顺序不能反：
    SPKI 的外层 SEQUENCE 里第一个元素也是 SEQUENCE，裸解析会先在"标签不是 INTEGER"
    处失败；而 SPKI 解析对裸 key 会在"算法 OID 缺失"处失败。两种顺序都能收敛，
    但先试 SPKI 能让 trace 里的 ``encoding`` 更符合现实分布。
    """
    if not isinstance(der, (bytes, bytearray)):
        raise DerError("DER 输入必须是 bytes，收到 %s" % type(der).__name__)
    data = bytes(der)
    if not data:
        raise DerError("p= 解出来是空字节（空 p= 表示密钥已撤销，不是可以解析的密钥）")

    errors: list[str] = []
    for encoding, parser in ((ENCODING_SPKI, _parse_spki), (ENCODING_RSAPUBLICKEY, _parse_pkcs1)):
        try:
            n, e = parser(data)
        except DerError as exc:
            errors.append("%s: %s" % (encoding, exc))
            continue
        if n <= 0 or e <= 0:
            raise DerError("RSA 公钥的 n/e 必须为正整数（n=%d, e=%d）" % (n.bit_length(), e))
        return RsaPublicKey(n=n, e=e, encoding=encoding)
    raise DerError("既不是 SubjectPublicKeyInfo 也不是 RSAPublicKey（%s）" % "；".join(errors))


# ── 两种结构 ────────────────────────────────────────────────────────────


def _parse_spki(data: bytes) -> tuple[int, int]:
    body, rest = _read_tlv(data, TAG_SEQUENCE, 0)
    if rest:
        raise DerError("外层 SEQUENCE 之后还有 %d 字节垃圾" % len(rest))

    algorithm, after_algorithm = _read_tlv(body, TAG_SEQUENCE, 0)
    oid, after_oid = _read_tlv(algorithm, TAG_OBJECT_IDENTIFIER, 0)
    if oid != OID_RSA_ENCRYPTION:
        raise DerError("算法 OID 不是 rsaEncryption（%s）" % oid.hex())
    if after_oid:
        # NULL 参数可以省略；出现了就必须是合法 NULL，且不该有其它尾巴。
        if after_oid[0] != TAG_NULL:
            raise DerError("算法参数不是 NULL（首字节 0x%02x）" % after_oid[0])
        _, leftover = _read_tlv(after_oid, TAG_NULL, 0)
        if leftover:
            raise DerError("算法参数之后还有 %d 字节垃圾" % len(leftover))

    bit_string, after_bit_string = _read_tlv(after_algorithm, TAG_BIT_STRING, 0)
    if after_bit_string:
        raise DerError("BIT STRING 之后还有 %d 字节垃圾" % len(after_bit_string))
    if not bit_string:
        raise DerError("BIT STRING 为空")
    unused = bit_string[0]
    if unused != 0:
        raise DerError("BIT STRING 的未用位数为 %d（密钥字节不该有未用位）" % unused)
    return _parse_pkcs1(bit_string[1:])


def _parse_pkcs1(data: bytes) -> tuple[int, int]:
    body, rest = _read_tlv(data, TAG_SEQUENCE, 0)
    if rest:
        raise DerError("RSAPublicKey 外层 SEQUENCE 之后还有 %d 字节垃圾" % len(rest))
    n_bytes, after_n = _read_tlv(body, TAG_INTEGER, 0)
    e_bytes, after_e = _read_tlv(after_n, TAG_INTEGER, 0)
    if after_e:
        raise DerError("RSAPublicKey 里除 n/e 之外还有 %d 字节" % len(after_e))
    return _int_from_der(n_bytes), _int_from_der(e_bytes)


# ── TLV ─────────────────────────────────────────────────────────────────


def _read_tlv(data: bytes, expected_tag: int, offset: int) -> tuple[bytes, bytes]:
    """读一个 TLV。返回 ``(内容, 该 TLV 之后的剩余字节)``。

    "剩余字节"而不是"下一个偏移"：少算一位在 DER 里是常态错误，
    让调用方显式处理剩余字节，比让它们自己算 ``offset + 2 + length`` 更难写错。
    """
    if offset >= len(data):
        raise DerError("偏移 %d 处已到末尾，期待标签 0x%02x" % (offset, expected_tag))
    tag = data[offset]
    if tag != expected_tag:
        raise DerError("偏移 %d 处标签是 0x%02x，期待 0x%02x" % (offset, tag, expected_tag))
    cursor = offset + 1

    if cursor >= len(data):
        raise DerError("标签 0x%02x 之后缺长度字节" % tag)
    first = data[cursor]
    cursor += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0:
            raise DerError("不定长编码（0x80）在 DER 里非法")
        if count > 4:
            raise DerError("长度字段 %d 字节，超出本解析器上限（密钥不会这么长）" % count)
        if cursor + count > len(data):
            raise DerError("长度字段越界")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        cursor += count
        if length < 0x80:
            # 非最短编码：BER 允许、DER 不允许。这里不判死（现实中确有实现这么发），
            # 但把长度照读——否则会切成半个密钥，症状更难查。
            pass

    end = cursor + length
    if end > len(data):
        raise DerError("声明长度 %d 超出剩余字节 %d" % (length, len(data) - cursor))
    return data[cursor:end], data[end:]


def _int_from_der(raw: bytes) -> int:
    if not raw:
        raise DerError("INTEGER 内容为空")
    value = int.from_bytes(raw, "big", signed=True)
    if value < 0:
        raise DerError("INTEGER 为负（DER 最高位是符号位；正整数前应补 0x00）")
    return value
