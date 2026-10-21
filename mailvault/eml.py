"""`.eml` 解析：headers（**保序、保留重复头**） / body / 多 `DKIM-Signature`（M1）。

为什么自己写而不用 :mod:`email`：本题要断言的正是"同一个头出现多次时逐条处理"。
``email.message.Message.get_all()`` 虽然也能取到重复头，但它同时会做
（a）头名大小写归一、（b）折行展开、（c）某些情况下的 RFC 2047 解码。
对一个**以字节为被测对象**的 DKIM 验签器（RFC 6376 §3.4 规范化）来说，
"解析器替我改了什么"是最难查的一类错误。这里只做最小解析：

- 头区 → ``headers``：``[(name, value), ...]``，**物理顺序**，重复头各占一条。
- 折行（``CRLF`` 后接空格/制表）按 RFC 5322 §2.2.3 展开：续行原样拼上（保留折行处的前导空白，
  因为 DKIM 的 ``b=``/``bh=`` 计算需要的是"折行展开后的值"，而 header 规范化会再处理空白）。
- 空行之后到文件末尾 → ``body``：**原始字节**，一个字节都不改。
- ``body`` 单独再提供 ``body_text``（UTF-8 宽松解码）给人读输出用。

多签名：``DKIM-Signature`` 全部条目按出现顺序返回，**不去重、不短路**（`plan/03` §3.3）。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Iterator

from .exits import InputError

#: 头区与 body 的分隔：空行（允许 ``\r\n`` 或裸 ``\n``）。
_HEADER_END = b"\r\n\r\n"
_HEADER_END_LF = b"\n\n"


@dataclass(frozen=True)
class Header:
    """一个头字段。``value`` 是**未做 DKIM 规范化**的展开值。"""

    name: str
    value: str

    @property
    def lower_name(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Message:
    """解析后的报文。"""

    headers: tuple[Header, ...]
    body: bytes
    raw_head: bytes

    # ── 取头 ───────────────────────────────────────────────────────────
    def get_all(self, name: str) -> list[str]:
        """按 **物理顺序** 返回同名头的全部值（重复头不去重）。"""
        lowered = name.lower()
        return [header.value for header in self.headers if header.lower_name == lowered]

    def get(self, name: str, default: str | None = None) -> str | None:
        """取**第一个**同名头（与 :meth:`get_all` 的首元素一致）。"""
        values = self.get_all(name)
        return values[0] if values else default

    def header_names(self) -> list[str]:
        """头名按出现顺序（**保留重复**，不折叠）。"""
        return [header.name for header in self.headers]

    # ── 签名 ───────────────────────────────────────────────────────────
    @property
    def dkim_signatures(self) -> list[str]:
        """全部 `DKIM-Signature` 头的值，按出现顺序；一个都没有 → ``[]``。"""
        return self.get_all("DKIM-Signature")

    def header_fields(self) -> list[tuple[bytes, bytes]]:
        """按**物理顺序**返回 ``(name_bytes, value_bytes)``，供 DKIM 逐字节规范化。

        :class:`Header` 是给人读的（折行展开成 ``\\n``、冒号后的前导空白已 strip），
        **不足以**做 RFC 6376 §3.4 的规范化——simple 规范化要求"一个字节都不改"，
        而 ``Header.value`` 已经改过。所以另开一条**面向字节**的读取路径。

        语义：

        - ``name_bytes``：冒号**之前**的原始字节（保留大小写与尾部空白）。
        - ``value_bytes``：冒号之后到字段结束（不含终止 CRLF）的原始字节，
          **保留折行**（含折行处的 CRLF 与前导 WSP）。
        - 字段之间**不**带终止符；调用方按需自己补 ``b"\\r\\n"``。
        - 行终止符统一为 CRLF：裸 ``\\n`` 输入按 RFC 5322 的规范形态归一
          （与参照实现 ``dkimpy`` 的 ``rfc822_parse`` 同一口径）。

        输入形态不合法（头部行缺冒号）→ :class:`InputError`，与 :func:`parse` 一致。
        """
        return _raw_header_fields(self.raw_head, source="<raw_head>")

    @property
    def body_text(self) -> str:
        """body 的 UTF-8 宽松解码（仅供人读输出；判定用 :attr:`body` 的原始字节）。"""
        return self.body.decode("utf-8", "replace")

    @property
    def body_crlf(self) -> bytes:
        """DKIM 规范化用的正文形态：**行终止符统一为 CRLF**。

        为什么不能直接用 :attr:`body`：RFC 6376 §3.4 的两种正文规范化都以 CRLF 为行界。
        报文在传输中可能被改成裸 LF（非 SMTP 通道），此时"按字节算"会把整段正文
        当成一行，``bh`` 必然不符——而故障现象看起来像是"签名坏了"。

        归一口径与参照实现 ``dkimpy`` 的 ``rfc822_parse`` **逐字对齐**：按 ``\\r?\\n``
        切行、再用 ``\\r\\n`` 拼回。**只动行终止符**，不动行内任何字节。
        """
        return _crlf_normalize(self.body)

    @property
    def body_sha256(self) -> str:
        import hashlib

        return hashlib.sha256(self.body).hexdigest()


def load_eml(path: str | Path) -> Message:
    """读报文文件。文件缺失/不可读 → :class:`InputError`（exit 3）。"""
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        raise InputError("报文文件不存在：%s" % path) from None
    except OSError as exc:
        raise InputError("报文文件不可读：%s（%s）" % (path, exc)) from None
    return parse(raw, source=str(path))


def parse(raw: bytes, *, source: str = "<bytes>") -> Message:
    """从原始字节解析报文。

    无头区（文件以空行开头）是合法的：得到空 ``headers`` 与整段 body。
    没有空行 → 整个文件都是头区，``body`` 为空（RFC 5322 允许无 body 的报文）。
    """
    if not isinstance(raw, bytes):
        raise InternalTypeError(source, type(raw).__name__)

    head, body = _split_head_body(raw)
    headers = tuple(_parse_headers(head, source=source))
    return Message(headers=headers, body=body, raw_head=head)


class InternalTypeError(TypeError):
    """``parse()`` 只接受 bytes——传 str 会让"字节级可比"悄悄失效。"""

    def __init__(self, source: str, got: str) -> None:
        super().__init__("%s：parse() 只接受 bytes，收到 %s（字符串会丢失原始编码）"
                         % (source, got))


def _split_head_body(raw: bytes) -> tuple[bytes, bytes]:
    index = raw.find(_HEADER_END)
    if index >= 0:
        return raw[:index], raw[index + len(_HEADER_END):]
    index = raw.find(_HEADER_END_LF)
    if index >= 0:
        return raw[:index], raw[index + len(_HEADER_END_LF):]
    # 裸 \r\n\r\n 之外还有 `\n\r\n` 之类混排：退化为按首个空行切。
    for marker in (b"\r\n\n", b"\n\r\n"):
        index = raw.find(marker)
        if index >= 0:
            return raw[:index], raw[index + len(marker):]
    return raw, b""


def _parse_headers(head: bytes, *, source: str) -> Iterator[Header]:
    """按物理顺序切头，折行展开。"""
    text = head.decode("utf-8", "replace")
    if not text:
        return
    current_name: str | None = None
    current_value: list[str] = []

    def flush() -> Header | None:
        if current_name is None:
            return None
        return Header(name=current_name, value="".join(current_value))

    for line in text.split("\n"):
        line = line.rstrip("\r")
        if not line:
            continue
        if line[:1] in (" ", "\t") and current_name is not None:
            # RFC 5322 §2.2.3 折行：续行原样拼上（保留前导空白，DKIM 规范化时再处理）
            current_value.append("\n" + line)
            continue
        if ":" not in line:
            # 无冒号且不在续行位置 → 不是合法头。报出来，不静默丢弃。
            raise InputError("%s：头部行缺冒号：%r" % (source, line[:80]))
        header = flush()
        if header is not None:
            yield header
        name, _, value = line.partition(":")
        current_name = name.strip()
        current_value = [value.strip()]

    header = flush()
    if header is not None:
        yield header


def _raw_header_fields(head: bytes, *, source: str) -> list[tuple[bytes, bytes]]:
    """把头部区切成 ``(name_bytes, value_bytes)``，**字节级保真**。

    `simple` 头部规范化（RFC 6376 §3.4.1）要求"头字段必须原样呈现给算法"——
    名字不得改大小写、空白不得改。所以这条路不能复用 :func:`_parse_headers`
    （它把值 strip 过、折行改成了 ``\\n``）。

    行切分口径与参照实现 ``dkimpy`` 的 ``rfc822_parse`` **逐字对齐**：按 ``\\r?\\n`` 切行
    （孤立 ``\\r`` 保留在行内），字段之间不再带终止符，由调用方按需补 ``\\r\\n``。
    折行按 RFC 5322 §2.2.3：续行（行首 WSP）属于上一个字段的值，**保留**折行本身——
    relaxed 规范化要先展开再压空白，simple 规范化则原样保留。
    """
    if not head:
        return []
    lines = re.split(rb"\r?\n", head)
    if lines and not lines[-1]:
        lines.pop()  # 尾部若因切分留下空元素（头部区以换行结尾），不是字段

    fields: list[tuple[bytes, bytes]] = []
    name = b""
    value_parts: list[bytes] = []
    started = False

    def flush_field() -> None:
        if started:
            fields.append((name, b"\r\n".join(value_parts)))

    for line in lines:
        if line[:1] in (b" ", b"\t"):
            if not started:
                raise InputError("%s：头部首行就是折行续行（缺字段名）" % source)
            value_parts.append(line)
            continue
        if b":" not in line:
            raise InputError("%s：头部行缺冒号：%r" % (source, line[:80]))
        flush_field()
        raw_name, _, raw_value = line.partition(b":")
        name = raw_name
        value_parts = [raw_value]
        started = True

    flush_field()
    return fields


def _crlf_normalize(data: bytes) -> bytes:
    """把行终止符统一成 CRLF，口径与 ``dkimpy.rfc822_parse`` 一致（按 ``\\r?\\n`` 切行）。

    只动行终止符：孤立 ``\\r`` **不**当换行（与参照实现一致），行内字节原样保留。
    """
    return b"\r\n".join(re.split(rb"\r?\n", data))
