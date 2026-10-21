"""DNS 访问的**唯一出口**（M1 实现 `snapshot fetch`）。

为什么单独一个模块：题面 §7 的隐私红线是"审计阶段零网络"。光靠"我记得别联网"不算保证，
必须有一条能跑红的门。做法是把所有 socket 相关 import 收进本文件，
再用 `tools/check_no_network.py` 扫其余全部模块（AST 级）。

**时间豁免（全仓唯一）**：`fetched_at` 必须记录"这份快照是什么时候抓的"，这件事本质上
要读系统时钟。K7 的原意是"**判定**不许读时钟"，不是"抓取不许"。因此本文件是
`tools/check_no_clock.py` 里**唯一**登记的豁免文件，且豁免范围精确到
:func:`utc_now_z` 这一个函数——其它任何地方调用时钟仍然报红。
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .constants import (
    DNS_MAX_CNAME_HOPS,
    DNS_PORT,
    DNS_QCLASS_IN,
    DNS_RCODE_BY_VALUE,
    DNS_RCODE_TIMEOUT,
    DNS_TIMEOUT_SECONDS,
    DNS_TYPE_BY_NAME,
    SNAPSHOT_SCHEMA_VERSION,
)
from .exits import InputError
from .psl import default_psl
from .snapshot import RCODE_NOERROR, make_query

# 本文件之外的模块禁止出现以下 import（由 tools/check_no_network.py 断言）：
#   import socket / ssl / http.client / urllib.request / ftplib / telnetlib
#   from socket import ... 等

#: 头部标志位：RD（期望递归）。
_FLAG_RECURSION_DESIRED = 0x0100
#: 头部标志位：TC（响应被截断 → 必须换 TCP 重问）。
_FLAG_TRUNCATED = 0x0200


class DnsError(Exception):
    """查询本身失败（网络不可达 / 超时 / 响应畸形）。**不是** "没有记录"。"""


class DnsTimeout(DnsError):
    """查询超时 → 落盘为 ``rcode="TIMEOUT"``，绝不写成 NXDOMAIN。"""


# ── 时钟豁免（唯一） ────────────────────────────────────────────────────


def utc_now_z() -> str:
    """当前 UTC 时刻，``YYYY-MM-DDTHH:MM:SSZ`` 形态。

    **这是全仓唯一允许读系统时钟的地方**（见模块 docstring）。它只用于给快照盖时间戳，
    不参与任何判定；判定侧的时间一律来自快照里这个字段。
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── 顶层动作 ────────────────────────────────────────────────────────────


def fetch_snapshot(
    *,
    eml: str,
    query: str,
    resolver: str | None = None,
    psl_path: str | None = None,
    transport: "Transport | None" = None,
) -> dict[str, Any]:
    """抓取一份 DNS 快照并返回可序列化的字典。

    参数
    ----
    eml / query
        输入三件套里的两件；用来**推导要查哪些记录**（信封域、DMARC、DKIM 选择器、
        以及有界的 include / redirect 展开）。
    resolver
        ``ip:port`` 或裸 IP。``None`` → :data:`mailvault.constants.DNS_DEFAULT_RESOLVER`。
    psl_path
        自定义 PSL 冻结件路径（``--psl``）。``None`` → 随包冻结件。
    transport
        供测试注入的传输层（签名 ``(server, wire) -> bytes``）。默认走真实 UDP/TCP。
    """
    from .eml import load_eml
    from .query import load_query

    message = load_eml(eml)
    context = load_query(query)

    psl = default_psl() if psl_path is None else _load_psl_at(psl_path)

    server = _parse_resolver(resolver)
    client = transport or UdpTransport(server)

    plan = plan_queries(message=message, query=context, client=client)

    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "fetched_at": utc_now_z(),
        "resolver": resolver or server_label(server),
        "psl_version": psl.version,
        "psl_date": psl.date,
        "queries": plan,
    }


def plan_queries(*, message: Any, query: Any, client: "Transport") -> list[dict[str, Any]]:
    """推导查询清单并逐条执行。

    顺序即写入 ``queries`` 的顺序（`plan/03` §3.1：有序列表，同键可多次）。

    展开纪律：``include:`` / ``redirect=`` 只做**有界**展开（深度 ≤
    :data:`mailvault.constants.SPF_MAX_TERMS`），且同一 ``(qname, qtype)`` 只问一次——
    真实的递归解析器也会缓存。展开不全的部分不会被"补造"，M2 求值时该域若缺查询
    就按"数据缺口"处理（`plan/04` §2.3）。
    """
    queries: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def ask(qname: str, qtype: str) -> list[str]:
        key = (qname.lower().rstrip("."), qtype.upper())
        if key in seen:
            return []
        seen.add(key)
        try:
            answers, ttl, rcode = client.query(qname, qtype)
        except DnsTimeout:
            queries.append(make_query(qname=qname, qtype=qtype, rcode=DNS_RCODE_TIMEOUT))
            return []
        except DnsError as exc:
            queries.append(make_query(qname=qname, qtype=qtype, rcode="SERVFAIL"))
            queries[-1]["note"] = str(exc)
            return []
        queries.append(make_query(qname=qname, qtype=qtype, rcode=rcode, answer=answers, ttl=ttl))
        return answers if rcode == RCODE_NOERROR else []

    domain = query.sender_domain
    if domain:
        spf_records = _spf_records(ask(domain, "TXT"))
        _expand_spf(spf_records, ask, budget=10)
        ask("_dmarc." + domain, "TXT")

    for signature in message.dkim_signatures:
        selector, signing_domain = _dkim_selector_and_domain(signature)
        if selector and signing_domain:
            ask("%s._domainkey.%s" % (selector, signing_domain), "TXT")

    return queries


def _spf_records(answers: Iterable[str]) -> list[str]:
    return [item for item in answers if item.lower().startswith("v=spf1")]


def _expand_spf(records: list[str], ask: Callable[[str, str], list[str]], *, budget: int) -> None:
    """有界展开 include/redirect：只把**记录文本**取回来，求值留给 M2。"""
    if budget <= 0:
        return
    for record in records:
        for token in record.split()[1:]:
            target = None
            lowered = token.lower()
            if lowered.startswith("include:"):
                target = token.split(":", 1)[1]
            elif lowered.startswith("redirect="):
                target = token.split("=", 1)[1]
            if not target or _has_macro(target) or "/" in target:
                continue  # 宏展开需要 %{...} 上下文（M2）；带 CIDR 的 include 是语法错
            sub_records = _spf_records(ask(target.rstrip("."), "TXT"))
            _expand_spf(sub_records, ask, budget=budget - 1)


def _has_macro(token: str) -> bool:
    return "%{" in token or "%" in token


def _dkim_selector_and_domain(signature: str) -> tuple[str | None, str | None]:
    """从一条 ``DKIM-Signature`` 值里取 ``s=`` 与 ``d=``（RFC 6376 §3.5 的 tag-list）。"""
    tags: dict[str, str] = {}
    # 折行展开后的值里仍可能有多余空白；tag-list 用 `;` 分隔
    for part in signature.replace("\n", " ").split(";"):
        name, sep, value = part.partition("=")
        if sep:
            tags.setdefault(name.strip().lower(), value.strip())
    return tags.get("s"), tags.get("d")


def _load_psl_at(path: str) -> Any:
    """``--psl`` 覆盖：冻结件同目录下的 ``psl.meta.json`` 一并读取（校验和必须对得上）。"""
    from .psl import PSL_META_FILENAME, load_psl

    psl_path = Path(path)
    return load_psl(psl_path, psl_path.parent / PSL_META_FILENAME)


# ── 传输层 ──────────────────────────────────────────────────────────────


class Transport:
    """传输层接口。测试注入桩，生产走 :class:`UdpTransport`。"""

    def query(self, qname: str, qtype: str) -> tuple[list[str], int, str]:
        """返回 ``(answers, ttl, rcode)``。失败时抛 :class:`DnsError`。"""
        raise NotImplementedError


class UdpTransport(Transport):
    """UDP 查询；响应带 TC 标志时退化为 TCP（RFC 1035 §4.2.2）。"""

    def __init__(self, server: tuple[str, int],
                 *, timeout: float = DNS_TIMEOUT_SECONDS) -> None:
        self.server = server
        self.timeout = timeout

    def query(self, qname: str, qtype: str) -> tuple[list[str], int, str]:
        message_id = _message_id()
        wire = build_query(qname, qtype, message_id=message_id)
        try:
            response = self._udp(wire)
            if _flags(response) & _FLAG_TRUNCATED:
                response = self._tcp(wire)
        except socket.timeout:
            raise DnsTimeout("查询超时：%s/%s @ %s" % (qname, qtype, self.server)) from None
        except OSError as exc:
            raise DnsError("查询失败：%s/%s @ %s（%s）"
                           % (qname, qtype, self.server, exc)) from None
        return parse_response(response, expected_id=message_id)

    def _udp(self, wire: bytes) -> bytes:
        with socket.socket(socket.AF_INET6 if ":" in self.server[0] else socket.AF_INET,
                           socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(wire, self.server)
            data, _ = sock.recvfrom(65535)
            return data

    def _tcp(self, wire: bytes) -> bytes:
        with socket.create_connection(self.server, timeout=self.timeout) as sock:
            sock.sendall(struct.pack("!H", len(wire)) + wire)
            header = _recv_exact(sock, 2)
            length = struct.unpack("!H", header)[0]
            return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise DnsError("TCP 连接提前关闭（还差 %d 字节）" % remaining)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _message_id() -> int:
    """查询 id。

    用 ``random`` 而不是计数器：DNS id 只用于匹配请求与响应，不影响语义；
    但**不能**用可预测常量（跨查询复用容易被中间设备串错响应）。
    注意 ``random`` 不是"判定随机性"——判定路径（audit）根本不经过本文件。
    """
    return random.SystemRandom().randrange(0, 0x10000)


def _flags(response: bytes) -> int:
    if len(response) < 4:
        raise DnsError("DNS 响应过短（%d 字节）" % len(response))
    return struct.unpack("!H", response[2:4])[0]


# ── 报文编解码 ──────────────────────────────────────────────────────────


def build_query(qname: str, qtype: str, *, message_id: int = 0) -> bytes:
    """构造 DNS 查询报文（单问题、RD=1）。"""
    qtype_value = DNS_TYPE_BY_NAME.get(qtype.upper())
    if qtype_value is None:
        raise InputError("不支持的查询类型 %r（允许：%s）"
                         % (qtype, "、".join(sorted(DNS_TYPE_BY_NAME))))
    header = struct.pack("!HHHHHH", message_id, _FLAG_RECURSION_DESIRED, 1, 0, 0, 0)
    return header + encode_name(qname) + struct.pack("!HH", qtype_value, DNS_QCLASS_IN)


def encode_name(name: str) -> bytes:
    labels = [label for label in name.rstrip(".").split(".") if label]
    if not labels:
        raise InputError("查询名为空：%r" % (name,))
    out = bytearray()
    for label in labels:
        encoded = label.encode("idna") if not label.isascii() else label.encode("ascii")
        if len(encoded) > 63:
            raise InputError("DNS 标签超过 63 字节：%r" % (label,))
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def parse_response(response: bytes, *, expected_id: int | None = None) -> tuple[list[str], int, str]:
    """解析响应，返回 ``(answers, ttl, rcode)``。

    只取 **answer 段**（`plan/01` §4 的快照五字段就是"逐查询的 answer"）。
    CNAME 链由调用方按需再查（本函数把 CNAME 目标作为一条 answer 原样返回）。
    """
    if len(response) < 12:
        raise DnsError("DNS 响应过短（%d 字节）" % len(response))
    (message_id, flags, qdcount, ancount, _nscount, _arcount) = struct.unpack(
        "!HHHHHH", response[:12])
    if expected_id is not None and message_id != expected_id:
        raise DnsError("DNS 响应 id 不匹配（期望 %d，收到 %d）" % (expected_id, message_id))

    rcode = DNS_RCODE_BY_VALUE.get(flags & 0x000F, "RCODE%d" % (flags & 0x000F))
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(response, offset)
        offset += 4  # qtype + qclass

    answers: list[str] = []
    ttls: list[int] = []
    for _ in range(ancount):
        _name, offset = _read_name(response, offset)
        if offset + 10 > len(response):
            raise DnsError("DNS 响应在 answer 头处截断")
        rtype, _rclass, ttl, rdlength = struct.unpack("!HHIH", response[offset:offset + 10])
        offset += 10
        rdata = response[offset:offset + rdlength]
        if len(rdata) != rdlength:
            raise DnsError("DNS 响应 rdata 截断（声明 %d，实得 %d）" % (rdlength, len(rdata)))
        offset += rdlength
        value = _decode_rdata(response, rtype, rdata, offset - rdlength)
        if value is not None:
            answers.append(value)
            ttls.append(ttl)

    ttl = min(ttls) if ttls else 0
    return answers, ttl, rcode


def _decode_rdata(response: bytes, rtype: int, rdata: bytes, rdata_offset: int) -> str | None:
    if rtype == DNS_TYPE_BY_NAME["A"] and len(rdata) == 4:
        return str(ipaddress.IPv4Address(rdata))
    if rtype == DNS_TYPE_BY_NAME["AAAA"] and len(rdata) == 16:
        return str(ipaddress.IPv6Address(rdata))
    if rtype in (DNS_TYPE_BY_NAME["CNAME"], DNS_TYPE_BY_NAME["PTR"]):
        name, _ = _read_name(response, rdata_offset)
        return name
    if rtype == DNS_TYPE_BY_NAME["MX"] and len(rdata) >= 3:
        preference = struct.unpack("!H", rdata[:2])[0]
        exchange, _ = _read_name(response, rdata_offset + 2)
        return "%d %s" % (preference, exchange)
    if rtype == DNS_TYPE_BY_NAME["TXT"]:
        return _decode_txt(rdata)
    return None


def _decode_txt(rdata: bytes) -> str:
    """TXT 的 rdata 是若干 ``<len><bytes>``，逻辑值 = 各段直接拼接（RFC 7208 §3.3）。"""
    parts: list[str] = []
    index = 0
    while index < len(rdata):
        length = rdata[index]
        index += 1
        parts.append(rdata[index:index + length].decode("utf-8", "replace"))
        index += length
    return "".join(parts)


def _read_name(message: bytes, offset: int) -> tuple[str, int]:
    """读域名，支持 RFC 1035 §4.1.4 的压缩指针。"""
    labels: list[str] = []
    jumped = False
    cursor = offset
    hops = 0
    while True:
        if cursor >= len(message):
            raise DnsError("DNS 名字越过报文末尾")
        length = message[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise DnsError("DNS 压缩指针截断")
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if not jumped:
                offset = cursor + 2
                jumped = True
            cursor = pointer
            hops += 1
            if hops > DNS_MAX_CNAME_HOPS:
                raise DnsError("DNS 压缩指针成环（>%d 跳）" % DNS_MAX_CNAME_HOPS)
            continue
        if length == 0:
            if not jumped:
                offset = cursor + 1
            break
        start = cursor + 1
        end = start + length
        if end > len(message):
            raise DnsError("DNS 标签越过报文末尾")
        labels.append(message[start:end].decode("ascii", "replace"))
        cursor = end
    return ".".join(labels), offset


# ── resolver 解析 ───────────────────────────────────────────────────────


def _parse_resolver(resolver: str | None) -> tuple[str, int]:
    from .constants import DNS_DEFAULT_RESOLVER

    text = (resolver or DNS_DEFAULT_RESOLVER).strip()
    if not text:
        raise InputError("--resolver 为空")
    if text.startswith("["):  # [::1]:53
        host, _, rest = text[1:].partition("]")
        port = int(rest.lstrip(":") or DNS_PORT)
        return host, port
    if text.count(":") == 1:
        host, _, port_text = text.partition(":")
        return host, int(port_text or DNS_PORT)
    return text, DNS_PORT


def server_label(server: tuple[str, int]) -> str:
    host, port = server
    return host if port == DNS_PORT else "%s:%d" % (host, port)
