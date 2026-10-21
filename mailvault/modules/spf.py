"""SPF 求值器（RFC 7208 §4–§7）：确定性、可复算、预算逐格可读。

本模块是 M2 的交付面。四条设计约束，每条都对应一处"看起来能跑但会骗人"的写法：

1. **只从 `Snapshot` 取值**。求值器不认识网络，也**不把"快照里没查过"当成"没有记录"**
   （`plan/04` §2.3）：``found=False`` 一律记数据缺口 → ``undecidable``，绝不落到 ``none``。
   这条是 `plan/04` 明文禁止的坑——把"没抓"读成"没有"，会让整份账本静默变成假绿。
2. **先校验、后求值**（RFC 7208 §4.6）。任何位置的语法错误都必须是 ``permerror``，
   即使前面某个机制已经匹配（上游用例 `detect-errors-anywhere` 锁的就是这条）。
3. **超限不抛异常**（`plan/03` §3.2）。:class:`Budget` 只记账并置 ``limit_hit``，
   由求值层决定后果：term / MX 超限 → ``permerror``（RFC 7208 §4.6.4 MUST），
   void 超限 → ``undecidable`` + 告警（本项目口径，见下）。
4. **include 树完整展开**。不因第 11 个 term 而截断树：被截断的树会把"后面还有 12 个
   include"整件事藏起来（checkdmarc #172 的用户诉求正是这个）。超限节点照样进树、
   照样带记录文本，只是标 ``receiver_would_stop_here`` 且不再向下求值。

**三处与 RFC 字面表述的差异，均为有意为之并逐条登记**（`data/rfc7208-failures.md`）：

- **void 超限**：RFC 7208 §4.6.4 的后果写作 ``permerror``；本项目按题面 §2.5 灰区 2
  （该限制本身是 SHOULD）判 ``undecidable`` + 告警。理由：SHOULD 级限制被突破时，
  "记录本身有错"与"实现选择更严格"无法区分，硬判 permerror 会把实现口径冒充成协议结论。
- **PTR 超限**：RFC 7208 §4.6.4 原文是"超出前 10 条 MUST 被忽略"（不是 permerror），
  §5.5 补充此时机制按未匹配处理。本模块照此实现（截断 + 不匹配）。上游用例
  `ptr-limit` 期望 ``neutral``/``pass`` 亦佐证截断语义。
- **``%{p}`` 缺 PTR**：§7.3 的规范行为是展开成 ``unknown``（**不是** fail）。本项目
  在此基础上再进一步：若最终结果是由含 ``%{p}`` 的机制**匹配**决定的，则降级为
  ``undecidable`` 并写明原因（题面 §2.5 灰区 4）。只做诊断的 ``%{p}``
  （如 ``exp=`` 文本、未匹配的机制）不触发降级。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable

from ..constants import (
    SPF_MAX_DEPTH,
    SPF_MAX_MX,
    SPF_MAX_PTR,
    SPF_MAX_TERMS,
    SPF_MAX_VOID,
    SPF_MAX_VOID_LIMIT_KIND,
    SPF_TREE_MAX_NODES,
)
from ..exits import InputError
from ..ledger import check_entry
from ..snapshot import Snapshot

# ── 条款号（`evidence_ref` 的唯一来源；格式见 `docs/ledger-format.md` §2.2） ──
REF_INITIAL = "RFC7208#4.3"
REF_RESULTS = "RFC7208#2.6"
REF_SELECT = "RFC7208#4.5"
REF_SYNTAX = "RFC7208#4.6.1"
REF_QUALIFIER = "RFC7208#4.6.2"
REF_DEFAULT = "RFC7208#4.7"
REF_LIMITS = "RFC7208#4.6.4"
REF_INCLUDE = "RFC7208#5.2"
REF_REDIRECT = "RFC7208#6.1"
REF_EXP = "RFC7208#6.2"
REF_MACRO = "RFC7208#7.1"

#: 机制 → 它自己的条款节。判定命中哪个机制就挂哪一节——
#: 只挂一个笼统的 §4.6.4 会让读者无法核对"到底是哪条规则判的"。
_REF_BY_MECHANISM = {
    "all": "RFC7208#5.1",
    "include": REF_INCLUDE,
    "a": "RFC7208#5.3",
    "mx": "RFC7208#5.4",
    "ptr": "RFC7208#5.5",
    "ip4": "RFC7208#5.6",
    "ip6": "RFC7208#5.6",
    "exists": "RFC7208#5.7",
}

# ── 语法（与 RFC 7208 §12 ABNF 一一对应） ────────────────────────────────
#: 记录必须以 ``v=spf1`` 开头，且其后必须是空格或串尾（§4.5/4）。
_RE_SPF = re.compile(r"^v=spf1$|^v=spf1 ", re.IGNORECASE)
#: 修饰符：``name "=" macro-string``，name 以字母开头（§12）。
_RE_MODIFIER = re.compile(r"^([a-z][a-z0-9_\-.]*)=", re.IGNORECASE)
_RE_DUAL_CIDR = re.compile(r"//(0|[1-9]\d*)$")
_RE_CIDR = re.compile(r"/(0|[1-9]\d*)$")

_PAT_IP4 = r"\.".join([r"(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])"] * 4)
_RE_IP4 = re.compile(_PAT_IP4 + r"$")

#: 宏字符：``%%`` / ``%_`` / ``%-`` / ``%{...}``。
_PAT_CHAR = r"%(%|_|-|(\{[^\}]*\}))"
_RE_CHAR = re.compile(_PAT_CHAR)
#: ``%`` 后面不是 ``{`` / ``%`` / ``-`` / ``_`` → 语法错（§7.1/9）。
_RE_INVALID_MACRO = re.compile(r"(?<!%)%[^{%_-]|%$")
#: 宏的变换参数：``[数字][r][分隔符集]``（§7.1/15–18）。
_RE_ARGS = re.compile(r"([0-9]*)(r?)([^0-9a-zA-Z]*)")

#: domain-spec 的 toplabel 判据（§7.1/2）：必须以合法 toplabel 或宏结尾。
_RE_TOPLAB = re.compile(
    r"\.(?:[0-9a-z]*[a-z][0-9a-z]*|[0-9a-z]+-[0-9a-z-]*[0-9a-z])\.?$|%s" % _PAT_CHAR,
    re.IGNORECASE,
)

#: 限定符 → 结果（§4.6.1）。
_QUALIFIERS = {"+": "pass", "-": "fail", "?": "neutral", "~": "softfail"}

#: 机制白名单（§5）。``all`` 之外的机制都计 term。
_MECHANISMS = ("a", "mx", "ptr", "exists", "include", "ip4", "ip6", "all")
_TERM_MECHANISMS = ("a", "mx", "ptr", "exists", "include")

#: 常见拼写错误：严格口径下仍是 permerror，只是理由更具体。
_COMMON_MISTAKES = {"prt": "ptr", "ip": "ip4", "ipv4": "ip4", "ipv6": "ip6", "all.": "all"}

#: 宏里可用的字母（§7.1）。``c``/``r``/``t`` 只许出现在 exp 文本里（§7.1/8）。
_MACRO_LETTERS = "slodipvhcrt"
_EXP_ONLY_LETTERS = "crt"

#: ``l`` / ``s`` 的分隔符在展开时替换成 ``.``（§7.1/15）。
_JOINERS = {"l": ".", "s": "."}

#: URL 转义的安全集（RFC 3986 unreserved + ``/``，与参照实现同集）。
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/")

#: 域名最大长度（§7.1/25）。
_MAX_NAME_LENGTH = 253


# ── 内部异常：把 RFC 的三类终态从递归里穿出来 ────────────────────────────


class _TempError(Exception):
    """DNS 层临时故障 → ``temperror``（§2.6.1）。"""


class _PermError(Exception):
    """记录本身有问题 → ``permerror``（§2.6.2）。"""


class _Undecidable(Exception):
    """数据不足或灰区 → ``undecidable``（本项目语义，不折叠成 fail）。"""


class DataGap(_Undecidable):
    """快照里**没有这条查询**（不是"查过但没有"）。

    单独成类，是因为调用方需要能把它与"灰区"区分开：灰区要如实报给用户，
    数据缺口则应该去补抓（`snapshot fetch`）或补夹具，而不是当成结论。
    """

    def __init__(self, qname: str, qtype: str) -> None:
        self.qname = qname
        self.qtype = qtype
        super().__init__(
            "快照里没有 %s/%s 这条查询（数据缺口，不等同于『没有记录』）"
            % (qname, qtype))


# ── 预算账本 ────────────────────────────────────────────────────────────


class Budget:
    """逐格消耗账本（`docs/ledger-format.md` §3）。

    **超限不抛异常**：只置 :attr:`limit_hit` 并记下 :attr:`hits`，后果由求值层决定。
    "记账"与"处置"分开，同一份账本才能同时服务严格口径与诊断口径。
    """

    def __init__(self) -> None:
        self.cells: dict[str, dict[str, Any]] = {
            "terms": {"used": 0, "limit": SPF_MAX_TERMS, "ref": REF_LIMITS},
            "mx": {"used": 0, "limit": SPF_MAX_MX, "ref": REF_LIMITS},
            "ptr": {"used": 0, "limit": SPF_MAX_PTR, "ref": REF_LIMITS},
            "void": {"used": 0, "limit": SPF_MAX_VOID, "ref": REF_LIMITS,
                     "limit_kind": SPF_MAX_VOID_LIMIT_KIND},
            "depth": {"used": 0, "limit": SPF_MAX_DEPTH, "ref": REF_INCLUDE},
        }
        #: 每一次消耗的明细：``(kind, node_id, ref)``（题面 M2 输出要求）。
        self.entries: list[dict[str, Any]] = []
        self.limit_hit = False
        self.hits: list[str] = []

    # ── 消耗 ───────────────────────────────────────────────────────────
    def consume(self, kind: str, node_id: str, *, ref: str | None = None) -> bool:
        """记一格。返回**是否仍在限内**（False = 这一格已超限）。"""
        cell = self.cells[kind]
        cell["used"] += 1
        self.entries.append({
            "kind": kind, "node_id": node_id, "used": cell["used"],
            "ref": ref or cell["ref"],
        })
        return self._within(kind)

    def observe(self, kind: str, count: int, node_id: str, *,
                ref: str | None = None) -> bool:
        """按**观测值**记一格（MX / PTR 是"本次返回几条"，不是"调了几次"）。"""
        cell = self.cells[kind]
        cell["used"] = max(cell["used"], int(count))
        self.entries.append({
            "kind": kind, "node_id": node_id, "used": cell["used"],
            "ref": ref or cell["ref"],
        })
        return self._within(kind)

    def _within(self, kind: str) -> bool:
        cell = self.cells[kind]
        limit = cell["limit"]
        if limit is None or cell["used"] <= limit:
            return True
        self.limit_hit = True
        if kind not in self.hits:
            self.hits.append(kind)
        return False

    # ── 读出 ───────────────────────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        """账本里的 ``budget`` 块：逐格 ``used`` / ``limit`` / ``ref``。"""
        return {kind: dict(cell) for kind, cell in self.cells.items()}


# ── 判定结果 ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SpfResult:
    """一次 ``check_host()`` 的完整结论。

    ``result`` 取 :data:`mailvault.constants.RESULTS` 里的值；``undecidable`` 是一等结果，
    不会被折叠成 ``fail``（K4）。
    """

    result: str
    reason: str
    domain: str
    record: str | None
    evidence_ref: tuple[str, ...]
    trace: tuple[dict[str, Any], ...]
    budget: dict[str, Any]
    budget_entries: tuple[dict[str, Any], ...]
    tree: dict[str, Any] | None
    warnings: tuple[str, ...]
    gray_areas: tuple[str, ...]
    limit_hit: bool
    limit_hits: tuple[str, ...]
    cut_point: dict[str, Any] | None
    mechanism: str | None
    explanations: tuple[dict[str, Any], ...] = ()
    data_gap: tuple[str, str] | None = None
    """数据缺口：``(qname, qtype)``。非空表示"快照里没查过"，**不是**"没有记录"。

    它与 ``undecidable`` 是两件事，必须分开：
    ``undecidable`` 是结论（灰区/数据不足，如实报给用户）；
    ``data_gap`` 是**待补的输入**（`snapshot fetch` 该抓而没抓的键）。
    把两者混为一谈，用户就分不清"该去补抓"还是"本来就判不了"。
    """

    def to_check_entry(self, *, check_id: str = "spf.check_host", module: str = "M2",
                       subject: dict[str, Any] | None = None) -> dict[str, Any]:
        """转成账本 ``checks[]`` 条目（`docs/ledger-format.md` §2）。

        ``evidence_ref`` 由本模块给出；为空时 ``ledger.check_entry`` 会把它降级成
        ``undecidable``——这里不做第二次判定，避免两处口径。
        """
        return check_entry(
            check_id=check_id,
            module=module,
            subject=subject or {"domain": self.domain, "scope": "mail_from"},
            result=self.result,
            reason=self.reason,
            evidence_ref=list(self.evidence_ref),
            trace=list(self.trace),
            budget=self.budget,
            warnings=list(self.warnings) + list(self.gray_areas),
            tree=self.tree,
        )


# ── DNS 读取（唯一入口：快照） ───────────────────────────────────────────


@dataclass(frozen=True)
class _Lookup:
    """一次快照查询的求值侧视图。"""

    status: str  #: ok / empty / nxdomain
    answers: tuple[str, ...] = ()
    note: str = ""

    @property
    def is_void(self) -> bool:
        return self.status in ("empty", "nxdomain")


def _normalize_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


def _name_is_queryable(name: str) -> bool:
    """DNS 名字是否可查（§4.3/1 的机制侧版本）。

    判据只有两条，与参照实现 `query.dns()` 一致：**每个标签非空且不超过 63 字节**。
    刻意**不**限制字符集——上游测试集里有 `a:foo:bar/baz.example.com` 这类
    "含冒号/斜杠但确实能查到"的用例（`a-colon-domain`），按字符集拦会把它们判错。
    字符集不合法的名字自然查不到，走 NXDOMAIN 那条路即可。

    名字不合法时返回 False，调用方按"查过、不存在"处理，**不计 void**：
    这不是一次真实的 DNS 查询。
    """
    if not name:
        return False
    return all(label and len(label) <= 63 for label in name.split("."))


# ── 求值上下文 ──────────────────────────────────────────────────────────


class _Ctx:
    """一次 ``check_host()`` 的全部可变状态。

    单独成类，是为了让"预算 / 缓存 / 宏变量"只有一份——递归时靠参数传递会串味。
    """

    def __init__(self, snap: Snapshot, ip: str, helo: str | None, *,
                 budget: Budget, trace: list[dict[str, Any]],
                 local: str | None = None, sender: str | None = None,
                 receiver: str | None = None) -> None:
        try:
            address = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            raise InputError("client_ip 不是合法 IP：%r" % (ip,)) from None
        # IPv4-mapped IPv6 必须当 IPv4 处理（§5/9/2；上游用例 ip4-mapped-ip6）。
        if address.version == 6 and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        self.ip = address
        if address.version == 4:
            self.v = "in-addr"
            self.a_qtype = "A"
            self.cidrmax = 32
            self.i = str(address)
        else:
            self.v = "ip6"
            self.a_qtype = "AAAA"
            self.cidrmax = 128
            self.i = ".".join(address.exploded.replace(":", "").upper())

        self.snap = snap
        self.budget = budget
        self.trace = trace
        self.h = helo if helo else "unknown"
        self.r = receiver or "unknown"
        self.c = str(address)

        if sender is not None:
            self.s = sender
            local_part, _, sender_domain = sender.partition("@")
            self.l = local_part or "postmaster"
            self.o = sender_domain or ""
        else:
            self.l = local or "postmaster"
            self.o = ""
            self.s = ("%s@%s" % (self.l, self.o)) if self.o else self.l

        #: 当前被求值的域（宏 ``%{d}``）；递归时逐层改写，退出时还原。
        self.d = ""
        #: 缓存只存**非空**结果——与参照实现一致：空结果每次都重新计 void。
        self._cache: dict[tuple[str, str], _Lookup] = {}
        self._ptr_cache: tuple[str, ...] | None = None
        #: ``%{p}`` 灰区：PTR 缺失时置位；只有"由 %{p} 机制决定结果"才降级。
        self.p_unavailable = False
        self.p_decided = False
        #: void 超限：只置位不抛，由求值结束处统一裁决（见 `_count_void`）。
        self.void_exceeded = False
        self.void_note = ""
        self.warnings: list[str] = []
        self.gray: list[str] = []
        self.explanations: list[dict[str, Any]] = []

    # ── 查询 ───────────────────────────────────────────────────────────
    def lookup(self, name: str, qtype: str, *, node_id: str,
               ignore_void: bool = False) -> _Lookup:
        """读快照。**唯一**取值入口——没有第二条路能绕过"缺口 ≠ 不存在"。"""
        qname = _normalize_name(name)
        qtype = qtype.upper()
        if not _name_is_queryable(qname):
            # 不可查的名字按"查过、不存在"处理，且**不计 void**（§4.3/1：这不算一次查询）。
            # 关键：这里返回 empty 而不是抛 DataGap——名字本身非法是**协议结论**
            # （上游 invalid-hello-macro 期望 fail），不是"夹具没抓"。
            self.trace.append({
                "node": node_id,
                "note": "%s/%s 名字不可查（非法域名），按不存在处理" % (qname, qtype)})
            return _Lookup("empty", (), "名字不可查（非法域名）")

        cached = self._cache.get((qname, qtype))
        if cached is not None:
            return cached

        resolved = self.snap.resolve(qname, qtype)
        if not resolved.found:
            raise DataGap(qname, qtype)
        rcode = (resolved.rcode or "").upper()
        if rcode == "TIMEOUT":
            raise _TempError("查询超时：%s/%s" % (qname, qtype))
        if rcode == "NXDOMAIN":
            lookup = _Lookup("nxdomain", (), "NXDOMAIN")
        elif rcode != "NOERROR":
            raise _TempError("查询失败：%s/%s → rcode=%s" % (qname, qtype, rcode))
        elif resolved.answer:
            lookup = _Lookup("ok", tuple(resolved.answer))
            self._cache[(qname, qtype)] = lookup
        else:
            lookup = _Lookup("empty", (), "NOERROR 但无记录")

        self.trace.append({"node": node_id, "note": resolved.trace_note()})
        if lookup.is_void and not ignore_void:
            self._count_void(node_id, "%s/%s" % (qname, qtype))
        return lookup

    def _count_void(self, node_id: str, what: str) -> None:
        if self.budget.consume("void", node_id, ref=REF_LIMITS):
            return
        # 项目口径（题面 §2.5 灰区 2）：void 上限是 SHOULD，突破不硬判 permerror。
        # **但也不立刻停**：同一条记录若同时踩了 MUST 级限制（term / MX），报 MUST 更站得住
        # ——那条记录无论实现怎么选都是坏的。因此这里只置位，由 `check_host` 统一裁决。
        if not self.void_exceeded:
            self.void_exceeded = True
            self.void_note = what

    def spf_record(self, domain: str, *, node_id: str) -> str | None:
        """取一个域的 SPF 记录（§4.5）。``None`` 表示"查过、没有"。"""
        lookup = self.lookup(domain, "TXT", node_id=node_id)
        candidates = [text for text in lookup.answers if _RE_SPF.match(text)]
        if len(candidates) > 1:
            raise _PermError(
                "%s 有 %d 条 v=spf1 TXT 记录（RFC 7208 §4.5/6：多条即 permerror）"
                % (domain, len(candidates)))
        if not candidates:
            return None
        record = candidates[0]
        if not record.isascii():
            raise _PermError(
                "%s 的 SPF 记录含非 ASCII 字符（RFC 7208 §3.1：策略只许 7-bit ASCII）"
                % domain)
        return record

    def dns_a(self, name: str, *, node_id: str) -> tuple[str, ...]:
        return self.lookup(name, self.a_qtype, node_id=node_id).answers

    def dns_mx(self, domain: str, *, node_id: str) -> tuple[str, ...]:
        """MX 机制的地址集合（§5.4）。超过 10 条 MX 记录 → permerror。"""
        answers = self.lookup(domain, "MX", node_id=node_id).answers
        within = self.budget.observe("mx", len(answers), node_id)
        if len(answers) > SPF_MAX_MX or not within:
            raise _PermError(
                "%s 返回 %d 条 MX 记录，超过 %d 条上限（RFC 7208 §4.6.4 MUST）"
                % (domain, len(answers), SPF_MAX_MX))
        exchanges: list[tuple[int, str]] = []
        for answer in answers:
            preference, _, exchange = answer.partition(" ")
            try:
                exchanges.append((int(preference), exchange.strip().rstrip(".")))
            except ValueError:
                exchanges.append((0, answer.strip().rstrip(".")))
        addresses: list[str] = []
        for _preference, exchange in sorted(exchanges):
            if exchange:
                addresses.extend(self.dns_a(exchange, node_id=node_id))
        return tuple(addresses)

    def validated_ptrs(self, *, node_id: str) -> tuple[str, ...]:
        """正向验证过的 PTR 名（§5.5）。超过 10 条 → **只取前 10 条**。"""
        if self._ptr_cache is not None:
            return self._ptr_cache
        reverse = "%s.%s.arpa" % (_reverse_dots(self.i), self.v)
        names = self.lookup(reverse, "PTR", node_id=node_id).answers
        self.budget.observe("ptr", len(names), node_id)
        if len(names) > SPF_MAX_PTR:
            # RFC 7208 §4.6.4：超出前 10 条 MUST 被忽略（不是 permerror）。
            self.warnings.append(
                "%s 返回 %d 条 PTR，超过 %d 条；按 RFC 7208 §4.6.4 只取前 %d 条"
                % (reverse, len(names), SPF_MAX_PTR, SPF_MAX_PTR))
            names = names[:SPF_MAX_PTR]
        validated: list[str] = []
        for name in names:
            target = name.strip().rstrip(".")
            if not target:
                continue
            if _cidr_match(self.dns_a(target, node_id=node_id), self.cidrmax, self.ip):
                validated.append(target)
        self._ptr_cache = tuple(validated)
        return self._ptr_cache

    def p_value(self, *, node_id: str) -> str:
        """``%{p}``（§7.3）：有验证名取最贴近 ``d`` 的那个，否则 ``unknown``。"""
        validated = self.validated_ptrs(node_id=node_id)
        if not validated:
            if not self.p_unavailable:
                self.p_unavailable = True
                self.gray.append(
                    "%{p} 被使用，但连接 IP 没有可验证的 PTR（RFC 7208 §7.3 展开为 "
                    "unknown）；本条不默认判 fail（题面 §2.5 灰区 4）")
            return "unknown"
        current = _normalize_name(self.d)
        for name in validated:
            if _normalize_name(name) == current:
                return name
        suffix = "." + current
        for name in validated:
            if _normalize_name(name).endswith(suffix):
                return name
        return validated[0]

    # ── 宏（§7） ───────────────────────────────────────────────────────
    def expand(self, text: str, *, node_id: str, stripdot: bool = True,
               in_exp: bool = False) -> str:
        """展开宏。语法错一律 :class:`_PermError`（§7.1/9）。"""
        if _RE_INVALID_MACRO.search(text):
            raise _PermError(
                "宏语法错：%% 后面必须是 { / %% / - / _（RFC 7208 §7.1/9）：%r" % text)
        pieces: list[str] = []
        end = 0
        for match in _RE_CHAR.finditer(text):
            pieces.append(text[end:match.start()])
            macro = match.group(0)
            if macro == "%%":
                pieces.append("%")
            elif macro == "%_":
                pieces.append(" ")
            elif macro == "%-":
                pieces.append("%20")
            else:
                pieces.append(self._expand_macro(macro, node_id=node_id, in_exp=in_exp))
            end = match.end()
        pieces.append(text[end:])
        result = "".join(pieces)
        if stripdot and result.endswith("."):
            result = result[:-1]
        if len(result) > _MAX_NAME_LENGTH and "." in result:
            # §7.1/25：从左逐个删标签，直到不超过 253 字符。
            while len(result) > _MAX_NAME_LENGTH and "." in result:
                result = result[result.index(".") + 1:]
        return result

    def _expand_macro(self, macro: str, *, node_id: str, in_exp: bool) -> str:
        letter_raw = macro[2]
        letter = letter_raw.lower()
        if letter not in _MACRO_LETTERS:
            raise _PermError(
                "未知宏字母 %%{%s}（允许：%s）" % (letter_raw, _MACRO_LETTERS))
        if letter in _EXP_ONLY_LETTERS and not in_exp:
            raise _PermError(
                "宏 %%{%s} 只允许出现在 exp 文本里（RFC 7208 §7.1/8）" % letter_raw)

        if letter == "p":
            value = self.p_value(node_id=node_id)
        elif letter == "d":
            value = self.d
        elif letter == "t":
            # `t` 是"当前时间戳"，展开它必须读系统时钟——而 K7 禁止判定读时钟
            # （时间只能来自快照）。这不是"不支持"，是**确定性纪律的直接后果**：
            # 判定的产物要能两次运行逐字节一致，就不能把墙钟写进去。
            # exp 文本取不到解释时按 §6.2/4 忽略（见 `_fetch_explanation`），
            # 所以这条只影响"解释文本"这一项人读信息，不影响 SPF 结果。
            self.warnings.append(
                "%{t} 需要系统时钟；本项目判定路径零时钟（K7），"
                "解释文本里的时间戳不展开")
            raise _PermError(
                "%{t} 需要系统时钟，判定路径按 K7 零时钟，无法展开")
        else:
            value = getattr(self, letter, None)
            if value is None:
                raise _PermError("未知宏字母 %%{%s}" % letter_raw)

        expansion = _expand_one(value, macro[3:-1], _JOINERS.get(letter))
        if letter != letter_raw:
            # 大写 = 展开后再做 URL 转义（§7.1/26）。
            expansion = _url_quote(expansion)
        return expansion

    def expand_domain(self, raw: str | None, *, node_id: str,
                      in_exp: bool = False) -> str:
        """校验并展开 domain-spec。

        校验作用在**展开前**的原文上（与参照实现一致）：以 ``%{h}`` 这类宏结尾的写法
        过得了 toplabel 判据，展开后的怪名字只当作"查不到"，不算语法错。
        上游用例 `invalid-hello-macro` 锁的正是这条。
        """
        if raw is None:
            raise _PermError("domain-spec 缺失")
        if _RE_TOPLAB.split(raw)[-1]:
            raise _PermError(
                "domain-spec 不是合法域名（需以合法 toplabel 或宏结尾）：%r" % (raw,))
        return self.expand(raw, node_id=node_id, in_exp=in_exp)


# ── 小工具 ──────────────────────────────────────────────────────────────


def _reverse_dots(name: str) -> str:
    return ".".join(reversed(name.split(".")))


def _url_quote(text: str) -> str:
    """RFC 3986 百分号转义（unreserved + ``/`` 不转义），与参照实现同集。"""
    out: list[str] = []
    for byte in text.encode("utf-8"):
        char = chr(byte)
        out.append(char if char in _UNRESERVED else "%%%02X" % byte)
    return "".join(out)


def _expand_one(value: str, args: str, joiner: str | None) -> str:
    """宏变换：``[数字][r][分隔符集]``（§7.1/15–18）。"""
    if not args:
        return value
    count, reverse, delimiters = _RE_ARGS.split(args)[1:4]
    if not delimiters:
        delimiters = "."
    parts = _split_keep(value, delimiters, joiner)
    if reverse:
        parts.reverse()
    if count:
        parts = parts[-int(count) * 2 + 1:]
    return "".join(parts)


def _split_keep(value: str, delimiters: str, joiner: str | None) -> list[str]:
    """按分隔符切分，并把分隔符原样（或替换成 joiner）留在列表里。

    留分隔符是为了让"取右边 N 段"能与"反转"组合出正确结果（§7.1/17）。
    """
    result: list[str] = []
    element = ""
    for char in value:
        if char in delimiters:
            result.append(element)
            element = ""
            result.append(joiner if joiner else char)
        else:
            element += char
    result.append(element)
    return result


def _cidr_match(addresses: Iterable[str], prefix: int, ip: Any) -> bool:
    """连接 IP 是否落在任一地址的 ``/prefix`` 内（§5.3/5.4 的匹配语义）。"""
    for text in addresses:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise _PermError("DNS 答复里的地址不合法：%r" % (text,)) from None
        if network.version != ip.version:
            # A 记录不匹配 IPv6 连接，反之亦然（上游 a-cidr4-0-ip6 锁这条）。
            continue
        if prefix > network.max_prefixlen:
            continue
        if ip in network.supernet(new_prefix=prefix):
            return True
    return False


def _uses_p_macro(raw: str) -> bool:
    """domain-spec 是否用了 ``%{p}``（含变换与大小写）。"""
    return "%{p" in raw.lower()


# ── 机制解析与校验（§4.6.1 / §5） ───────────────────────────────────────


@dataclass(frozen=True)
class _Mechanism:
    """校验通过的机制。"""

    token: str
    name: str
    arg: str | None
    cidr: int
    result: str
    raw_arg: str | None = None


def _parse_mechanism(token: str, default_domain: str) -> tuple[
        str, str | None, int | None, int | None]:
    """拆出 ``(name, arg, cidr4, cidr6)``，顺序同 RFC 7208 §12 的 ABNF。"""
    head = token
    cidr6: int | None = None
    dual = _RE_DUAL_CIDR.search(head)
    if dual:
        cidr6 = int(dual.group(1))
        head = head[:dual.start()]
    cidr: int | None = None
    single = _RE_CIDR.search(head)
    if single:
        cidr = int(single.group(1))
        head = head[:single.start()]
    name, sep, rest = head.partition(":")
    if not sep:
        lowered = name.lower()
        return lowered, (None if lowered == "exists" else default_domain), cidr, cidr6
    return name.lower(), rest, cidr, cidr6


def _validate_mechanism(ctx: _Ctx, token: str, domain: str, *,
                        node_id: str) -> _Mechanism:
    """校验一个 term。任何错误 → :class:`_PermError`（§4.6.1/2）。"""
    if token.endswith(","):
        raise _PermError("机制之间不能用逗号分隔（RFC 7208 §4.6.1/2）：%r" % token)

    name, arg, cidr, cidr6 = _parse_mechanism(token, domain)
    result = "pass"
    if name and name[0] in _QUALIFIERS:
        result = _QUALIFIERS[name[0]]
        name = name[1:]

    if name in _COMMON_MISTAKES:
        raise _PermError(
            "疑似拼写错误：%r 应为 %r（RFC 7208 §4.6.1/4）"
            % (token, _COMMON_MISTAKES[name]))
    if name not in _MECHANISMS:
        raise _PermError("未知机制 %r（RFC 7208 §4.6.1/4）" % token)

    if name in ("a", "mx"):
        if cidr is None:
            cidr = 32
        elif cidr > 32:
            raise _PermError("IPv4 CIDR 超过 32：%r" % token)
        if cidr6 is None:
            cidr6 = 128
        elif cidr6 > 128:
            raise _PermError("IPv6 CIDR 超过 128：%r" % token)
        effective = cidr6 if ctx.v == "ip6" else cidr
    elif name == "ip4":
        if cidr6 is not None:
            raise _PermError("ip4 不允许 dual-cidr：%r" % token)
        if cidr is None:
            cidr = 32
        elif cidr > 32:
            raise _PermError("IPv4 CIDR 超过 32：%r" % token)
        if not arg or not _RE_IP4.match(arg):
            raise _PermError("ip4 地址不合法（不允许省略段或带端口）：%r" % token)
        effective = cidr
    elif name == "ip6":
        if cidr6 is not None:
            raise _PermError("ip6 不允许 dual-cidr：%r" % token)
        if cidr is None:
            cidr = 128
        elif cidr > 128:
            raise _PermError("IPv6 CIDR 超过 128：%r" % token)
        if not arg:
            raise _PermError("ip6 地址不合法：%r" % token)
        try:
            if ipaddress.ip_address(arg).version != 6:
                raise ValueError("不是 IPv6")
        except ValueError:
            raise _PermError("ip6 地址不合法：%r" % token) from None
        effective = cidr
    else:
        if cidr is not None or cidr6 is not None:
            raise _PermError("%s 机制不接受 CIDR：%r" % (name, token))
        effective = ctx.cidrmax

    if name == "all":
        if ":" in token:
            raise _PermError("all 机制只允许限定符，不接受参数：%r" % token)
        return _Mechanism(token, name, None, effective, result, None)

    if name in ("ip4", "ip6"):
        return _Mechanism(token, name, arg, effective, result, None)

    if name in _TERM_MECHANISMS:
        if name == "exists" and not arg:
            raise _PermError("exists 必须带 domain-spec：%r" % token)
        raw = arg
        expanded = ctx.expand_domain(raw, node_id=node_id)
        if not expanded:
            raise _PermError("%s 的 domain-spec 为空：%r" % (name, token))
        if name == "include" and _normalize_name(expanded) == _normalize_name(domain):
            raise _PermError("include 指向自己（trivial recursion）：%r" % token)
        if name == "a" and _RE_IP4.match(expanded):
            raise _PermError("a 机制不要用 IP 字面量，请用 ip4：%r" % token)
        return _Mechanism(token, name, expanded, effective, result, raw)

    # 走不到这里：_MECHANISMS 与上面的分支穷尽。
    raise _PermError("未知机制 %r" % token)


# ── 求值 ────────────────────────────────────────────────────────────────


class _Evaluation:
    """一次求值的内部累加器（``check_host`` 用它组装 :class:`SpfResult`）。"""

    def __init__(self) -> None:
        self.reason: str = ""
        self.mechanism: str | None = None
        self.refs: list[str] = []
        #: 树节点 id → 该节点的求值结果。键与 :func:`_node_id` 同源，
        #: 所以求值阶段和画树阶段不需要互相知道对方（K12：id 不依赖遍历顺序）。
        self.node_results: dict[str, str] = {}
        self.cut_point: dict[str, Any] | None = None
        self.term_ordinal = 0


def _node_id(path: tuple[int, ...]) -> str:
    """树节点 id（K12）：根 ``n0``，第 i 个 include ``n<i>``，嵌套 ``n<i>.<j>``。

    只由"从根到该节点的 include 序号路径"决定，与遍历顺序、与是否被截断都无关。
    """
    if not path:
        return "n0"
    return "n" + ".".join(str(index) for index in path)


def _evaluate(ctx: _Ctx, ev: _Evaluation, domain: str, record: str, *,
              depth: int, path: tuple[int, ...]) -> str:
    """求值一条记录，返回 ``pass`` / ``fail`` / ``softfail`` / ``neutral``。

    递归只发生在 ``include`` 与 ``redirect``；``temperror`` / ``permerror`` /
    ``undecidable`` 用异常穿出去，避免每层都写一遍"是错就往上抛"。

    ``path`` 是"从根到本节点的 include 序号路径"，节点 id 由它算出（K12）：
    这样 id 与遍历顺序无关，也与树有没有被截断无关。
    """
    node_id = _node_id(path)
    if depth > SPF_MAX_DEPTH:
        raise _PermError("include/redirect 嵌套超过 %d 层（RFC 7208 §4.6.4）"
                         % SPF_MAX_DEPTH)
    ctx.budget.observe("depth", depth, node_id, ref=REF_INCLUDE)

    previous_domain = ctx.d
    ctx.d = domain
    try:
        tokens = [token for token in record.split(" ") if token]
        if not tokens or tokens[0].lower() != "v=spf1":
            # 选记录阶段已过滤；这里再判一次是为了"直接喂文本"的调用路径。
            return "none"

        mechanisms: list[_Mechanism] = []
        seen_modifiers: set[str] = set()
        redirect_target: str | None = None
        #: 本记录里 include 的出现序号（从 1 起）。树节点 id 用它，不另设全局计数器。
        include_ordinal = 0

        # ── 先全量校验（§4.6：任何位置的语法错都是 permerror） ──
        for token in tokens[1:]:
            match = _RE_MODIFIER.match(token)
            if match:
                name = match.group(1).lower()
                arg = token[match.end():]
                if name in seen_modifiers:
                    raise _PermError(
                        "修饰符 %s= 出现了不止一次（RFC 7208 §6/2）" % name)
                seen_modifiers.add(name)
                if name == "exp":
                    if not arg:
                        raise _PermError("exp= 的 domain-spec 为空（RFC 7208 §6.2/1）")
                    # 注意 in_exp=False：``c`` / ``r`` / ``t`` 只许出现在**解释文本**里，
                    # 不许出现在 ``exp=`` 的 domain-spec 里（§7.1/8）。
                    # 上游用例 exp-only-macro-char 锁这条。
                    spec = ctx.expand_domain(arg, node_id=node_id)
                    if depth == 0:
                        _fetch_explanation(ctx, spec, node_id=node_id)
                elif name == "redirect":
                    redirect_target = ctx.expand_domain(arg, node_id=node_id)
                    if not redirect_target:
                        raise _PermError(
                            "redirect= 的 domain-spec 为空（RFC 7208 §6.1/2）")
                else:
                    # ``default=`` 已废弃、未知修饰符被忽略：两者都**必须**校验宏语法
                    # （§6/2 + §7.1/9）。上游 default-modifier-* / invalid-modifier 锁这条。
                    ctx.expand(arg, node_id=node_id)
                continue
            mech = _validate_mechanism(ctx, token, domain, node_id=node_id)
            if mech.name == "include":
                include_ordinal += 1
            mechanisms.append((mech, include_ordinal))

        # ── 再求值 ──
        for mech, ordinal in mechanisms:
            if mech.name in _TERM_MECHANISMS:
                ev.term_ordinal += 1
                if not ctx.budget.consume("terms", node_id, ref=REF_LIMITS):
                    ev.cut_point = {
                        "term_ordinal": ev.term_ordinal,
                        "mechanism": mech.name,
                        "token": mech.token,
                        "node_id": node_id,
                        "receiver_would_stop_here": True,
                    }
                    raise _PermError(
                        "DNS 查询类 term 超过 %d 个（RFC 7208 §4.6.4 MUST → permerror）；"
                        "第 %d 个是 %r" % (SPF_MAX_TERMS, ev.term_ordinal, mech.token))

            child_path = path + (ordinal,) if mech.name == "include" else path
            if _mechanism_matches(ctx, ev, mech, path=child_path, depth=depth):
                ev.mechanism = mech.token
                # 挂命中机制自己的条款节（§5.1–§5.7），再补限定符语义（§4.6.2）。
                ev.refs.append(_REF_BY_MECHANISM.get(mech.name, REF_RESULTS))
                ev.refs.append(REF_QUALIFIER)
                if mech.raw_arg and _uses_p_macro(mech.raw_arg) and ctx.p_unavailable:
                    ctx.p_decided = True
                return mech.result

        # ── 没有机制匹配：redirect 或默认结果（§6.1 / §4.7） ──
        if redirect_target is not None:
            # redirect 也算一个 DNS 查询类 term（§4.6.4）。
            ev.term_ordinal += 1
            if not ctx.budget.consume("terms", node_id, ref=REF_LIMITS):
                ev.cut_point = {
                    "term_ordinal": ev.term_ordinal,
                    "mechanism": "redirect",
                    "token": "redirect=" + redirect_target,
                    "node_id": node_id,
                    "receiver_would_stop_here": True,
                }
                raise _PermError(
                    "DNS 查询类 term 超过 %d 个（含 redirect，RFC 7208 §4.6.4）"
                    % SPF_MAX_TERMS)
            child_record = ctx.spf_record(redirect_target, node_id=node_id)
            if child_record is None:
                raise _PermError(
                    "redirect 目标 %s 没有 SPF 记录（RFC 7208 §6.1/4 → permerror）"
                    % redirect_target)
            ev.refs.append(REF_REDIRECT)
            # redirect 沿用本节点的 id（它在树上是本节点的"续"，不是 include 子节点）。
            return _evaluate(ctx, ev, redirect_target, child_record,
                             depth=depth + 1, path=path)

        ev.refs.append(REF_DEFAULT)
        return "neutral"
    finally:
        ctx.d = previous_domain


def _mechanism_matches(ctx: _Ctx, ev: _Evaluation, mech: _Mechanism, *,
                       path: tuple[int, ...], depth: int) -> bool:
    """单个机制是否匹配（§5.1–§5.7）。"""
    node_id = _node_id(path)
    if mech.name == "all":
        return True
    if mech.name == "ip4":
        return ctx.v == "in-addr" and _cidr_match([mech.arg or ""], mech.cidr, ctx.ip)
    if mech.name == "ip6":
        return ctx.v == "ip6" and _cidr_match([mech.arg or ""], mech.cidr, ctx.ip)
    if mech.name == "a":
        return _cidr_match(ctx.dns_a(mech.arg or "", node_id=node_id), mech.cidr, ctx.ip)
    if mech.name == "mx":
        return _cidr_match(ctx.dns_mx(mech.arg or "", node_id=node_id),
                           mech.cidr, ctx.ip)
    if mech.name == "exists":
        # exists 永远查 A，即使连接是 IPv6（§5.7/3）。
        return bool(ctx.lookup(mech.arg or "", "A", node_id=node_id).answers)
    if mech.name == "ptr":
        target = _normalize_name(mech.arg or "")
        for name in ctx.validated_ptrs(node_id=node_id):
            lowered = _normalize_name(name)
            if lowered == target or lowered.endswith("." + target):
                return True
        return False
    if mech.name == "include":
        child_record = ctx.spf_record(mech.arg or "", node_id=node_id)
        if child_record is None:
            # §5.2/9：include 目标没有记录 → permerror（不是 none）。
            raise _PermError(
                "include 目标 %s 没有 SPF 记录（RFC 7208 §5.2/9 → permerror）"
                % mech.arg)
        child = _evaluate(ctx, ev, mech.arg or "", child_record,
                          depth=depth + 1, path=path)
        ev.node_results[_node_id(path)] = child
        # 子域的 -all 不终止父域处理：只有 pass 才让 include 命中（§5.2）。
        return child == "pass"
    raise _PermError("未实现的机制 %r" % mech.name)


def _fetch_explanation(ctx: _Ctx, spec: str, *, node_id: str) -> None:
    """取 ``exp=`` 的解释文本（§6.2）。

    失败一律**忽略**（§6.2/4）：exp 只是给人看的说明，不能因为它把结果改掉。
    但失败原因要进 ``warnings``——"忽略"与"没发生"必须可区分。
    """
    try:
        lookup = ctx.lookup(spec, "TXT", node_id=node_id, ignore_void=True)
        if len(lookup.answers) != 1:
            ctx.warnings.append(
                "exp=%s 的 TXT 记录有 %d 条（需恰好 1 条），已忽略解释文本"
                % (spec, len(lookup.answers)))
            return
        text = ctx.expand(lookup.answers[0], node_id=node_id, stripdot=False, in_exp=True)
        if not text.isascii():
            ctx.warnings.append("exp=%s 的解释文本含非 ASCII 字符，已忽略" % spec)
            return
        ctx.explanations.append({"domain": spec, "text": text, "ref": REF_EXP})
    except (_TempError, _PermError, _Undecidable) as exc:
        ctx.warnings.append("exp=%s 取解释文本失败（已忽略）：%s" % (spec, exc))


# ── include 树（完整展开，不因第 11 个 term 截断） ──────────────────────


def _build_tree(ctx: _Ctx, domain: str, record: str, *, path: tuple[int, ...],
                parent: str | None, term_ordinal: list[int],
                seen: tuple[str, ...], counter: list[int],
                mechanism: str | None) -> dict[str, Any]:
    """结构性地展开 include 目标。

    这一步只回答"树长什么样"，**不参与判定**：用独立的 shadow 上下文（独立预算、
    独立缓存），否则"为了画树"会把 void 计数和 term 预算搅乱，判定就不再可复算。

    ``term_ordinal`` 是**全局**的 DNS 查询类 term 计数（跨整棵树），因为 RFC 7208
    §4.6.4 的限制是"每次 check_host 全局 10 个"，不是每层 10 个。树必须用它来标切点。
    """
    node_id = _node_id(path)
    node: dict[str, Any] = {
        "node_id": node_id,
        "parent": parent,
        "domain": domain,
        "record": record,
        "mechanism": mechanism,
        "child_result": None,
        "consumes_term": parent is not None,
        "terminates_parent": False,
        "receiver_would_stop_here": False,
        "children": [],
    }

    tokens = [token for token in record.split(" ") if token]
    include_targets: list[str] = []
    for token in tokens[1:]:
        match = _RE_MODIFIER.match(token)
        if match:
            # redirect 不建独立子节点：它在语义上是"本节点换一条记录继续"，
            # 给它在树上单开一格会让读者误以为是 include。
            continue
        name, arg, _cidr, _cidr6 = _parse_mechanism(token, domain)
        if name and name[0] in _QUALIFIERS:
            name = name[1:]
        if name != "include" or not arg:
            continue
        try:
            expanded = ctx.expand(arg, node_id=node_id)
        except (_PermError, _Undecidable, _TempError):
            continue
        if expanded:
            include_targets.append(expanded)

    children: list[dict[str, Any]] = []
    for index, target in enumerate(include_targets, 1):
        term_ordinal[0] += 1
        children.append(_tree_child(
            ctx, target, path + (index,), node_id, term_ordinal,
            seen, counter, "include"))
    node["children"] = children
    return node


def _tree_child(ctx: _Ctx, target: str, path: tuple[int, ...], parent: str,
                term_ordinal: list[int], seen: tuple[str, ...],
                counter: list[int], mechanism: str) -> dict[str, Any]:
    """建一个子节点。超限或成环时只留"到此为止"的节点，不再向下。"""
    node_id = _node_id(path)
    over_limit = term_ordinal[0] > SPF_MAX_TERMS
    normalized = _normalize_name(target)
    child: dict[str, Any] = {
        "node_id": node_id,
        "parent": parent,
        "domain": target,
        "record": None,
        "mechanism": mechanism,
        "child_result": None,
        "consumes_term": True,
        "terminates_parent": False,
        "receiver_would_stop_here": over_limit,
        "children": [],
    }
    counter[0] += 1
    if over_limit:
        child["note"] = (
            "第 %d 个 DNS 查询类 term：收件方会在此处 permerror 停下（RFC 7208 §4.6.4）"
            % term_ordinal[0])
        return child
    if counter[0] > SPF_TREE_MAX_NODES:
        child["note"] = "树节点数超过 %d，停止展开（防环）" % SPF_TREE_MAX_NODES
        return child
    if normalized in seen:
        child["note"] = "include 成环（该域在本路径上已出现过），停止展开"
        return child
    try:
        record = ctx.spf_record(target, node_id=node_id)
    except (_PermError, _Undecidable, _TempError) as exc:
        child["note"] = "取记录失败：%s" % exc
        return child
    if record is None:
        child["note"] = "目标域没有 SPF 记录"
        return child
    child.update(_build_tree(ctx, target, record, path=path, parent=parent,
                             term_ordinal=term_ordinal,
                             seen=seen + (normalized,), counter=counter,
                             mechanism=mechanism))
    child["node_id"] = node_id
    child["parent"] = parent
    child["domain"] = target
    child["mechanism"] = mechanism
    child["consumes_term"] = True
    child["receiver_would_stop_here"] = over_limit
    return child


def _fill_tree_results(node: dict[str, Any], results: dict[str, str]) -> None:
    """把求值阶段真正算过的子节点结果填进树。"""
    for child in node.get("children") or []:
        child["child_result"] = results.get(child["node_id"])
        if child["child_result"] == "pass":
            # include 匹配 → 父域在该 term 停下；子域的 -all 不终止父域（§5.2）。
            child["terminates_parent"] = True
        _fill_tree_results(child, results)


# ── 对外入口 ────────────────────────────────────────────────────────────


def check_host(snap: Snapshot, ip: str, domain: str, helo: str | None, *,
               budget: Budget | None = None,
               trace: list[dict[str, Any]] | None = None,
               local: str | None = None,
               sender: str | None = None,
               receiver: str | None = None) -> SpfResult:
    """对 ``(ip, domain)`` 做一次 SPF 求值（RFC 7208 §4–§7）。

    参数
    ----
    snap
        已加载的 DNS 快照。**求值器不联网**，也拿不到网络能力（AST 守门）。
    ip / domain / helo
        连接 IP、被检查域（信封发件人域；空发件人时用 HELO 域）、HELO 名。
    budget / trace
        可复用的预算账本与轨迹列表（调用方持有，便于把多次求值记在同一本账上）。
    local / sender
        信封发件人的本地部分与完整地址（``%{l}`` / ``%{s}`` 需要）。只给 ``domain``
        时 ``%{l}`` 取 ``postmaster``（§4.3/2）。
    """
    budget = budget if budget is not None else Budget()
    trace = trace if trace is not None else []
    ctx = _Ctx(snap, ip, helo, budget=budget, trace=trace,
               local=local, sender=sender, receiver=receiver)

    ev = _Evaluation()
    record: str | None = None
    checked = _initial_domain(domain)
    ctx.d = checked or _normalize_name(domain)
    if not ctx.o:
        ctx.o = ctx.d
        ctx.s = "%s@%s" % (ctx.l, ctx.o)
    data_gap: tuple[str, str] | None = None

    try:
        # ── 初始处理（§4.3） ──
        if checked is None:
            return _result(
                ctx, ev, result="none",
                reason="%r 不是可检查的多标签域名（RFC 7208 §4.3/1）→ none"
                       % (domain,),
                domain=domain, record=None, refs=[REF_INITIAL], trace=trace,
                budget=budget, tree=None)

        record = ctx.spf_record(checked, node_id="n0")
        if record is None:
            return _result(
                ctx, ev, result="none",
                reason="%s 没有 v=spf1 TXT 记录（RFC 7208 §4.5/1）→ none" % checked,
                domain=checked, record=None, refs=[REF_SELECT], trace=trace,
                budget=budget, tree=None)

        trace.append({"node": "n0", "note": "选中记录：%s" % record})
        result = _evaluate(ctx, ev, checked, record, depth=0, path=())

        # ── %{p} 灰区：只有"由 %{p} 机制决定结果"才降级（题面 §2.5 灰区 4） ──
        if ctx.p_decided and result in ("fail", "softfail"):
            ctx.gray.append(
                "结果由含 %{p} 的机制匹配决定，而连接 IP 没有可验证 PTR；"
                "按题面灰区 4 判 undecidable，不默认 fail")
            result = "undecidable"

        # ── void 超限：项目口径判 undecidable（SHOULD 级，不硬判 permerror） ──
        # 但 MUST 级的结论优先：同一条记录若已踩了 term / MX 上限，报 MUST 更站得住
        # （那条记录无论实现怎么选都是坏的）。permerror / temperror 因此不被覆盖。
        if ctx.void_exceeded:
            if result not in ("permerror", "temperror"):
                result = "undecidable"
                ctx.gray.append(
                    "void lookup 超过 %d 次（RFC 7208 §4.6.4 的**限制**是 SHOULD，"
                    "不是 MUST）；本项目按题面 §2.5 灰区 2 判 undecidable 而非 "
                    "permerror。超限处：%s" % (SPF_MAX_VOID, ctx.void_note))

        refs = list(dict.fromkeys(ev.refs))
        if not refs:
            refs = [REF_RESULTS]
        if ev.cut_point and REF_LIMITS not in refs:
            refs.append(REF_LIMITS)
        reason = _reason(result, checked, ev.mechanism)

    except _PermError as exc:
        result, reason, refs = "permerror", "permerror：%s" % exc, [REF_SYNTAX]
        if ev.cut_point:
            refs = [REF_LIMITS, REF_SYNTAX]
    except _TempError as exc:
        result, reason, refs = "temperror", "temperror：%s" % exc, [REF_RESULTS]
    except DataGap as gap:
        # 数据缺口：结果按 undecidable 报，但**同时**把缺的键带出去，
        # 调用方才能决定"补抓"还是"如实登记"。两种信息都要，不能只留一个。
        data_gap = (gap.qname, gap.qtype)
        result = "undecidable"
        reason = "undecidable：%s" % gap
        refs = [REF_LIMITS]
    except _Undecidable as exc:
        result, reason, refs = "undecidable", "undecidable：%s" % exc, [REF_LIMITS]

    # ── include 树：求值之后展开，用独立 shadow 上下文，绝不影响判定 ──
    root = None
    if record is not None:
        try:
            shadow = _Ctx(snap, ip, helo, budget=Budget(), trace=[],
                          local=ctx.l, sender=ctx.s, receiver=ctx.r)
            shadow.d = checked
            root = _build_tree(shadow, checked, record, path=(), parent=None,
                               term_ordinal=[0], seen=(_normalize_name(checked),),
                               counter=[1], mechanism=None)
            _fill_tree_results(root, ev.node_results)
        except Exception as exc:  # noqa: BLE001 - 诊断树失败不得掩盖判定结果
            ctx.warnings.append("include 树展开失败（不影响判定）：%r" % (exc,))
            root = None

    return _result(ctx, ev, result=result, reason=reason,
                   domain=checked or _normalize_name(domain), record=record,
                   refs=refs, trace=trace, budget=budget, tree=root,
                   data_gap=data_gap)


def _result(ctx: _Ctx, ev: _Evaluation, *, result: str, reason: str, domain: str,
            record: str | None, refs: list[str], trace: list[dict[str, Any]],
            budget: Budget, tree: dict[str, Any] | None,
            data_gap: tuple[str, str] | None = None) -> SpfResult:
    """组装 :class:`SpfResult`（所有出口共用，保证字段一致）。"""
    return SpfResult(
        result=result,
        reason=reason,
        domain=domain,
        record=record,
        evidence_ref=tuple(refs),
        trace=tuple(trace),
        budget=budget.to_dict(),
        budget_entries=tuple(budget.entries),
        tree=tree,
        warnings=tuple(ctx.warnings),
        gray_areas=tuple(ctx.gray),
        limit_hit=budget.limit_hit,
        limit_hits=tuple(budget.hits),
        cut_point=ev.cut_point,
        mechanism=ev.mechanism,
        explanations=tuple(ctx.explanations),
        data_gap=data_gap,
    )


def _initial_domain(domain: str) -> str | None:
    """§4.3/1：不可检查的域一律 ``none``（不是 permerror，也不是 temperror）。"""
    name = _normalize_name(domain or "")
    if not name:
        return None
    if "[" in name or "]" in name:
        return None  # 域名字面量（如 [192.0.2.1]）不做 SPF 检查
    labels = name.split(".")
    if len(labels) < 2:
        return None
    if any(not label or len(label) > 63 for label in labels):
        return None
    return name


def _reason(result: str, domain: str, mechanism: str | None) -> str:
    """给人读的一句话结论（不含定性词，`--strict-evidence` 安全）。"""
    if result == "pass":
        return "%s：机制 %s 匹配（RFC 7208 §5）" % (domain, mechanism or "?")
    if result == "fail":
        return "%s：机制 %s 匹配，限定符为 -（RFC 7208 §4.6.2）" % (domain, mechanism or "?")
    if result == "softfail":
        return "%s：机制 %s 匹配，限定符为 ~（RFC 7208 §4.6.2）" % (domain, mechanism or "?")
    if result == "neutral":
        return "%s：没有机制匹配且无 redirect（默认 neutral，RFC 7208 §4.7）" % domain
    if result == "none":
        return "%s：没有可求值的 SPF 记录（RFC 7208 §4.5）" % domain
    if result == "undecidable":
        return "%s：数据不足或规则为灰区，判不可判定（不折叠为 fail）" % domain
    return "%s：%s" % (domain, result)


def evaluate(snap: Snapshot, query: Any, *, budget: Budget | None = None,
             trace: list[dict[str, Any]] | None = None) -> SpfResult:
    """按 ``query.json`` 的语义调一次 :func:`check_host`。

    ``mail_from`` 为空时用 HELO 域做被检查域，本地部分取 ``postmaster``（§4.3/2）。
    """
    mail_from = getattr(query, "mail_from", "") or ""
    helo = getattr(query, "helo", None)
    local, _, sender_domain = mail_from.partition("@")
    domain = sender_domain or (helo or "")
    return check_host(
        snap, getattr(query, "client_ip"), domain, helo,
        budget=budget, trace=trace,
        local=local or None,
        sender=mail_from or None,
    )
