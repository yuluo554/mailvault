"""DMARC（RFC 9989）：DNS Tree Walk + 双算对齐 + 处置。

本模块是 M4 的交付面。五条设计约束：

1. **tree walk 照 §4.10 的通用步骤逐条实现**，不是"从 Author 域逐级往上找 `_dmarc`"。
   两者的差别在**标签数 ≥ 8 时的跳步**（§4.10 步骤 4：x >= 8 时一次删到只剩 7 个标签）。
   不实现跳步，深度域名会多做几十次查询，而且与附录 B.4.2 的逐跳结果对不上。
2. **`psd=n` / `psd=y` 改变 Organizational Domain（§4.10.2）**，不只是"多一个标签"。
   ``psd=y`` 出现在**不是走查起点**的记录上时，Organizational Domain 是它下面
   **一层**的域名——不是它自己。B.4.3 的第三个走查就是这个形态
   （`bank.example` 上 `psd=y` → `mega.bank.example` 才是 Organizational Domain）。
3. **对齐必须双算**：``relaxed`` 与 ``strict`` 各出一个布尔值（`constants.ALIGN_MODES`）。
   合并成一个布尔值会让"为什么 strict 不过"变成不可诊断——两者的差异本身就是信息。
4. **"没查过" ≠ "没有记录"**（K13，与 SPF/DKIM 同一口径）：快照里没有某跳的查询 →
   该跳 ``not_queried``，整条结论 ``undecidable`` + ``data_gaps``；
   快照明确答复 NXDOMAIN / NOERROR 空答复 → ``nxdomain`` / ``no_record``，走查继续。
5. **旧标签不静默忽略**：``pct`` / ``rf`` / ``ri`` 已被 RFC 9989 删除
   （Appendix C.5.2，``pct`` 另见 A.6）。它们的语义本工具**不解释**，但每条都必须
   进 ``warnings``——静默忽略会让读者以为"``pct=0`` 被尊重了"。

### PSL 在这里的角色（与 RFC 9989 的关系必须说清）

RFC 7489 用 PSL 求 Organizational Domain；**RFC 9989 §4.10 把它换成了 tree walk**，
并在原文里写明了理由（PSL 版本不一致会造成互操作问题）。所以本模块：

- ``organizational_domain`` **只**由 tree walk 得出（§4.10.2），这是判定用的值；
- ``psl_organizational_domain`` 由随包冻结的 PSL 算出，**仅作对照**，并明写
  "RFC 9989 以 tree walk 为准"；
- ``psl_version`` / ``psl_date`` 来自**快照**（题面 §2.5 灰区 3 要求输出必须带），
  与随包冻结件的版本不同时出告警——跨 PSL 版本的结果差异不是 bug，但必须能看见。

把 PSL 的值当判定值会在 B.4.3 那种 ``psd=y`` 场景下给出**错误**的 Organizational Domain
（``bank.example`` 而不是 ``giant.bank.example``），所以两者必须分开存。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..constants import (
    DMARC_DEFAULT_ALIGN,
    DMARC_DEFAULT_PSD,
    DMARC_DISPOSITIONS,
    DMARC_DNS_ERROR_RCODES,
    DMARC_MAX_LABELS,
    DMARC_RECORD_LABEL,
    DMARC_REMOVED_TAGS,
    DMARC_TEST_MODE_DOWNGRADE,
    DMARC_TREE_KEEP_LABELS,
    DMARC_VERSION,
    DMARC_WALK_STATUSES,
)
from ..ledger import check_entry
from ..psl import PSL, default_psl
from ..snapshot import Snapshot

# ── 条款号（`evidence_ref` 的唯一来源；格式见 `docs/ledger-format.md` §2.2） ──
REF_TREE_WALK = "RFC9989#4.10"
REF_DISCOVERY = "RFC9989#4.10.1"
REF_ALIGN = "RFC9989#4.10.2"
REF_ALIGN_CONCEPT = "RFC9989#4.4"
REF_DKIM_IDENTIFIER = "RFC9989#4.4.1"
REF_SPF_IDENTIFIER = "RFC9989#4.4.2"
REF_TAGS = "RFC9989#4.7"
REF_ABNF = "RFC9989#4.8"
REF_AUTHOR = "RFC9989#5.3.1"
REF_VERDICT = "RFC9989#5.3.5"
REF_APPLY = "RFC9989#5.3.6"
REF_NONEXISTENT = "RFC9989#3.2.13"
REF_PCT_REMOVED = "RFC9989#appendix-A.6"
REF_TAGS_REMOVED = "RFC9989#appendix-C.5.2"

#: 走查每跳的状态取值（唯一出处 = `constants.DMARC_WALK_STATUSES`）。
_WALK_STATUSES = frozenset(DMARC_WALK_STATUSES)
_POLICY_VALUES = frozenset(DMARC_DISPOSITIONS)

#: 记录里**已知**的标签（§4.7 / §4.8）。未知标签按 §4.7 ``unknown tags MUST be ignored``
#: 处理——那是协议明确允许的扩展位，不是错误。
_KNOWN_TAGS = frozenset(
    "v adkim aspf fo np p psd rua ruf sp t".split()
)


# ── 结构 ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Hop:
    """tree walk 的一跳：一个 ``_dmarc.<domain>`` 的查询与结论。"""

    index: int
    domain: str
    qname: str
    status: str
    """``constants.DMARC_WALK_STATUSES`` 里的值。"""
    record: str | None = None
    """命中的记录原文（``status == "record"`` 时非空）。"""
    psd: str | None = None
    """命中记录的 ``psd=`` 值（缺省按 §4.7 默认 ``u``）。"""
    rcode: str | None = None
    note: str = ""

    @property
    def is_data_gap(self) -> bool:
        return self.status == "not_queried"

    @property
    def is_dns_error(self) -> bool:
        return self.status == "dns_error"

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "domain": self.domain,
            "qname": self.qname,
            "status": self.status,
            "record": self.record,
            "psd": self.psd,
            "rcode": self.rcode,
            "note": self.note,
        }


@dataclass(frozen=True)
class Walk:
    """一次 tree walk 的完整逐跳结果。"""

    start: str
    hops: tuple[Hop, ...]
    stopped_by: str
    """``psd`` / ``labels_exhausted``。"""

    @property
    def records(self) -> tuple[Hop, ...]:
        return tuple(hop for hop in self.hops if hop.status == "record")

    @property
    def data_gaps(self) -> tuple[tuple[str, str], ...]:
        return tuple((hop.qname, "TXT") for hop in self.hops if hop.is_data_gap)

    @property
    def dns_errors(self) -> tuple[Hop, ...]:
        return tuple(hop for hop in self.hops if hop.is_dns_error)

    def record_at(self, domain: str) -> Hop | None:
        for hop in self.records:
            if hop.domain == _normalize(domain):
                return hop
        return None

    def to_list(self) -> list[dict[str, Any]]:
        return [hop.to_dict() for hop in self.hops]


@dataclass(frozen=True)
class Record:
    """一条通过 ``v=`` 过滤的 DMARC Policy Record（§4.7 / §4.8）。"""

    text: str
    tags: dict[str, str]
    malformed: tuple[str, ...] = ()
    """解析期按 §4.8 忽略掉的片段（``syntax errors ... discarded``）。"""

    def value(self, name: str) -> str | None:
        return self.tags.get(name)

    @property
    def psd(self) -> str:
        return self.tags.get("psd", DMARC_DEFAULT_PSD)


@dataclass(frozen=True)
class Alignment:
    """一个 Authenticated Identifier 与 Author Domain 的对齐结论。"""

    identifier: str
    source: str
    """``spf`` / ``dkim``。"""
    organizational_domain: str | None
    relaxed: bool
    strict: bool
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "identifier": self.identifier,
            "source": self.source,
            "organizational_domain": self.organizational_domain,
            "relaxed": self.relaxed,
            "strict": self.strict,
            "note": self.note,
        }


@dataclass(frozen=True)
class DmarcResult:
    """一次 DMARC 求值的完整结论。"""

    result: str
    reason: str
    author_domain: str | None
    organizational_domain: str | None
    policy_domain: str | None
    policy_source: str | None
    """``author`` / ``organizational`` / ``psd`` / ``None``。"""
    policy_tag: str | None
    policy_value: str | None
    disposition: str | None
    disposition_status: str
    """``determined`` / ``not_applicable`` / ``undecidable``（`constants` 未收，见 `plan/03` §3.4）。"""
    test_mode: bool
    record: Record | None
    walk: Walk | None
    alignments: tuple[Alignment, ...]
    spf_align: dict[str, bool]
    dkim_align: dict[str, bool]
    psl_version: str
    psl_date: str
    psl_organizational_domain: str | None
    evidence_ref: tuple[str, ...]
    trace: tuple[dict[str, Any], ...]
    warnings: tuple[str, ...]
    data_gaps: tuple[tuple[str, str], ...] = ()
    """数据缺口（``(qname, qtype)``）：待补的输入，**不是**结论。

    与 ``undecidable`` 分开：前者是"该去补抓快照"，后者是"已经得出判不了"（K13）。
    """

    @property
    def psd(self) -> str | None:
        return self.record.psd if self.record is not None else None

    def to_check_entry(self, *, subject: dict[str, Any] | None = None) -> dict[str, Any]:
        """转成账本 ``checks[]`` 条目（`docs/ledger-format.md` §2 与 §3.2）。"""
        return check_entry(
            check_id="dmarc.evaluate",
            module="M4",
            subject=subject or self.default_subject(),
            result=self.result,
            reason=self.reason,
            evidence_ref=list(self.evidence_ref),
            trace=list(self.trace),
            warnings=list(self.warnings),
            tree=None,
        )

    def default_subject(self) -> dict[str, Any]:
        """``subject`` 只放**标量**：渲染层按 ``k=v`` 平铺，嵌套值会变成不可读的 repr。"""
        return {
            "author_domain": self.author_domain,
            "organizational_domain": self.organizational_domain,
            "policy_domain": self.policy_domain,
            "policy_source": self.policy_source,
            "policy_tag": self.policy_tag,
            "policy_value": self.policy_value,
            "disposition": self.disposition,
            "disposition_status": self.disposition_status,
            "psd": self.psd,
            "test_mode": self.test_mode,
            "spf_align_relaxed": self.spf_align["relaxed"],
            "spf_align_strict": self.spf_align["strict"],
            "dkim_align_relaxed": self.dkim_align["relaxed"],
            "dkim_align_strict": self.dkim_align["strict"],
            "walk_queries": len(self.walk.hops) if self.walk else 0,
            "walk_hit": self._walk_hit(),
            "psl_version": self.psl_version,
            "psl_date": self.psl_date,
            "psl_organizational_domain": self.psl_organizational_domain,
        }

    def _walk_hit(self) -> str | None:
        if self.walk is None or not self.walk.records:
            return None
        # 最靠前（标签最多）的命中处：走查"第一次碰到记录"的位置。
        return self.walk.records[0].qname


# ── 记录解析（§4.7 / §4.8） ─────────────────────────────────────────────


def parse_record(text: str) -> Record | None:
    """解析一条 TXT 答复；不合格返回 ``None``（= 该条被丢弃，§4.10 步骤 2）。

    只有一条判据是**硬**的：``v`` 必须是**第一个**标签且值为 ``DMARC1``（大小写敏感）。
    §4.7 原文："If the tag is not the first in the list, the tag is absent, or the value
    is not 'DMARC1', then the entire record MUST be ignored."

    其余语法问题按 §4.8 从宽："syntax errors in the remainder of the record MUST be
    discarded in favor of default values (if any) or ignored outright"——所以坏片段进
    ``malformed``，记录本身仍然有效。两者混为一谈会把「多打一个分号」判成
    「这个域没有 DMARC」。
    """
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped:
        return None

    parts = [part.strip() for part in stripped.split(";")]
    while parts and not parts[-1]:
        parts.pop()  # 末尾分号（ABNF：`[dmarc-sep]`）
    if not parts:
        return None

    name, separator, value = parts[0].partition("=")
    if not separator or name.strip().lower() != "v" or value.strip() != DMARC_VERSION:
        return None

    tags: dict[str, str] = {"v": value.strip()}
    malformed: list[str] = []
    for fragment in parts[1:]:
        if not fragment:
            malformed.append("连续分号（空标签）")
            continue
        tag_name, tag_separator, tag_value = fragment.partition("=")
        tag_name = tag_name.strip().lower()
        if not tag_separator or not tag_name:
            malformed.append("片段缺 '='：%r" % (fragment[:40],))
            continue
        if tag_name in tags:
            malformed.append("标签 %s= 重复，保留首次出现的值" % tag_name)
            continue
        tags[tag_name] = tag_value.strip()

    return Record(text=stripped, tags=tags, malformed=tuple(malformed))


def valid_version_record(text: str) -> bool:
    """这条 TXT 是否"以 v 标签标识当前版本"（§4.10 步骤 2 的过滤条件）。"""
    return parse_record(text) is not None


# ── tree walk（§4.10 步骤 1–7） ──────────────────────────────────────────


def walk(snap: Snapshot, start: str,
         trace: list[dict[str, Any]] | None = None, *,
         label: str | None = None) -> Walk:
    """从 ``start`` 这个**域**开始做一次 DNS Tree Walk（§4.10）。

    ``label`` 是 trace 节点 id 的前缀（默认 = ``start`` 域名）。**一次评估会做多次
    走查**（Author 一次、每个 Authenticated Identifier 各一次），若都用 ``walk.0`` /
    ``walk.1``，两份走查在 trace 里会撞 id——K12 要求节点 id **只由路径决定**且可指认，
    撞 id 会让"这条 trace 属于哪次走查"变成猜的。所以 id 形如
    ``walk.<start 域名>.<跳序号>``。

    走查一直走到"标签用尽"或"遇到 ``psd=n``/``psd=y``"，而不是"发现第一条记录就停"：
    §4.10.2 的 Organizational Domain 选择要按"从长到短"看**全部**命中记录
    （``psd=n`` 优先、其次非起点的 ``psd=y``、否则取标签最少的那条）。早停会让
    "``_dmarc.bank.example`` 上 ``psd=y``"这类形态选错 Organizational Domain
    （B.4.3 就是这个形态）。§4.10.1 的策略**偏好**顺序由 :func:`_discover_policy`
    在这份完整走查结果上施加——两者的"停"是不同层面的。

    单跳状态判定顺序（顺序本身就是错误优先级）：

    1. 快照没这条查询 → ``not_queried``（数据缺口，K13）
    2. rcode 是 DNS 错误 → ``dns_error``（§5.3.6：不能算 pass 也不能算 fail）
    3. NXDOMAIN → ``nxdomain``（"问过了没有"）
    4. NOERROR 但答复为空 → ``no_record``
    5. 有 TXT 但没有一条以 ``v=DMARC1`` 开头 → ``invalid_record``（全部丢弃）
    6. 多条通过 ``v=`` 过滤 → ``multiple_records``（§4.10 步骤 2：**全部丢弃**）
    7. 恰好一条 → ``record``
    """
    hops: list[Hop] = []
    target = _normalize(start)
    stopped_by = "labels_exhausted"

    while target:
        qname = "%s.%s" % (DMARC_RECORD_LABEL, target)
        hop = _query_hop(snap, qname, target, index=len(hops), trace=trace,
                         label=label if label is not None else _normalize(start))
        hops.append(hop)

        if hop.status == "record" and hop.psd in ("y", "n"):
            # §4.10 步骤 6：单条记录且带 psd=n / psd=y → 停。
            stopped_by = "psd"
            break

        shortened = _shorten(target)
        if shortened is None:
            stopped_by = "labels_exhausted"
            break
        target = shortened

    return Walk(start=_normalize(start), hops=tuple(hops), stopped_by=stopped_by)


def select_organizational_domain(result_walk: Walk) -> str | None:
    """按 §4.10.2 从一次走查的命中记录里选出 Organizational Domain。

    原文三段（"from the longest to the shortest"）：

    1. 有效记录带 ``psd=n`` → 该域就是 Organizational Domain；
    2. 有效记录带 ``psd=y`` **且不是走查起点那一条** → Organizational Domain 是它
       **下面一层**的域名（B.4.3：`bank.example` 上 `psd=y` → `giant.bank.example`）；
    3. 否则取**标签最少**的那条记录的域（B.4.1：`signing.example.com` 与
       `example.com` 都有记录 → `example.com`）。

    一条记录都没有 → ``None``（调用方按"没有 Organizational Domain"处理，
    relaxed 对齐因此不可能成立）。
    """
    records = result_walk.records
    if not records:
        return None

    # 标签多的在前（"from the longest to the shortest"），同长度按走查顺序。
    ordered = sorted(records, key=lambda hop: (-len(_labels(hop.domain)), hop.index))

    for hop in ordered:
        if hop.psd == "n":
            return hop.domain

    for hop in ordered:
        if hop.psd == "y" and hop.domain != result_walk.start:
            below = _one_label_below(hop.domain, result_walk.start)
            if below is not None:
                return below
            # 起点不在这条记录之下（例如起点本身已被 8 标签规则截短过）：
            # 退回"该记录本身"会把 psd=y 的语义反了，所以跳过并继续找。

    return ordered[-1].domain


def _query_hop(snap: Snapshot, qname: str, domain: str, *, index: int,
               trace: list[dict[str, Any]] | None, label: str) -> Hop:
    resolved = snap.resolve(qname, "TXT", trace=trace)
    node: dict[str, Any] = {"node": "walk.%s.%d" % (label, index)}

    if not resolved.found:
        node["note"] = "%s 未在快照中查询（数据缺口，不等同于没有记录）" % qname
        _emit(trace, node)
        return Hop(index=index, domain=domain, qname=qname, status="not_queried",
                   note="快照里没有这条查询")

    if resolved.rcode in DMARC_DNS_ERROR_RCODES:
        node["note"] = "%s → rcode=%s（DNS 错误：不能据此判 pass 或 fail）" % (
            qname, resolved.rcode)
        _emit(trace, node)
        return Hop(index=index, domain=domain, qname=qname, status="dns_error",
                   rcode=resolved.rcode, note="DNS 错误，结论不可判定")

    if resolved.is_nxdomain:
        node["note"] = "%s → NXDOMAIN（问过了，没有这个域）" % qname
        _emit(trace, node)
        return Hop(index=index, domain=domain, qname=qname, status="nxdomain",
                   rcode=resolved.rcode, note="该域不存在")

    if not resolved.is_noerror:
        node["note"] = "%s → rcode=%s（非 NOERROR，按 DNS 错误处理）" % (
            qname, resolved.rcode)
        _emit(trace, node)
        return Hop(index=index, domain=domain, qname=qname, status="dns_error",
                   rcode=resolved.rcode, note="非 NOERROR 答复")

    if not resolved.answer:
        node["note"] = "%s → NOERROR 但答复为空（问过了，没有记录）" % qname
        _emit(trace, node)
        return Hop(index=index, domain=domain, qname=qname, status="no_record",
                   rcode=resolved.rcode, note="空答复")

    candidates = [record for record in map(parse_record, resolved.answer)
                  if record is not None]
    if not candidates:
        node["note"] = ("%s → %d 条 TXT，但都不以 v=%s 开头（§4.7：整条忽略）"
                        % (qname, len(resolved.answer), DMARC_VERSION))
        _emit(trace, node)
        return Hop(index=index, domain=domain, qname=qname, status="invalid_record",
                   rcode=resolved.rcode, note="记录存在但 v= 不合格")

    if len(candidates) > 1:
        node["note"] = ("%s → %d 条通过 v= 过滤的记录（§4.10 步骤 2：同一目标多条 → 全部丢弃）"
                        % (qname, len(candidates)))
        _emit(trace, node)
        return Hop(index=index, domain=domain, qname=qname, status="multiple_records",
                   rcode=resolved.rcode, note="同一目标返回多条记录")

    record = candidates[0]
    node["note"] = "%s → 记录 `%s`（psd=%s）" % (qname, record.text, record.psd)
    _emit(trace, node)
    return Hop(index=index, domain=domain, qname=qname, status="record",
               record=record.text, psd=record.psd, rcode=resolved.rcode)


def _emit(trace: list[dict[str, Any]] | None, node: dict[str, Any]) -> None:
    if trace is not None:
        trace.append(node)


def _shorten(domain: str) -> str | None:
    """§4.10 步骤 4：``x < 8`` 删最左一个标签；``x >= 8`` 删到只剩 7 个。

    返回 ``None`` 表示没有标签可删（走查结束）。
    """
    labels = _labels(domain)
    if len(labels) <= 1:
        return None
    if len(labels) < DMARC_MAX_LABELS:
        remaining = labels[1:]
    else:
        keep = min(DMARC_TREE_KEEP_LABELS, len(labels) - 1)
        remaining = labels[len(labels) - keep:]
    return ".".join(remaining) if remaining else None


def _one_label_below(target: str, descendant: str) -> str | None:
    """``descendant`` 里比 ``target`` 多一个标签的那一层（§4.10.2 步骤 2）。"""
    target_labels = _labels(target)
    start_labels = _labels(descendant)
    if not target_labels or len(start_labels) <= len(target_labels):
        return None
    return ".".join(start_labels[len(start_labels) - len(target_labels) - 1:])


# ── Author Domain（§5.3.1） ─────────────────────────────────────────────


def from_domains(message: Any) -> tuple[list[str], list[str]]:
    """从 ``RFC5322.From`` 取 Author Domain（§5.3.1）。

    返回 ``(域列表, 说明列表)``。**零个**或**多于一个**域时 DMARC 判定不成立
    （原文："DMARC validation is not possible and the process terminates"），
    调用方据此判 ``none`` / ``undecidable``——**不猜**哪个是"真的"。
    """
    values: list[str] = list(message.get_all("From"))
    if not values:
        return [], ["报文没有 From 头字段（§5.3.1 要求从 RFC5322.From 取 Author Domain）"]

    notes: list[str] = []
    domains: list[str] = []
    for value in values:
        for spec in _addr_specs(value):
            domain = spec.rpartition("@")[2].strip().rstrip(".").lower()
            if not domain:
                notes.append("From 里的地址 %r 没有域部分" % (spec,))
                continue
            converted, note = _to_a_label(domain)
            if note:
                notes.append(note)
            if converted and converted not in domains:
                domains.append(converted)
    if len(values) > 1:
        notes.append("报文有 %d 个 From 头字段（§5.3.1：多于一个域时判定不成立）"
                     % len(values))
    if len(domains) > 1:
        notes.append("From 里出现 %d 个不同的域：%s" % (len(domains), "、".join(domains)))
    return domains, notes


def _addr_specs(value: str) -> list[str]:
    """从 From 头值里取出 addr-spec 列表（``显示名 <a@b>`` 与裸 ``a@b`` 两种形态）。"""
    specs: list[str] = []
    cursor = 0
    while True:
        start = value.find("<", cursor)
        if start < 0:
            break
        end = value.find(">", start)
        if end < 0:
            break
        specs.append(value[start + 1:end].strip())
        cursor = end + 1
    if specs:
        return specs
    for piece in value.split(","):
        token = piece.strip()
        if not token or "@" not in token:
            continue
        specs.append(token.split()[-1])
    return specs


def _to_a_label(domain: str) -> tuple[str | None, str | None]:
    """§5.3.1：U-label 必须转成 A-label 再处理。"""
    try:
        domain.encode("ascii")
        return domain, None
    except UnicodeEncodeError:
        pass
    try:
        return (domain.encode("idna").decode("ascii"),
                "From 域是非 ASCII（U-label），已按 §5.3.1 转成 A-label")
    except (UnicodeError, ValueError) as exc:
        return None, "From 域 %r 无法转成 A-label（%s）" % (domain, exc)


# ── 对齐（§4.4 / §4.10.2） ─────────────────────────────────────────────


def align(author_domain: str, author_org: str | None, identifier: str, *,
          source: str, walk_cache: dict[str, Walk], snap: Snapshot,
          psl: PSL | None, trace: list[dict[str, Any]] | None) -> Alignment:
    """算一个 Authenticated Identifier 与 Author Domain 的**两种**对齐。

    - ``strict``（§3.2.10.2）：两者**完全相同**（域名比较大小写不敏感，§4.4）。
    - ``relaxed``（§3.2.10.1）：两者有同一个 Organizational Domain（§4.10.2 的走查）。

    ``psl`` 只用于在"tree walk 与 PSL 给出不同 Organizational Domain"时补一条告警
    ——RFC 9989 以 tree walk 为准，但差异本身值得让读者看见。
    """
    identifier = _normalize(identifier)
    if identifier in walk_cache:
        identifier_walk = walk_cache[identifier]
    else:
        identifier_walk = walk(snap, identifier, trace=trace)
        walk_cache[identifier] = identifier_walk
    identifier_org = select_organizational_domain(identifier_walk)

    strict = author_domain == identifier
    relaxed = (author_org is not None and identifier_org is not None
               and author_org == identifier_org)

    notes: list[str] = []
    if author_org is None:
        notes.append("Author Domain 没有 Organizational Domain（走查无命中），relaxed 不可能成立")
    elif identifier_org is None:
        notes.append("%s 没有 Organizational Domain（走查无命中），relaxed 不可能成立"
                     % identifier)
    if psl is not None and author_org is not None and identifier_org is not None:
        psl_author = psl.organizational_domain(author_domain)
        psl_identifier = psl.organizational_domain(identifier)
        if (psl_author is not None and psl_identifier is not None
                and psl_author != psl_identifier):
            notes.append(
                "PSL 口径下 %s 与 %s 不同域（%s / %s），但 RFC 9989 §4.10.2 的 tree walk "
                "判定为同一 Organizational Domain（%s）——以 tree walk 为准"
                % (author_domain, identifier, psl_author, psl_identifier, author_org))

    if trace is not None:
        trace.append({
            "node": "align.%s" % source,
            "note": "%s：%s vs %s → relaxed=%s / strict=%s（Organizational Domain：%s / %s）"
                    % (source, author_domain, identifier,
                       _flag(relaxed), _flag(strict), author_org, identifier_org),
        })

    return Alignment(identifier=identifier, source=source,
                     organizational_domain=identifier_org,
                     relaxed=relaxed, strict=strict, note="；".join(notes))


# ── 主入口 ──────────────────────────────────────────────────────────────


def evaluate(
    snap: Snapshot,
    message: Any,
    query: Any,
    *,
    spf: Any | None = None,
    dkim: Any | None = None,
    psl: PSL | None = None,
    trace: list[dict[str, Any]] | None = None,
) -> DmarcResult:
    """按 RFC 9989 求一次 DMARC。

    参数
    ----
    snap / message / query
        输入三件套。DMARC 的输入是**已算好的** SPF/DKIM 结论 + 快照里的 `_dmarc` 查询。
    spf
        :class:`mailvault.modules.spf.SpfResult`。``None`` → 无从判断对齐，结论
        ``undecidable``（不猜）。
    dkim
        :class:`mailvault.modules.dkim.DkimResult`。同上。
    psl
        PSL 视图，默认加载随包冻结件。**只用于对照**，不参与判定。
    trace
        共享轨迹列表（CLI 让三个模块写同一条轨迹）。
    """
    shared = trace if trace is not None else []
    psl = psl if psl is not None else default_psl()

    psl_version = snap.psl_version
    psl_date = snap.psl_date
    warnings: list[str] = []
    if (psl_version, psl_date) != (psl.version, psl.date):
        warnings.append(
            "快照记录的 PSL 版本 %s / %s 与随包冻结件 %s / %s 不同：PSL 只用于对照，"
            "判定以 RFC 9989 §4.10.2 的 tree walk 为准；若两版 PSL 对某域的切分不同，"
            "本节给出的 PSL 对照值会与快照使用者的认知不一致"
            % (psl_version, psl_date, psl.version, psl.date))

    author_domain, from_notes = from_domains(message)
    warnings.extend(from_notes)
    shared.append({"node": "dmarc.author",
                   "note": "RFC5322.From 提取到 %d 个域：%s"
                           % (len(author_domain), "、".join(author_domain) or "（无）")})

    if not author_domain:
        return _degenerate(
            result="none",
            reason="报文没有可提取的 Author Domain（§5.3.1）→ DMARC 机制不适用，判 none",
            refs=[REF_AUTHOR], psl_version=psl_version, psl_date=psl_date,
            trace=shared, warnings=warnings)

    if len(author_domain) > 1:
        return _degenerate(
            result="undecidable",
            reason="RFC5322.From 里出现 %d 个不同的域（%s）；§5.3.1 规定此时 DMARC "
                   "判定不成立，本工具不猜哪一个才是 Author Domain"
                   % (len(author_domain), "、".join(author_domain)),
            refs=[REF_AUTHOR], psl_version=psl_version, psl_date=psl_date,
            trace=shared, warnings=warnings)

    author = author_domain[0]

    # ── §4.10.2：Author Domain 的 Organizational Domain（完整走查） ──
    walk_cache: dict[str, Walk] = {}
    author_walk = walk(snap, author, trace=shared)
    walk_cache[author] = author_walk
    author_org = select_organizational_domain(author_walk)
    shared.append({"node": "dmarc.org",
                   "note": "Author Domain %s 的 Organizational Domain：%s"
                           % (author, author_org or "（走查无命中）")})

    # ── §4.10.1：策略记录的发现顺序 Author → Organizational → PSD ──
    record, policy_domain, policy_source = _discover_policy(author, author_org, author_walk)
    if record is not None:
        warnings.extend(_record_warnings(record, policy_domain or author))

    psl_org = psl.organizational_domain(author)

    # ── 数据缺口 / DNS 错误优先于一切判定（K13 + §5.3.6） ──
    gaps = _collect_gaps(author_walk)
    if gaps:
        return _undecidable(
            reason="tree walk 有 %d 跳在快照里没有查询（%s）：这是**数据缺口**，"
                   "不等于该域没有 DMARC 记录；补抓这些键后重跑即可判定"
                   % (len(gaps), "、".join("_dmarc.%s" % hop.domain
                                           for hop in author_walk.hops if hop.is_data_gap)),
            refs=[REF_TREE_WALK, REF_DISCOVERY],
            snap=snap, psl=psl, author=author, author_org=author_org,
            policy_domain=policy_domain, policy_source=policy_source, record=record,
            result_walk=author_walk, psl_version=psl_version, psl_date=psl_date,
            psl_org=psl_org, trace=shared, warnings=warnings, data_gaps=gaps)

    errors = author_walk.dns_errors
    if errors:
        return _undecidable(
            reason="tree walk 有 %d 跳是 DNS 错误（rcode=%s）：§5.3.6 规定此时报文"
                   "\"cannot be considered to pass or fail\"，处置策略也无法施加"
                   % (len(errors), "、".join(str(hop.rcode) for hop in errors)),
            refs=[REF_TREE_WALK, REF_APPLY],
            snap=snap, psl=psl, author=author, author_org=author_org,
            policy_domain=policy_domain, policy_source=policy_source, record=record,
            result_walk=author_walk, psl_version=psl_version, psl_date=psl_date,
            psl_org=psl_org, trace=shared, warnings=warnings)

    if record is None:
        return DmarcResult(
            result="none",
            reason="tree walk 逐跳都没有有效 DMARC Policy Record（%d 跳：%s）；"
                   "§4.10.1：Mail Receivers MUST NOT apply the DMARC mechanism → none"
                   % (len(author_walk.hops),
                      "、".join("%s=%s" % (hop.qname, hop.status)
                                for hop in author_walk.hops)),
            author_domain=author,
            organizational_domain=author_org,
            policy_domain=None,
            policy_source=None,
            policy_tag=None,
            policy_value=None,
            disposition=None,
            disposition_status="not_applicable",
            test_mode=False,
            record=None,
            walk=author_walk,
            alignments=(),
            spf_align={"relaxed": False, "strict": False},
            dkim_align={"relaxed": False, "strict": False},
            psl_version=psl_version,
            psl_date=psl_date,
            psl_organizational_domain=psl_org,
            evidence_ref=(REF_TREE_WALK, REF_DISCOVERY),
            trace=tuple(shared),
            warnings=tuple(warnings),
        )

    # ── 对齐（§4.4 / §4.10.2）：SPF 与 DKIM 各出两种模式 ──
    alignments, spf_align, dkim_align, align_notes = _align_all(
        snap=snap, query=query, spf=spf, dkim=dkim, author=author,
        author_org=author_org, walk_cache=walk_cache, psl=psl, trace=shared)
    warnings.extend(align_notes)

    adkim_mode = _align_mode(record.value("adkim"), "adkim", warnings)
    aspf_mode = _align_mode(record.value("aspf"), "aspf", warnings)
    evidence = [REF_TREE_WALK, REF_DISCOVERY, REF_ALIGN, REF_ALIGN_CONCEPT, REF_VERDICT]

    if spf is None or dkim is None:
        missing = "、".join(name for name, value in (("SPF", spf), ("DKIM", dkim))
                            if value is None)
        return _undecidable(
            reason="缺少 %s 的求值结论，无法判断 §5.3.5 的\"是否有对齐的 Authenticated "
                   "Identifier\"；本工具不假定它 pass 也不假定它 fail" % missing,
            refs=evidence,
            snap=snap, psl=psl, author=author, author_org=author_org,
            policy_domain=policy_domain, policy_source=policy_source, record=record,
            result_walk=author_walk, psl_version=psl_version, psl_date=psl_date,
            psl_org=psl_org, trace=shared, warnings=warnings,
            alignments=alignments, spf_align=spf_align, dkim_align=dkim_align)

    # §4.10.1 的 adkim= / aspf= 各自只影响自己那一侧（不交叉）。
    spf_aligned = spf_align[aspf_mode]
    dkim_aligned = dkim_align[adkim_mode]
    decided = spf_aligned or dkim_aligned
    shared.append({
        "node": "dmarc.verdict",
        "note": "aspf=%s / adkim=%s；SPF 在本侧模式下对齐=%s、DKIM 在对齐模式下对齐=%s → %s"
                % (aspf_mode, adkim_mode, _flag(spf_aligned), _flag(dkim_aligned),
                   "pass" if decided else "fail"),
    })

    if decided:
        return DmarcResult(
            result="pass",
            reason="至少一个 Authenticated Identifier 与 Author Domain 对齐"
                   "（SPF 侧 %s 模式=%s / DKIM 侧 %s 模式=%s）；§5.3.5 判 pass，不施加处置策略"
                   % (aspf_mode, _flag(spf_aligned), adkim_mode, _flag(dkim_aligned)),
            author_domain=author,
            organizational_domain=author_org,
            policy_domain=policy_domain,
            policy_source=policy_source,
            policy_tag=None,
            policy_value=None,
            disposition=None,
            disposition_status="not_applicable",
            test_mode=False,
            record=record,
            walk=author_walk,
            alignments=alignments,
            spf_align=spf_align,
            dkim_align=dkim_align,
            psl_version=psl_version,
            psl_date=psl_date,
            psl_organizational_domain=psl_org,
            evidence_ref=tuple(evidence),
            trace=tuple(shared),
            warnings=tuple(warnings),
        )

    # ── 失败：§4.10.1 选策略标签 → §4.7 应用（含 t= 降级） ──
    selection = _select_policy(snap, record, author, policy_domain)
    warnings.extend(selection["warnings"])
    disposition = selection["disposition"]
    test_mode = _test_mode(record, warnings)
    if test_mode and disposition is not None:
        original = disposition
        disposition = DMARC_TEST_MODE_DOWNGRADE[original]
        if disposition != original:
            shared.append({"node": "dmarc.test_mode",
                           "note": "t=y：策略从 %s 降级为 %s（§4.7）"
                                   % (original, disposition)})
        warnings.append("t=y：§4.7 要求把 %s 降一级施加，实际处置 %s"
                        % (original, disposition))

    refs = list(evidence) + [REF_TAGS]
    if selection["tag"] == "np":
        refs.append(REF_NONEXISTENT)
    if selection["status"] == "determined":
        refs.append(REF_APPLY)

    return DmarcResult(
        result="fail",
        reason=_finalize_reason(selection["reason"], disposition),
        author_domain=author,
        organizational_domain=author_org,
        policy_domain=policy_domain,
        policy_source=policy_source,
        policy_tag=selection["tag"],
        policy_value=selection["value"],
        disposition=disposition,
        disposition_status=selection["status"],
        test_mode=test_mode,
        record=record,
        walk=author_walk,
        alignments=alignments,
        spf_align=spf_align,
        dkim_align=dkim_align,
        psl_version=psl_version,
        psl_date=psl_date,
        psl_organizational_domain=psl_org,
        evidence_ref=tuple(refs),
        trace=tuple(shared),
        warnings=tuple(warnings),
    )


# ── 策略发现 / 策略选择 ─────────────────────────────────────────────────


def _discover_policy(author: str, author_org: str | None,
                     author_walk: Walk) -> tuple[Record | None, str | None, str | None]:
    """§4.10.1 的优先级：Author → Organizational → PSD。

    返回 ``(记录, 策略域, 来源)``；来源是 ``author`` / ``organizational`` / ``psd``。
    """
    own = author_walk.record_at(author)
    if own is not None and own.record:
        return parse_record(own.record), author, "author"

    if author_org is not None and author_org != author:
        at_org = author_walk.record_at(author_org)
        if at_org is not None and at_org.record:
            return parse_record(at_org.record), author_org, "organizational"

    # PSD：走查里带 psd=y 的那条（且不是 Author 自己）。
    for hop in author_walk.records:
        if hop.psd == "y" and hop.domain != author and hop.record:
            return parse_record(hop.record), hop.domain, "psd"

    return None, None, None


def _select_policy(snap: Snapshot, record: Record, author: str,
                   policy_domain: str | None) -> dict[str, Any]:
    """§4.10.1：从 ``p`` / ``sp`` / ``np`` 里选出要施加的处置策略。

    选择规则（照原文）：

    - 策略记录就是 Author Domain 自己的 → 取 ``p``；
    - 否则 Author Domain 是它的子域：**存在** → ``sp``（没有则 ``p``）；
      **不存在** → ``np``（没有则 ``sp``，再没有则 ``p``，见 §4.7 的 np 定义）；
    - ``p`` 缺失 → §4.7 "the record is treated as if it included ``p=none``"；
    - 选中的值非法 → §4.10.1：``rua`` 有有效 URI 则按 ``p=none`` 继续，否则不施加处理。

    **``disposition_status`` 为 ``undecidable`` 时 ``disposition`` 必为 ``None``——不猜。**
    唯一会判不出来的情形：记录带 ``np=``，但快照里没有 Author Domain 本身的查询，
    于是"它存在还是不存在"未知，而 ``np=`` 与 ``sp=/p=`` 给出**不同**的策略。
    两者恰好给出同一个处置时不算歧义（结论一样），此时给告警并按已确定的那个值继续。
    """
    warnings: list[str] = []
    is_own_record = policy_domain is None or _normalize(policy_domain) == author

    if is_own_record:
        return _decide(record, "p", record.value("p"), policy_domain, author, warnings,
                       own_record=True)

    existence, existence_note = _author_existence(snap, author)
    if existence_note:
        warnings.append(existence_note)

    np_value = record.value("np")
    sp_value = record.value("sp")
    p_value = record.value("p")

    # 若 Author Domain 存在（或未知但当作存在）：sp= → p=
    fallback_tag, fallback_value = (("sp", sp_value) if sp_value is not None
                                    else ("p", p_value))

    if existence == "unknown" and np_value is not None:
        np_disposition = _policy_disposition(np_value)
        fallback_disposition = _policy_disposition(fallback_value)
        if np_disposition is not None and np_disposition == fallback_disposition:
            warnings.append(
                "np=%r 与 %s=%r 给出同一处置 %s：即使 Author Domain 的存在性未知，"
                "两条分支结论相同，因此仍可判定（§4.10.1 的歧义在此不成立）"
                % (np_value, fallback_tag, fallback_value, np_disposition))
            return _decide(record, "np", np_value, policy_domain, author, warnings,
                           own_record=False)
        return {
            "tag": "np",
            "value": np_value,
            "disposition": None,
            "status": "undecidable",
            "warnings": warnings,
            "reason": "DMARC 判 fail，但记录带 np=%r：要判定该用它还是 %s=%r，"
                      "必须先知道 Author Domain %s 是否存在（§3.2.13：以该名字的查询"
                      "答复为准），而快照里没有这条查询。两条分支给出不同处置，本工具不猜"
                      % (np_value, fallback_tag, fallback_value, author),
        }

    if existence == "nxdomain" and np_value is not None:
        return _decide(record, "np", np_value, policy_domain, author, warnings,
                       own_record=False)
    if existence == "nxdomain":
        warnings.append("Author Domain %s 不存在（快照答复 NXDOMAIN）且记录没有 np=："
                        "§4.7 规定回落到 %s=" % (author, fallback_tag))
    return _decide(record, fallback_tag, fallback_value, policy_domain, author, warnings,
                   own_record=False)


def _decide(record: Record, tag: str, value: str | None, policy_domain: str | None,
            author: str, warnings: list[str], *, own_record: bool) -> dict[str, Any]:
    """把选中的标签值落成处置；处理"缺标签"与"值非法"两种情形。"""
    who = "Author Domain" if own_record else "策略域 %s" % (policy_domain or author)

    if value is None:
        if tag in ("p", "sp"):
            warnings.append("%s 没有 %s= 标签：§4.7 规定按 p=none 处理（不是判不了）"
                            % (who, tag))
            return _determined(record, tag, "none", "none", warnings,
                               "DMARC 判 fail；%s 的 %s= 缺失，"
                               "§4.7 按 p=none 处理 → 处置 none" % (who, tag))
        # np= 为 None 的情况不会走到这里（调用方已按 sp=/p= 回落）。
        return _determined(record, tag, None, "none", warnings,
                           "DMARC 判 fail；无可用策略标签 → 处置 none")

    if value not in _POLICY_VALUES:
        warnings.append("%s=%r 不是合法策略（§4.8 的 dmarc-request 只允许 %s）"
                        % (tag, value, " / ".join(DMARC_DISPOSITIONS)))
        if _has_valid_report_uri(record.value("rua")):
            warnings.append("§4.10.1：%s=%r 非法但 rua= 含有效 URI → 按 p=none 继续处理"
                            % (tag, value))
            return _determined(record, "p", "none", "none", warnings,
                               "DMARC 判 fail；%s 的 %s=%r 非法，但记录带有效 rua=，"
                               "§4.10.1 规定按 p=none 处理 → 处置 none"
                               % (who, tag, value))
        warnings.append("§4.10.1：%s=%r 非法且 rua= 不可用 → 本工具不施加 DMARC 处理"
                        % (tag, value))
        return {
            "tag": tag, "value": value, "disposition": None,
            "status": "not_applicable", "warnings": warnings,
            "reason": "DMARC 判 fail；%s 的 %s=%r 非法且没有可用的 rua=，"
                      "§4.10.1 规定不施加 DMARC 处理" % (who, tag, value),
        }

    return _determined(record, tag, value, value, warnings,
                       "DMARC 判 fail；%s 的 %s=%s → 处置 %s"
                       % (who, tag, value, value))


def _determined(record: Record, tag: str, value: str | None, disposition: str,
                warnings: list[str], reason: str) -> dict[str, Any]:
    del record
    return {
        "tag": tag, "value": value, "disposition": disposition,
        "status": "determined", "warnings": warnings, "reason": reason,
    }


def _policy_disposition(value: str | None) -> str | None:
    """把一个策略标签值折算成"若采用它，处置会是什么"（非法 → ``None``）。"""
    if value is None:
        return "none"  # §4.7：缺 p= 视同 p=none
    return value if value in _POLICY_VALUES else None


def _finalize_reason(reason: str, disposition: str | None) -> str:
    """理由里不带处置值——处置有独立字段（``disposition``），写两处必然漂移。

    ``t=y`` 降级时在 :func:`evaluate` 里单独追加一条 warning 说明降级，
    理由本身保持"策略取自哪里、取了什么"这一层。
    """
    del disposition
    return reason


def _author_existence(snap: Snapshot, author: str) -> tuple[str, str | None]:
    """Author Domain 是否存在（§3.2.13：以该名字的查询答复为准）。

    只看 ``qname == author`` 的查询（任意类型）。返回 ``exists`` / ``nxdomain`` / ``unknown``。
    """
    seen = False
    for entry in snap.queries:
        if _normalize(str(entry.get("qname", ""))) != author:
            continue
        seen = True
        if str(entry.get("rcode", "")).upper() == "NXDOMAIN":
            return "nxdomain", None
    if seen:
        return "exists", None
    return "unknown", ("快照里没有 Author Domain %s 本身的查询：sp= / np= 的选择依赖它是否存在"
                       "（§3.2.13）" % author)


def _has_valid_report_uri(value: str | None) -> bool:
    """``rua=`` 是否含至少一个**语法上**可用的 URI（§4.10.1 的兜底条件）。

    只做形态判断（``scheme:`` 后非空），不解析具体方案——§4.7 说
    "URIs involving schemes not supported by Mail Receivers MUST be ignored"，
    支持哪些方案是实现自由，不属于判定。
    """
    if not value:
        return False
    for item in value.split(","):
        candidate = item.strip()
        scheme, separator, rest = candidate.partition(":")
        if separator and scheme.strip() and rest.strip():
            return True
    return False


def _test_mode(record: Record, warnings: list[str]) -> bool:
    value = record.value("t")
    if value is None:
        return False
    if value not in ("y", "n"):
        warnings.append("t=%r 非法（§4.8 只允许 y / n），按默认 t=n 处理" % (value,))
        return False
    return value == "y"


def _align_mode(value: str | None, name: str, warnings: list[str]) -> str:
    """``adkim=`` / ``aspf=`` → ``relaxed`` / ``strict``（§4.7）。"""
    if value is None:
        return "relaxed"
    if value == "s":
        return "strict"
    if value == "r":
        return "relaxed"
    warnings.append("%s=%r 非法（§4.8 只允许 r / s），按默认 %s 处理"
                    % (name, value, DMARC_DEFAULT_ALIGN))
    return "relaxed"


def _record_warnings(record: Record, policy_domain: str) -> list[str]:
    """记录级告警：旧标签 + 解析期忽略的片段 + 未知标签。"""
    warnings: list[str] = []
    for tag in DMARC_REMOVED_TAGS:
        if tag not in record.tags:
            continue
        if tag == "pct":
            warnings.append(
                "pct=%r：该标签已被 RFC 9989 删除（Appendix A.6 与 C.5.2），"
                "本工具**不**按百分比施加策略——按完整策略处理。记录在 %s"
                % (record.tags[tag], policy_domain))
        else:
            warnings.append(
                "%s=%r：该标签已被 RFC 9989 删除（Appendix C.5.2），"
                "本工具不解释其语义，也不静默忽略。记录在 %s"
                % (tag, record.tags[tag], policy_domain))
    for fragment in record.malformed:
        warnings.append("记录 %s 有可忽略的语法问题：%s（§4.8 按默认值处理）"
                        % (policy_domain, fragment))
    # 已删除的标签（pct/rf/ri）上面已经逐条报过"已被删除"，不再重复报成"未知标签"
    # ——同一个事实报两次会让读者以为是两个问题。
    for name in sorted(name for name in record.tags
                       if name not in _KNOWN_TAGS and name not in DMARC_REMOVED_TAGS):
        warnings.append("%s= 不在本工具已知标签内（§4.7：unknown tags MUST be ignored）"
                        % name)
    return warnings


def _collect_gaps(result_walk: Walk) -> tuple[tuple[str, str], ...]:
    return tuple((hop.qname, "TXT") for hop in result_walk.hops if hop.is_data_gap)


# ── 对齐的批量计算 ──────────────────────────────────────────────────────


def _align_all(*, snap: Snapshot, query: Any, spf: Any | None, dkim: Any | None,
               author: str, author_org: str | None,
               walk_cache: dict[str, Walk], psl: PSL,
               trace: list[dict[str, Any]]) -> tuple[
                   tuple[Alignment, ...], dict[str, bool], dict[str, bool], list[str]]:
    alignments: list[Alignment] = []
    notes: list[str] = []
    spf_align = {"relaxed": False, "strict": False}
    dkim_align = {"relaxed": False, "strict": False}

    # ── SPF 侧：§4.4.2 "DMARC relies solely on SPF validation of the MAIL FROM identity"
    sender_domain = _normalize(getattr(query, "sender_domain", "") or "")
    helo = getattr(query, "helo", None)
    if sender_domain:
        identifier_domain = sender_domain
        note_prefix = ""
    else:
        # **空反向路径不是"没有 SPF 身份"**：RFC 9989 §3.2.4 把 SPF 域定义为
        # "an SPF-validated MAIL FROM identity"，并指向 RFC 7208 §2.4——那里写着
        # "When the reverse-path is null, this document defines the 'MAIL FROM' identity
        # to be the mailbox composed of the local-part 'postmaster' and the 'HELO'
        # identity"。所以此时 SPF 域**就是 HELO 域**，仍然是一个 Authenticated Identifier。
        # 早先版本按"空发件人 → 没有身份"实现，会把这类报文的 DMARC 判得比 RFC 严。
        identifier_domain = _normalize(helo or "")
        note_prefix = ("MAIL FROM 为空（null 反向路径）：按 RFC 7208 §2.4（§3.2.4 引用），"
                       "SPF 的 MAIL FROM 身份是 postmaster@<HELO>，故 SPF 域取 HELO 域 %s"
                       % (identifier_domain or "（HELO 也为空）"))

    if identifier_domain:
        alignment = align(author, author_org, identifier_domain, source="spf",
                          walk_cache=walk_cache, snap=snap, psl=psl, trace=trace)
        alignments.append(alignment)
        if note_prefix:
            notes.append(note_prefix)
        if spf is not None and _spf_passed(spf):
            spf_align["relaxed"] = alignment.relaxed
            spf_align["strict"] = alignment.strict
        elif spf is not None:
            notes.append("SPF 结论是 %s（非 pass）：%s 不构成 "
                         "SPF-Authenticated Identifier（§4.4.2），两侧对齐均为 false"
                         % (spf.result, identifier_domain))
    else:
        notes.append(
            "反向路径为空且没有 HELO 名：RFC 7208 §2.4 下 SPF 的 MAIL FROM 身份无从确定，"
            "没有 SPF-Authenticated Identifier，spf 两侧对齐均为 false")

    # ── DKIM 侧：每条 pass 的签名各是一个 DKIM-Authenticated Identifier（§4.4.1） ──
    if dkim is None:
        return tuple(alignments), spf_align, dkim_align, notes

    passed = [signature for signature in getattr(dkim, "signatures", ())
              if signature.result == "pass" and signature.domain]
    if not passed:
        notes.append("没有结论为 pass 的 DKIM 签名：不构成 DKIM-Authenticated Identifier"
                     "（§4.4.1），两侧对齐均为 false")
    for signature in passed:
        alignment = align(author, author_org, signature.domain, source="dkim",
                          walk_cache=walk_cache, snap=snap, psl=psl, trace=trace)
        alignments.append(alignment)
        dkim_align["relaxed"] = dkim_align["relaxed"] or alignment.relaxed
        dkim_align["strict"] = dkim_align["strict"] or alignment.strict
    if len(passed) > 1:
        notes.append("报文有 %d 条 pass 的 DKIM 签名：任意一条对齐即满足（§4.4.1 "
                     "\"if any DKIM-Authenticated Identifier aligns\"）" % len(passed))
    return tuple(alignments), spf_align, dkim_align, notes


def _spf_passed(spf: Any) -> bool:
    return getattr(spf, "result", None) == "pass"


# ── 退化路径 ────────────────────────────────────────────────────────────


def _degenerate(*, result: str, reason: str, refs: list[str], psl_version: str,
                psl_date: str, trace: list[dict[str, Any]],
                warnings: list[str]) -> DmarcResult:
    return DmarcResult(
        result=result,
        reason=reason,
        author_domain=None,
        organizational_domain=None,
        policy_domain=None,
        policy_source=None,
        policy_tag=None,
        policy_value=None,
        disposition=None,
        disposition_status="undecidable" if result == "undecidable" else "not_applicable",
        test_mode=False,
        record=None,
        walk=None,
        alignments=(),
        spf_align={"relaxed": False, "strict": False},
        dkim_align={"relaxed": False, "strict": False},
        psl_version=psl_version,
        psl_date=psl_date,
        psl_organizational_domain=None,
        evidence_ref=tuple(refs),
        trace=tuple(trace),
        warnings=tuple(warnings),
    )


def _undecidable(*, reason: str, refs: list[str], snap: Snapshot, psl: PSL,
                 author: str, author_org: str | None, policy_domain: str | None,
                 policy_source: str | None, record: Record | None, result_walk: Walk,
                 psl_version: str, psl_date: str, psl_org: str | None,
                 trace: list[dict[str, Any]], warnings: list[str],
                 alignments: tuple[Alignment, ...] = (),
                 spf_align: dict[str, bool] | None = None,
                 dkim_align: dict[str, bool] | None = None,
                 data_gaps: tuple[tuple[str, str], ...] = ()) -> DmarcResult:
    del snap, psl
    return DmarcResult(
        result="undecidable",
        reason=reason,
        author_domain=author,
        organizational_domain=author_org,
        policy_domain=policy_domain,
        policy_source=policy_source,
        policy_tag=None,
        policy_value=None,
        disposition=None,
        disposition_status="undecidable",
        test_mode=False,
        record=record,
        walk=result_walk,
        alignments=alignments,
        spf_align=spf_align or {"relaxed": False, "strict": False},
        dkim_align=dkim_align or {"relaxed": False, "strict": False},
        psl_version=psl_version,
        psl_date=psl_date,
        psl_organizational_domain=psl_org,
        evidence_ref=tuple(refs),
        trace=tuple(trace),
        warnings=tuple(warnings),
        data_gaps=data_gaps,
    )


# ── 小工具 ──────────────────────────────────────────────────────────────


def _normalize(name: str) -> str:
    return str(name).strip().rstrip(".").lower()


def _labels(name: str) -> tuple[str, ...]:
    normalized = _normalize(name)
    if not normalized:
        return ()
    return tuple(label for label in normalized.split(".") if label)


def _flag(value: bool) -> str:
    return "true" if value else "false"


def summary_text(result: DmarcResult) -> str:
    """一句话摘要（CLI stderr 用）。"""
    parts = ["DMARC 判定：%s" % result.result]
    if result.author_domain:
        parts.append("author=%s" % result.author_domain)
    if result.organizational_domain:
        parts.append("org=%s" % result.organizational_domain)
    if result.policy_source:
        parts.append("策略来源=%s" % result.policy_source)
    if result.disposition:
        parts.append("处置=%s" % result.disposition)
    elif result.result == "fail":
        parts.append("处置=%s" % result.disposition_status)
    return "（%s）" % "，".join(parts) if len(parts) > 1 else parts[0]


__all__ = [
    "Alignment",
    "DmarcResult",
    "Hop",
    "Record",
    "Walk",
    "align",
    "evaluate",
    "from_domains",
    "parse_record",
    "select_organizational_domain",
    "summary_text",
    "valid_version_record",
    "walk",
]
