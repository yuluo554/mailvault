"""RFC 7208 测试集的本地读取 + **离线 DNS 桩**（M1 交付，M2 使用）。

三件事，各自解决一个具体问题：

1. **读**：`fixtures/spf/rfc7208-tests.yml` 是 openspf.org 测试集的 pyspf 原样副本
   （203 个 `spec:` 用例 / 16 分组）。YAML 只在**测试期**解析，所以这里用 PyYAML
   （`dev` extra），运行时零依赖不受影响。
2. **桩**：`zonedata` → :class:`StubResolver`。它按 pyspf 自家 driver 的语义回答：
   - 名字不在 `zonedata` → ``NXDOMAIN``；以 ``error.`` 开头 → ``TIMEOUT``；
   - ``'TIMEOUT'`` 项 → 本次查询超时；
   - ``{'TXT': 'NONE'}`` → 该类型"查了但没有"；
   - 有 ``SPF`` 而无 ``TXT`` 时，driver 会**合成**一条同名 TXT（RFC 7208 已废弃 type SPF，
     但测试集里有分组就是拿这个性质做判据的，见上游 CHANGES 2014.04）；
   - ``CNAME`` 会跟一跳。
3. **转**：:func:`to_snapshot` 把一次用例的桩答复转成**标准 `snap.json` 快照对象**。
   这样测试集跑的是与生产同一条代码路径（`Snapshot.resolve`），而不是"测试专用捷径"；
   也顺带证明 `snap.json` schema 能承载全部 203 条用例，不需要为测试开字段。

**纪律**：不校验也不改写上游期望值（`plan/04` §2.1）。口径差异由 M2 逐条登记到
`data/rfc7208-failures.md`，不在这里悄悄放过。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from mailvault.constants import SNAPSHOT_SCHEMA_VERSION
from mailvault.snapshot import Snapshot, make_query

REPO_ROOT = Path(__file__).resolve().parent.parent
SUITE_PATH = REPO_ROOT / "fixtures" / "spf" / "rfc7208-tests.yml"

#: 上游 CO 语义里的两个哨兵值。
TIMEOUT = "TIMEOUT"
NONE = "NONE"

#: 一次用例 = 一条 `tests:` 条目 + 它所在分组的 `zonedata`。
DEFAULT_RCODE_NXDOMAIN = "NXDOMAIN"


@dataclass(frozen=True)
class Case:
    """单条 RFC 7208 用例。"""

    section: str
    name: str
    spec: str
    helo: str
    host: str
    mailfrom: str
    #: 上游期望。可能是单个字符串，也可能是**可接受的多个结果**（如 ``[fail, permerror]``）。
    result: tuple[str, ...]
    #: 上游 `strict` 原值（测试集里出现过 `strict: 2`）。**保留原值**而不是 bool()：
    #: 把它压成 True 会丢掉"这条用例按非 strict 语义跑"的信息。
    strict: Any
    zonedata: dict[str, list[Any]] = field(default_factory=dict, repr=False)
    description: str = ""

    @property
    def case_id(self) -> str:
        return "%s/%s" % (self.section, self.name)

    @property
    def is_strict(self) -> bool:
        """`strict` 的**布尔**语义：上游只在 `bytes-bug` 上写了非默认值。

        保留原值（``strict``）与给出布尔（``is_strict``）分开：
        前者是"上游怎么写的"，后者是"按严格语义跑吗"。
        """
        return self.strict is True or self.strict == 1

    @property
    def acceptable(self) -> tuple[str, ...]:
        return self.result

    def accepts(self, actual: str) -> bool:
        return actual in self.result


@dataclass(frozen=True)
class Suite:
    """整个测试集。"""

    cases: tuple[Case, ...]
    sha256: str

    @property
    def case_count(self) -> int:
        return len(self.cases)

    def by_section(self) -> dict[str, list[Case]]:
        grouped: dict[str, list[Case]] = {}
        for case in self.cases:
            grouped.setdefault(case.section, []).append(case)
        return grouped

    def find(self, case_id: str) -> Case:
        for case in self.cases:
            if case.case_id == case_id:
                return case
        raise KeyError(case_id)


def load_suite(path: Path | None = None) -> Suite:
    """读入测试集。**只读上游字节**，不改写、不排序（顺序本身就是分组信息）。"""
    suite_path = Path(path) if path is not None else SUITE_PATH
    raw = suite_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()

    import yaml  # 测试期依赖（pyproject `dev` extra）

    cases: list[Case] = []
    for document in yaml.safe_load_all(raw.decode("utf-8")):
        if not document:
            continue
        section = str(document.get("description", "")).strip()
        zonedata = document.get("zonedata") or {}
        for name, body in (document.get("tests") or {}).items():
            result = body["result"]
            if isinstance(result, str):
                acceptable = (result,)
            else:
                acceptable = tuple(str(item) for item in result)
            cases.append(Case(
                section=section,
                name=str(name),
                spec=str(body["spec"]),
                helo=str(body["helo"]),
                host=str(body["host"]),
                mailfrom=str(body["mailfrom"]),
                result=acceptable,
                strict=body.get("strict", True),
                zonedata=zonedata,
                description=str(body.get("description", "")).strip(),
            ))
    return Suite(cases=tuple(cases), sha256=digest)


# ── 离线 DNS 桩 ─────────────────────────────────────────────────────────


class StubResponse:
    """桩答复：三种终态 + answer。"""

    __slots__ = ("rcode", "answer", "ttl")

    def __init__(self, rcode: str, answer: Iterable[str] = (), ttl: int = 300) -> None:
        self.rcode = rcode
        self.answer = tuple(answer)
        self.ttl = ttl

    @property
    def is_noerror(self) -> bool:
        return self.rcode == "NOERROR"

    def __repr__(self) -> str:  # 便于失败时定位
        return "StubResponse(%s, %r)" % (self.rcode, list(self.answer))


class StubResolver:
    """按一条用例的 `zonedata` 回答查询。**永不联网**。

    语义与 pyspf `testspf.py::getrdata` / `DNSLookup` 对齐（见模块 docstring）。
    """

    def __init__(self, zonedata: dict[str, list[Any]], *, default_ttl: int = 300) -> None:
        self._zone = {name.lower().rstrip("."): records
                      for name, records in zonedata.items()}
        self._ttl = default_ttl
        #: 记录每次查询，供断言"没有查询被凭空跳过"。
        self.calls: list[tuple[str, str]] = []

    # ── 查询 ───────────────────────────────────────────────────────────
    def query(self, qname: str, qtype: str, *, level: int = 0) -> StubResponse:
        name = qname.lower().rstrip(".")
        qtype = qtype.upper()
        if level == 0:
            self.calls.append((name, qtype))

        records = self._zone.get(name)
        if records is None:
            if name.startswith("error."):
                return StubResponse(TIMEOUT)
            return StubResponse(DEFAULT_RCODE_NXDOMAIN)

        answers, timed_out, _saw_none = self._collect(records, qtype, level=level)
        if timed_out:
            return StubResponse(TIMEOUT)
        if answers:
            return StubResponse("NOERROR", answers, self._ttl)
        # 查了但没有（`NONE` 哨兵，或该类型确实没有记录）→ NOERROR + 空答案。
        # 关键：**不是** NXDOMAIN——"问过了、没有这条记录"与"这个名字不存在"是两回事。
        return StubResponse("NOERROR", (), self._ttl)

    def _collect(self, records: list[Any], qtype: str, *,
                 level: int = 0) -> tuple[list[str], bool, bool]:
        """按上游 `testspf.DNSLookup` 的**顺序语义**收集答案。

        `timeout` 这个局部标志是关键（上游同样叫这个名字）：它初值为 True，
        一旦本次查询**拿到了同类型的值**就转 False。之后才遇到的 ``'TIMEOUT'`` 项
        不再生效——这正是上游 `spftimeout` 用例（TXT 有记录、SPF 查询超时）能
        "TXT 照常返回、SPF 超时"的原因。把整域一律判超时会让那条用例假失败。
        """
        answers: list[str] = []
        timeout = True
        saw_none = False
        # 上游 `getrdata`：没有 TXT 记录时，由 SPF 记录**合成**一条同名 TXT。
        # 这条只看"有没有 TXT 记录"，与请求的 qtype 无关——先算出来，
        # 否则 qtype=TXT 时会把 CNAME/MX 等分支一并跳过。
        spawn_txt = not any(isinstance(record, dict) and "TXT" in record for record in records)

        for record in records:
            if record == TIMEOUT:
                if timeout:
                    return [], True, saw_none
                continue
            if not isinstance(record, dict):
                continue
            for rtype, value in record.items():
                if value == NONE:
                    if rtype == qtype:
                        saw_none = True
                    continue
                if value == TIMEOUT:
                    if rtype == qtype and timeout:
                        return [], True, saw_none
                    continue
                if rtype == "SPF" and spawn_txt and qtype == "TXT":
                    answers.extend(_as_text_list(value))
                    timeout = False
                    continue
                if rtype == "CNAME":
                    # CNAME 是**别名**，对任何 qtype 都成立（RFC 1034 §3.6.2）：
                    # 因此必须在 "rtype != qtype" 过滤**之前**处理，否则
                    # `CNAME` 记录在 qtype=TXT 时会被整条跳过。
                    #
                    # 只跟**一跳**（与上游 `if not level` 一致）。上游测试集里有
                    # `loop4.example.com → CNAME.example.com` 这类自指/成环数据，
                    # 不限深度会直接 RecursionError。第二跳按"查不到"处理。
                    if level == 0:
                        nested = self.query(_as_text(value), qtype, level=1)
                        if nested.is_noerror:
                            answers.extend(nested.answer)
                            if nested.answer:
                                timeout = False
                        elif nested.rcode == TIMEOUT:
                            if timeout:
                                return [], True, saw_none
                    continue
                if rtype != qtype:
                    continue
                timeout = False
                if rtype == "MX":
                    answers.append(_format_mx(value))
                    continue
                answers.extend(_as_text_list(value))
        return answers, False, saw_none

    # ── 便捷断言面 ─────────────────────────────────────────────────────
    def txt(self, qname: str) -> StubResponse:
        return self.query(qname, "TXT")


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(str(item) for item in value)
    return str(value)


def _as_text_list(value: Any) -> list[str]:
    """TXT 的 rdata 可以是字符串，也可以是**多段列表**（拼接后成一个逻辑值）。"""
    return [_as_text(value)]


def _format_mx(value: Any) -> str:
    if isinstance(value, list) and len(value) == 2:
        preference, exchange = value
        return "%d %s" % (int(preference), str(exchange))
    return str(value)


# ── 转成标准快照 ────────────────────────────────────────────────────────


def to_snapshot(case: Case, *, fetched_at: str = "2026-10-19T18:35:00Z",
                psl_version: str = "2026-10-20_08-40-56_UTC",
                psl_date: str = "2026-10-20",
                extra: Iterable[tuple[str, str]] = ()) -> Snapshot:
    """把一条用例的桩答复转成 `Snapshot`——跑的是与生产**同一条** `resolve()` 路径。

    **查询清单必须覆盖求值器会问的全部键**，否则"快照里没查过"会被求值器如实判成
    数据缺口（`plan/04` §2.3），用例会因为夹具不全而假失败。清单来自三处：

    1. 用例 `zonedata` 里出现过的**每一个名字** × 求值器会用的五种 qtype
       （TXT / A / AAAA / MX / PTR）；
    2. 连接 IP 的反向名（`in-addr.arpa` / `ip6.arpa`）——`ptr` 机制与 `%{p}` 要用；
    3. 记录文本里不含宏的 `include:` / `redirect=` / `a:` / `mx:` / `ptr:` /
       `exists:` / `exp=` 目标，以及 PTR / MX / CNAME 记录**指向**的名字。

    ``extra`` 是第 4 个来源，也是唯一能让清单收敛的办法：宏展开后的名字事先算不出来，
    所以由 :func:`run_case` 把"求值器实际问过、但快照里没有"的键补进来再重跑。
    这样清单的每一项都是**桩真实答复过的**，不是猜的。
    """
    resolver = StubResolver(case.zonedata)
    queries: list[dict[str, Any]] = []
    asked: set[tuple[str, str]] = set()

    def record(qname: str, qtype: str) -> None:
        key = (qname.lower().rstrip("."), qtype.upper())
        if key in asked:
            return
        asked.add(key)
        response = resolver.query(qname, qtype)
        queries.append(make_query(
            qname=qname, qtype=qtype,
            rcode=response.rcode,
            answer=response.answer if response.is_noerror else (),
            ttl=response.ttl,
        ))

    names: set[str] = set()

    domain = case.mailfrom.rpartition("@")[2].strip().rstrip(".").lower()
    if domain:
        names.add(domain)

    reverse = reverse_lookup_name(case.host)
    if reverse:
        names.add(reverse)

    # 1) zone 里出现过的全部名字
    names.update(name.lower().rstrip(".") for name in case.zonedata)

    # 3) 记录文本里不含宏的目标，以及记录**指向**的名字（PTR 目标 / MX 交换 / CNAME 目标）
    for _name, records in case.zonedata.items():
        for record_entry in records:
            if not isinstance(record_entry, dict):
                continue
            for rtype, value in record_entry.items():
                if rtype in ("SPF", "TXT"):
                    for text in _as_text_list(value):
                        for token in text.split()[1:]:
                            target = _referenced_target(token)
                            if target and "%" not in target and "/" not in target:
                                names.add(target)
                elif rtype in ("PTR", "CNAME"):
                    # 求值器会对这些目标做正向 A/AAAA 验证（§5.5）。
                    names.add(_as_text(value).rstrip(".").lower())
                elif rtype == "MX":
                    names.add(_format_mx(value).partition(" ")[2].rstrip(".").lower())

    for name in sorted(names):
        if not name:
            continue
        for qtype in ("TXT", "A", "AAAA", "MX", "PTR"):
            record(name, qtype)

    # 4) 求值器上一轮实际问过、但清单里还没有的键（宏展开的产物）
    for qname, qtype in extra:
        record(qname, qtype)

    return Snapshot({
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "fetched_at": fetched_at,
        "resolver": "synthetic",
        "psl_version": psl_version,
        "psl_date": psl_date,
        "queries": queries,
    })


def run_case(case: Case, evaluator: Any, *, max_rounds: int = 64) -> Any:
    """跑一条用例，直到**求值器不再报数据缺口**。

    为什么必须迭代：宏展开后的查询名（``%{i}.%{l2r-}.user.%{d2}`` 之类）事先算不出来，
    静态清单必然漏。漏掉时求值器会如实把缺口写进 ``data_gap``（这正是 `plan/04` §2.3
    要的行为——"没查过"不许当成"没有"）。这里把缺口键补进快照再重跑，直到收敛。

    ``max_rounds`` 是防死循环的硬闸：收敛不了说明求值器每轮都在问新名字，
    那是真问题，必须炸出来而不是静默返回一个"差不多"的结果。
    """
    extra: list[tuple[str, str]] = []
    for _round in range(max_rounds):
        snapshot = to_snapshot(case, extra=extra)
        result = evaluator(snapshot)
        gap = getattr(result, "data_gap", None)
        if not gap:
            return result
        if gap in extra:
            raise AssertionError(
                "数据缺口补过之后仍然缺：%r（求值器在问同一件事两次）" % (gap,))
        extra.append(gap)
    raise AssertionError(
        "用例 %s 在 %d 轮内没有收敛到完整快照——求值器可能每次都在问新名字"
        % (case.case_id, max_rounds))


def _referenced_target(token: str) -> str | None:
    """从一条 term 里取它引用的域名（``include:x`` / ``redirect=y`` / ``-a:z`` …）。"""
    lowered = token.lower()
    for prefix in ("include:", "exists:", "ptr:", "a:", "mx:"):
        if lowered.startswith(prefix):
            return token.split(":", 1)[1].rstrip(".").lower()
    for prefix in ("redirect=", "exp="):
        if lowered.startswith(prefix):
            return token.split("=", 1)[1].rstrip(".").lower()
    return None


def reverse_lookup_name(host: str) -> str | None:
    """连接 IP 的反向查询名（``4.3.2.1.in-addr.arpa`` / ``....ip6.arpa``）。

    IPv4-mapped IPv6 先折回 IPv4（RFC 7208 §5/9/2：这类连接按 IPv4 处理）。
    """
    import ipaddress

    try:
        address = ipaddress.ip_address(str(host).strip())
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.version == 4:
        return "%s.in-addr.arpa" % ".".join(reversed(str(address).split(".")))
    return "%s.ip6.arpa" % ".".join(reversed(address.exploded.replace(":", "")))


def case_summary(suite: Suite) -> dict[str, Any]:
    """测试集概况（写进失败登记表 / 控制台输出用）。"""
    sections = suite.by_section()
    return {
        "sha256": suite.sha256,
        "case_count": suite.case_count,
        "section_count": len(sections),
        "sections": {name: len(items) for name, items in sections.items()},
        "strict_cases": [case.case_id for case in suite.cases if not case.strict],
    }
