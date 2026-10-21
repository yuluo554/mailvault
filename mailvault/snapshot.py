"""`snap.json` 的解析、schema 校验与查询接口（M1）。

三条语义（`plan/03` §3.1）：

1. ``queries`` 是**有序列表**，不是字典——同一 ``(qname, qtype)`` 可以有多次查询
   （CNAME 链、重试）。用字典建模会在加载期就把"查了两次结果不同"静默合并成一条。
2. :meth:`Snapshot.resolve` 返回**按列表顺序第一次命中**的那一条，并把下标带出来，
   调用方可以把它写进 ``trace``。这样"快照里同名单查了两次、答案不同"是可见的。
3. ``rcode`` 非 ``NOERROR`` 时 ``answer`` 必须为空；缺 ``psl_version`` / ``psl_date``、
   未知 ``schema_version`` → :class:`~mailvault.exits.InputError`（exit 3）。

**"没查过" 与 "查了但没有" 必须可区分**：字段 ``found`` 为 False 表示快照里根本没有这条查询
（数据缺口），``found`` 为 True 且 ``rcode == "NXDOMAIN"`` 才是"查过、不存在"。
把两者混为一谈，下游就会把"没抓"读成"没有记录"——`plan/04` §2.3 明令禁止。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .constants import SNAPSHOT_SCHEMA_VERSION
from .exits import InputError

#: 唯一表示"成功答复"的 rcode。其余一律视为非 NOERROR。
RCODE_NOERROR = "NOERROR"

#: 快照逐查询的必需字段（`plan/01` §4）。
QUERY_FIELDS = ("qname", "qtype", "rcode", "answer", "ttl")

#: 快照顶层必需字段。``schema_version`` 单独校验。
REQUIRED_FIELDS = ("fetched_at", "resolver", "psl_version", "psl_date", "queries")


@dataclass(frozen=True)
class Resolved:
    """一次查询的解析结果。

    ``found=False`` 表示快照里没有这条 ``(qname, qtype)``——**是数据缺口，不是"不存在"**。
    """

    qname: str
    qtype: str
    found: bool
    index: int | None = None
    rcode: str | None = None
    answer: tuple[str, ...] = ()
    ttl: int | None = None

    @property
    def is_noerror(self) -> bool:
        return self.found and self.rcode == RCODE_NOERROR

    @property
    def is_nxdomain(self) -> bool:
        return self.found and self.rcode == "NXDOMAIN"

    def trace_note(self) -> str:
        """写进 ``trace`` 的一行（含命中下标，K12）。"""
        if not self.found:
            return "%s/%s 未在快照中查询（数据缺口，不等同于不存在）" % (self.qname, self.qtype)
        return "%s/%s → rcode=%s answer=%d 条（queries[%d]）" % (
            self.qname, self.qtype, self.rcode, len(self.answer), self.index)

    def to_dict(self) -> dict[str, Any]:
        return {
            "qname": self.qname,
            "qtype": self.qtype,
            "found": self.found,
            "index": self.index,
            "rcode": self.rcode,
            "answer": list(self.answer),
            "ttl": self.ttl,
        }


class Snapshot:
    """不可变的 DNS 快照视图。

    构造走 :func:`load_snapshot`（文件）或 :func:`from_dict`（内存，测试与 runner 用）。
    """

    __slots__ = ("_data", "_index")

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data
        #: (qname, qtype) → 该键**全部**命中下标（保序）。保留多条是为了让 resolve 能
        #: 只取第一条、而调试/统计仍能看到"查了两次"。
        self._index: dict[tuple[str, str], list[int]] = {}
        for position, entry in enumerate(data["queries"]):
            self._index.setdefault(
                (_norm_name(entry["qname"]), entry["qtype"].upper()), []).append(position)

    # ── 元数据 ─────────────────────────────────────────────────────────
    @property
    def schema_version(self) -> int:
        return self._data["schema_version"]

    @property
    def fetched_at(self) -> str:
        return self._data["fetched_at"]

    @property
    def resolver(self) -> str:
        return self._data["resolver"]

    @property
    def psl_version(self) -> str:
        return self._data["psl_version"]

    @property
    def psl_date(self) -> str:
        return self._data["psl_date"]

    @property
    def queries(self) -> list[dict[str, Any]]:
        return list(self._data["queries"])

    @property
    def query_count(self) -> int:
        return len(self._data["queries"])

    def meta(self) -> dict[str, Any]:
        """账本里的 ``snapshot`` 块（`docs/ledger-format.md` §1）。"""
        return {
            "fetched_at": self.fetched_at,
            "resolver": self.resolver,
            "psl_version": self.psl_version,
            "psl_date": self.psl_date,
            "query_count": self.query_count,
        }

    # ── 查询 ───────────────────────────────────────────────────────────
    def resolve(self, qname: str, qtype: str,
                trace: list[dict[str, Any]] | None = None) -> Resolved:
        """按列表顺序取**第一次命中**；把下标写进 ``trace``（若给了 trace）。"""
        key = (_norm_name(qname), qtype.upper())
        positions = self._index.get(key)
        if not positions:
            resolved = Resolved(qname=_norm_name(qname), qtype=qtype.upper(), found=False)
        else:
            position = positions[0]
            entry = self._data["queries"][position]
            resolved = Resolved(
                qname=entry["qname"],
                qtype=entry["qtype"],
                found=True,
                index=position,
                rcode=entry["rcode"],
                answer=tuple(entry["answer"]),
                ttl=entry["ttl"],
            )
        if trace is not None:
            trace.append({"node": "snap.resolve", "note": resolved.trace_note()})
        return resolved

    def occurrences(self, qname: str, qtype: str) -> list[Resolved]:
        """同键的全部命中（保序）。用于"同一名字查了两次"的可见性。"""
        out: list[Resolved] = []
        for position in self._index.get((_norm_name(qname), qtype.upper()), []):
            entry = self._data["queries"][position]
            out.append(Resolved(
                qname=entry["qname"], qtype=entry["qtype"], found=True, index=position,
                rcode=entry["rcode"], answer=tuple(entry["answer"]), ttl=entry["ttl"]))
        return out

    def to_dict(self) -> dict[str, Any]:
        """还原成可序列化的字典（**必须**经 `canonical.dump_file` 落盘）。"""
        return {
            "schema_version": self.schema_version,
            "fetched_at": self.fetched_at,
            "resolver": self.resolver,
            "psl_version": self.psl_version,
            "psl_date": self.psl_date,
            "queries": self.queries,
        }


# ── 构造：文件 / 内存 ───────────────────────────────────────────────────


def load_snapshot(path: str | Path) -> Snapshot:
    """从 ``snap.json`` 读取并校验。"""
    data = _load_json_object(path, what="快照")
    return from_dict(data, source=str(path))


def from_dict(data: Any, *, source: str = "<memory>") -> Snapshot:
    """从已解析的字典校验并构造快照。"""
    _validate(data, source=source)
    return Snapshot(data)


# ── 校验 ────────────────────────────────────────────────────────────────


def _validate(data: Any, *, source: str) -> None:
    if not isinstance(data, dict):
        raise InputError("%s：快照顶层必须是对象，收到 %s" % (source, type(data).__name__))

    version = data.get("schema_version")
    if version is None:
        raise InputError("%s：缺 schema_version（本工具支持 %d）"
                         % (source, SNAPSHOT_SCHEMA_VERSION))
    if not isinstance(version, int) or isinstance(version, bool):
        raise InputError("%s：schema_version 必须是整数，收到 %r" % (source, version))
    if version != SNAPSHOT_SCHEMA_VERSION:
        raise InputError("%s：不支持的 schema_version=%d（本工具支持：%d）"
                         % (source, version, SNAPSHOT_SCHEMA_VERSION))

    missing = [field for field in REQUIRED_FIELDS if field not in data]
    if missing:
        raise InputError("%s：缺必需字段 %s" % (source, "、".join(missing)))

    for field in ("fetched_at", "resolver", "psl_version", "psl_date"):
        value = data[field]
        if not isinstance(value, str) or not value.strip():
            raise InputError(
                "%s：%s 必须是非空字符串（%s）"
                % (source, field, _field_hint(field)))

    queries = data["queries"]
    if not isinstance(queries, list):
        raise InputError("%s：queries 必须是有序列表，收到 %s"
                         % (source, type(queries).__name__))

    for position, entry in enumerate(queries):
        _validate_query(entry, "%s：queries[%d]" % (source, position))

    # 规范化：qtype 统一大写，answer 统一为 list[str]，其余字段原样。
    for entry in queries:
        entry["qtype"] = entry["qtype"].upper()
        entry["answer"] = [str(item) for item in entry["answer"]]


def _field_hint(field: str) -> str:
    if field in ("psl_version", "psl_date"):
        return "题面 §2.5 灰区 3：输出必须带 PSL 版本与日期，不允许缺省"
    return "快照元数据不允许缺省"


def _validate_query(entry: Any, where: str) -> None:
    if not isinstance(entry, dict):
        raise InputError("%s：每条查询必须是对象，收到 %s" % (where, type(entry).__name__))
    missing = [field for field in QUERY_FIELDS if field not in entry]
    if missing:
        raise InputError("%s：缺字段 %s" % (where, "、".join(missing)))

    for field in ("qname", "qtype", "rcode"):
        value = entry[field]
        if not isinstance(value, str) or not value.strip():
            raise InputError("%s：%s 必须是非空字符串，收到 %r" % (where, field, value))

    answer = entry["answer"]
    if not isinstance(answer, list):
        raise InputError("%s：answer 必须是列表，收到 %s"
                         % (where, type(answer).__name__))
    for index, item in enumerate(answer):
        if not isinstance(item, str):
            raise InputError("%s：answer[%d] 必须是字符串，收到 %r" % (where, index, item))

    ttl = entry["ttl"]
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0:
        raise InputError("%s：ttl 必须是非负整数，收到 %r" % (where, ttl))

    if entry["rcode"].upper() != RCODE_NOERROR and answer:
        # 非 NOERROR 还带 answer，会把"不存在"读成"有记录"。
        raise InputError(
            "%s：rcode=%s 时 answer 必须为空列表，收到 %d 条"
            % (where, entry["rcode"], len(answer)))


# ── 小工具 ──────────────────────────────────────────────────────────────


def make_query(*, qname: str, qtype: str, rcode: str = RCODE_NOERROR,
               answer: Iterable[str] = (), ttl: int = 0) -> dict[str, Any]:
    """构造一条合法的 query 记录（fixture 与 fetch 共用，保证形态一致）。"""
    return {
        "qname": qname,
        "qtype": qtype.upper(),
        "rcode": rcode,
        "answer": list(answer),
        "ttl": ttl,
    }


def _norm_name(name: str) -> str:
    """DNS 名字比较口径：小写、去尾点。"""
    return name.strip().rstrip(".").lower()


def _load_json_object(path: str | Path, *, what: str) -> Any:
    """读 JSON 对象。文件缺失/语法错 → InputError（exit 3），消息带相对路径。"""
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        raise InputError("%s文件不存在：%s" % (what, path)) from None
    except OSError as exc:
        raise InputError("%s文件不可读：%s（%s）" % (what, path, exc)) from None
    try:
        return json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InputError("%s不是 UTF-8：%s（%s）" % (what, path, exc)) from None
    except json.JSONDecodeError as exc:
        raise InputError("%s JSON 语法错误：%s 第 %d 行第 %d 列：%s"
                         % (what, path, exc.lineno, exc.colno, exc.msg)) from None
