"""反事实差分（M5）：改一条配置，**只重跑** M2–M4，与基线账本做结构差分。

做法（题面 §3 的 M5 明文要求）：**不重写求值器**。把输入三件套里的快照/查询复制一份，
按 ``--change KEY=VALUE`` 改副本，再让同一套 M2–M4 求值器跑一遍，最后对两份账本做
**结构差分**。

三条纪律：

1. **未知 ``--change`` 键或不可解析的值 → :class:`InputError`（exit 3）**，不静默忽略
   （`plan/03` §2 第 3 条）。静默忽略会让用户以为"我改了"，实际跑的还是基线。
2. **差分可复算**：:func:`diff_ledgers` 的 ops 施加到基线得到候选；把 ops 反转
   施加到候选得到基线。两个方向都能反推，因此差分不是"看起来像差异的一段文字"。
3. **RUA 关联标注报告期口径**：RUA 是**聚合报告**，它只覆盖报告期内、且结论依赖报告方
   的口径；这与"本次审计这一时刻"不是一回事（K7 的推论）。缺 RUA 数据 → ``undecidable``
   + 所需输入清单，**不猜**。
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..constants import (
    DMARC_DISPOSITIONS,
    DIFF_SCHEMA_VERSION,
    WHATIF_CHANGE_KEYS,
    WHATIF_SPF_ALL_VALUES,
)
from ..exits import InputError

#: ``include:`` 的值与 ``_dmarc`` 目标域都要形如域名（标签 + 保留域由卫生门管）。
_DOMAIN = re.compile(r"\A[A-Za-z0-9_](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")

#: ``all`` 机制的取值形态（含限定符）。
_ALL_VARIANTS = ("all", "+all", "-all", "~all", "?all")

#: RUA 报告的必需输入清单：缺数据时原样报给用户"这一项需要什么"。
RUA_REQUIRED_INPUTS = (
    "RUA 聚合报告（parsedmarc 导出的 JSON），含 report_metadata.date_range 与 records[]",
    "每条记录的 source_ip 与 count（用于聚类『会打断谁』）",
    "每条记录的 identifiers.header_from（被评估的 Author 域）",
    "每条记录的 policy_evaluated.dkim / .spf / .disposition（决定该条在 p=reject 下的后果）",
    "报告期（date_range.begin / end）——用于标注『只覆盖报告期内』",
)


@dataclass(frozen=True)
class Change:
    """一条已校验的候选变更。"""

    key: str
    value: str
    raw: str

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "value": self.value, "raw": self.raw}


# ── 参数校验 ────────────────────────────────────────────────────────────


def parse_changes(items: list[str]) -> tuple[Change, ...]:
    """把 ``--change KEY=VALUE`` 列表校验成 :class:`Change` 元组。

    两种形态：

    - ``KEY=VALUE``（``p=reject`` / ``t=y`` / ``all=-all``）；
    - ``include:<domain>``——`plan/03` §2 冻结的形态就是**冒号**（`--change
      include:_spf.example.invalid`），所以这里不能只按 ``=`` 切；``include=<domain>``
      也一并接受（同一件事的两种写法，不引入第二种语义）。

    校验三件事，任何一条不满足都 **raise**（exit 3）而不是跳过：

    1. 形态必须是上面两种之一（键与值都不许为空）；
    2. ``KEY`` 必须在 :data:`constants.WHATIF_CHANGE_KEYS` 里；
    3. ``VALUE`` 必须能解析（策略值是三选一、``t`` 是 y/n、``all`` 是四个限定符之一、
       ``include:`` 的值要像域名）。
    """
    if not items:
        raise InputError("whatif 至少需要一个 --change KEY=VALUE")
    changes: list[Change] = []
    seen: set[str] = set()
    for item in items:
        if item.startswith("include:"):
            key, value = "include", item[len("include:"):].strip()
        elif "=" in item:
            raw_key, _, raw_value = item.partition("=")
            key, value = raw_key.strip().lower(), raw_value.strip()
        else:
            raise InputError(
                "--change 需要 KEY=VALUE（或 include:<domain>）形态，收到 %r" % (item,))
        if not key:
            raise InputError("--change 的键为空：%r" % (item,))
        if key not in WHATIF_CHANGE_KEYS:
            raise InputError(
                "--change 的键 %r 未知（允许：%s）；未知键不做静默忽略"
                % (key, "、".join(WHATIF_CHANGE_KEYS)))
        if not value:
            raise InputError("--change %s 的值为空（不做静默忽略）" % key)
        _validate_value(key, value)
        if key in seen:
            raise InputError("--change %s= 出现了两次（同一键只允许一条变更）" % key)
        seen.add(key)
        changes.append(Change(key=key, value=value, raw=item))
    return tuple(changes)


def _validate_value(key: str, value: str) -> None:
    if key in ("p", "sp", "np"):
        if value not in DMARC_DISPOSITIONS:
            raise InputError(
                "--change %s=%s 的值非法（允许：%s）"
                % (key, value, "、".join(DMARC_DISPOSITIONS)))
        return
    if key == "t":
        if value.lower() not in ("y", "n", "true", "false", "1", "0"):
            raise InputError("--change t=%s 的值非法（允许：y / n）" % value)
        return
    if key == "all":
        if value not in WHATIF_SPF_ALL_VALUES:
            raise InputError(
                "--change all=%s 的值非法（允许：%s；可以写 `~all`，不要写裸 `all`）"
                % (value, "、".join(WHATIF_SPF_ALL_VALUES)))
        return
    if key == "include":
        if not _DOMAIN.match(value):
            raise InputError("--change include:%s 的值不是一个域名" % value)
        return


# ── 施加变更（改快照副本） ───────────────────────────────────────────────


def apply_changes(snap_dict: dict[str, Any], *, changes: tuple[Change, ...],
                  author_domain: str | None = None,
                  spf_domain: str | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """把变更施加到快照副本，返回 ``(新快照, 施加明细)``。

    **只改快照副本**，不动 ``message.eml`` / ``query.json``：这是"改配置"而不是
    "改报文"——报文与查询是**既成事实**，反事实要问的是"配置改了会怎样"。

    目标记录定位：

    - ``p`` / ``sp`` / ``np`` / ``t`` → ``_dmarc.<author_domain>`` 那条 TXT；
      Author 域缺证据时退化为"快照里唯一一条带 DMARC 记录的 `_dmarc` 查询"，
      多于一条且对不上 Author 域 → :class:`InputError`（不挑一条来猜）。
    - ``all`` / ``include`` → ``spf_domain`` 的 SPF TXT 记录。
    """
    out = copy.deepcopy(snap_dict)
    queries = out["queries"]
    applied: list[dict[str, Any]] = []

    for change in changes:
        if change.key in ("p", "sp", "np", "t"):
            query, index = _resolve_dmarc_target(
                queries, author_domain=author_domain, key=change.key)
            value = change.value
            if change.key == "t":
                value = "y" if value.lower() in ("y", "true", "1") else "n"
            before = query["answer"][0]
            after = _set_tag(before, change.key, value)
            query["answer"][0] = after
            applied.append({
                "key": change.key, "value": value, "record": query["qname"],
                "path": "queries[%d].answer[0]" % index, "from": before, "to": after,
            })
        else:
            query, answer_index, index = _resolve_spf_target(queries, spf_domain=spf_domain)
            before = query["answer"][answer_index]
            if change.key == "all":
                after = _rewrite_all(before, change.value)
            else:
                after = _insert_include(before, change.value)
            query["answer"][answer_index] = after
            applied.append({
                "key": change.key, "value": change.value, "record": query["qname"],
                "path": "queries[%d].answer[%d]" % (index, answer_index),
                "from": before, "to": after,
            })

    return out, applied


def _resolve_dmarc_target(queries: list[dict[str, Any]], *, author_domain: str | None,
                          key: str) -> tuple[dict[str, Any], int]:
    candidates = [
        (index, query) for index, query in enumerate(queries)
        if query["qtype"].upper() == "TXT"
        and query["qname"].lower().startswith("_dmarc.")
        and any(item.strip().lower().startswith("v=dmarc1") for item in query["answer"])
    ]
    if not candidates:
        raise InputError(
            "快照里没有带 DMARC 记录的 `_dmarc` TXT 查询，无法施加 %s= 变更"
            "（whatif 只改配置，不凭空造记录）" % key)
    if author_domain:
        exact = "_dmarc." + author_domain.lower().rstrip(".")
        for index, query in candidates:
            if query["qname"].lower().rstrip(".") == exact:
                return query, index
    if len(candidates) == 1:
        return candidates[0][1], candidates[0][0]
    raise InputError(
        "快照里有 %d 条带 DMARC 记录的 `_dmarc` 查询，且都对应不上 Author 域 %r"
        "（无法判断该改哪一条，不挑一条来猜）"
        % (len(candidates), author_domain or "（未给出）"))


def _resolve_spf_target(queries: list[dict[str, Any]],
                        *, spf_domain: str | None) -> tuple[dict[str, Any], int, int]:
    if not spf_domain:
        raise InputError("无法确定 SPF 记录的域（mail_from 与 helo 都为空），不能施加 SPF 变更")
    wanted = spf_domain.lower().rstrip(".")
    for index, query in enumerate(queries):
        if query["qtype"].upper() != "TXT":
            continue
        if query["qname"].lower().rstrip(".") != wanted:
            continue
        for answer_index, answer in enumerate(query["answer"]):
            if answer.strip().lower().startswith("v=spf1"):
                return query, answer_index, index
    raise InputError(
        "快照里没有 %s 的 SPF 记录（v=spf1 ...），无法施加该变更（不凭空造记录）"
        % spf_domain)


def _set_tag(record: str, key: str, value: str) -> str:
    """在 ``key=value`` 形态的记录里设置/追加一个标签，**保持其余标签原样原序**。"""
    pairs: list[list[str]] = []
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, tag_value = part.partition("=")
        pairs.append([name.strip(), tag_value.strip()])
    target = key.lower()
    for pair in pairs:
        if pair[0].lower() == target:
            pair[1] = value
            break
    else:
        pairs.append([key, value])
    return "; ".join("%s=%s" % (name, item) if item else name for name, item in pairs)


def _rewrite_all(record: str, value: str) -> str:
    tokens = record.split()
    for position, token in enumerate(tokens):
        if token.lower() in _ALL_VARIANTS:
            tokens[position] = value
            return " ".join(tokens)
    return record + " " + value


def _insert_include(record: str, domain: str) -> str:
    mechanism = "include:" + domain
    tokens = record.split()
    for position, token in enumerate(tokens):
        if token.lower() in _ALL_VARIANTS:
            tokens.insert(position, mechanism)
            return " ".join(tokens)
    tokens.append(mechanism)
    return " ".join(tokens)


# ── RUA 关联 ────────────────────────────────────────────────────────────


def rua_association(path: str | None, *, policy_value: str = "reject") -> dict[str, Any]:
    """吃一份最小 RUA 报告，聚类"上 ``policy_value`` 会打断谁"。

    - ``path`` 为 ``None`` → ``undecidable`` + :data:`RUA_REQUIRED_INPUTS`（**不猜**）。
    - ``path`` 给了但读不了/JSON 坏 → :class:`InputError`（exit 3）：那是指定错了，
      不是"没有数据"。
    - 报告存在但没有 ``records`` → ``undecidable`` + 所需输入清单。
    """
    if path is None:
        return _rua_undecidable(
            "未提供 RUA 报告（--rua）：本项判 undecidable，不凭审计输入推测历史投递",
            policy_value=policy_value)

    data = _load_json(path, what="RUA 报告")
    if not isinstance(data, dict):
        raise InputError("RUA 报告顶层必须是对象，收到 %s" % type(data).__name__)

    metadata = data.get("report_metadata") or {}
    period = metadata.get("date_range") or {}
    org_name = metadata.get("org_name")
    records = data.get("records")
    if not isinstance(records, list) or not records:
        return _rua_undecidable(
            "RUA 报告里没有 records[]：没有可聚类的投递记录，本项判 undecidable",
            policy_value=policy_value, org_name=org_name, period=period)

    affected: list[dict[str, Any]] = []
    clusters: dict[str, list[str]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise InputError("RUA 报告的 records[] 里每一条都必须是对象")
        policy = record.get("policy_evaluated") or {}
        identifiers = record.get("identifiers") or {}
        header_from = str(identifiers.get("header_from") or "（报告未给 header_from）")
        source_ip = str(record.get("source_ip") or "（报告未给 source_ip）")
        spf_result = str(policy.get("spf") or "（未评估）")
        dkim_result = str(policy.get("dkim") or "（未评估）")
        aligned = spf_result == "pass" or dkim_result == "pass"
        clusters.setdefault(header_from, [])
        if source_ip not in clusters[header_from]:
            clusters[header_from].append(source_ip)
        if aligned:
            continue
        affected.append({
            "source_ip": source_ip,
            "header_from": header_from,
            "count": record.get("count"),
            "spf": spf_result,
            "dkim": dkim_result,
            "reported_disposition": policy.get("disposition"),
            "would_be": policy_value,
            "reason": "报告期内该来源既没通过 SPF 也没通过 DKIM 对齐；"
                      "策略取 %s 时这类投递会被打断" % policy_value,
        })

    affected.sort(key=lambda item: (item["header_from"], item["source_ip"]))
    return {
        "status": "complete",
        "policy_under_test": policy_value,
        "org_name": org_name,
        "report_period": {"begin": period.get("begin"), "end": period.get("end")},
        "period_note": _PERIOD_NOTE,
        "records": len(records),
        "affected": affected,
        "affected_total": len(affected),
        "clusters": [{"header_from": domain, "source_ips": sorted(clusters[domain])}
                     for domain in sorted(clusters)],
        "notes": [
            "affected 只列『报告期内 SPF 与 DKIM 都没通过对齐』的来源；"
            "那是策略取 %s 时会打断的部分" % policy_value,
            "count 是报告方给的投递条数，**不**等同本工具能复核的报文数",
        ],
    }


_PERIOD_NOTE = ("RUA 是聚合报告：它只覆盖报告期内的投递，且结论依赖报告方的观测口径"
                "（source_ip 取样点、对齐判定实现）。这与『本次审计这一时刻』不是一回事——"
                "报告期内没出现，不等于以后不出现；报告期外发生的事，本报告看不见。")


def _rua_undecidable(reason: str, *, policy_value: str,
                     org_name: Any = None, period: Any = None) -> dict[str, Any]:
    return {
        "status": "undecidable",
        "policy_under_test": policy_value,
        "org_name": org_name,
        "report_period": {"begin": (period or {}).get("begin"),
                          "end": (period or {}).get("end")},
        "period_note": _PERIOD_NOTE,
        "required_inputs": list(RUA_REQUIRED_INPUTS),
        "affected": [],
        "affected_total": 0,
        "clusters": [],
        "notes": [reason],
    }


def _load_json(path: str | Path, *, what: str) -> Any:
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        raise InputError("%s不存在：%s" % (what, path)) from None
    except OSError as exc:
        raise InputError("%s不可读：%s（%s）" % (what, path, exc)) from None
    try:
        return json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InputError("%s不是 UTF-8：%s（%s）" % (what, path, exc)) from None
    except json.JSONDecodeError as exc:
        raise InputError("%s JSON 语法错误：%s 第 %d 行第 %d 列：%s"
                         % (what, path, exc.lineno, exc.colno, exc.msg)) from None


# ── 结构差分（可复算：两个方向都能反推） ─────────────────────────────────


def diff_ledgers(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """对两份账本做结构差分。

    ``ops`` 的语义：把 ``ops`` 施加到 ``baseline`` 得到 ``candidate``；
    把 :func:`invert_ops` 之后的 ``ops`` 施加到 ``candidate`` 得到 ``baseline``。
    两个方向都由 :mod:`tests.test_whatif` 断言（"能反推基线"不是口号）。
    """
    ops: list[dict[str, Any]] = []
    _diff(baseline, candidate, (), ops)
    ops.sort(key=lambda item: item["path"])
    return {
        "schema_version": DIFF_SCHEMA_VERSION,
        "ops": ops,
        "op_count": len(ops),
        "changed_checks": _changed_checks(baseline, candidate),
        "summary": {
            "exit_code": {
                "from": (baseline.get("summary") or {}).get("exit_code"),
                "to": (candidate.get("summary") or {}).get("exit_code"),
            },
            "counts": {
                "from": (baseline.get("summary") or {}).get("counts"),
                "to": (candidate.get("summary") or {}).get("counts"),
            },
        },
    }


def _diff(a: Any, b: Any, path: tuple[Any, ...], ops: list[dict[str, Any]]) -> None:
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            if key in a and key in b:
                _diff(a[key], b[key], path + (key,), ops)
            elif key in b:
                ops.append({"op": "add", "path": _encode_path(path + (key,)),
                            "to": copy.deepcopy(b[key])})
            else:
                ops.append({"op": "remove", "path": _encode_path(path + (key,)),
                            "from": copy.deepcopy(a[key])})
        return
    # 只有"等长的、元素都是对象的列表"才按下标递归：长度不同的时候按下标做增删，
    # 重建顺序无法唯一定义（这个洞比"差分粒度粗一点"严重得多）。
    if _indexable(a) and _indexable(b) and len(a) == len(b):
        for position in range(len(a)):
            _diff(a[position], b[position], path + (position,), ops)
        return
    if a != b:
        ops.append({"op": "set", "path": _encode_path(path),
                    "from": copy.deepcopy(a), "to": copy.deepcopy(b)})


def _indexable(value: Any) -> bool:
    return (isinstance(value, list) and bool(value)
            and all(isinstance(item, dict) for item in value))


def _encode_path(path: tuple[Any, ...]) -> str:
    """编码成 JSON Pointer 形态（RFC 6901 的 ``~0`` / ``~1`` 转义）。"""
    return "/" + "/".join(
        str(element).replace("~", "~0").replace("/", "~1") for element in path)


def _decode_path(path: str) -> tuple[Any, ...]:
    if not path.startswith("/"):
        raise InputError("diff 路径必须是 `/` 开头的 JSON Pointer 形态：%r" % path)
    elements = []
    for raw in path.split("/")[1:]:
        element = raw.replace("~1", "/").replace("~0", "~")
        elements.append(int(element) if element.isdigit() else element)
    return tuple(elements)


def invert_ops(ops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """反转一组 ops（``add`` ↔ ``remove``，``set`` 的 ``from``/``to`` 互换）。"""
    flipped: list[dict[str, Any]] = []
    for op in ops:
        kind = op["op"]
        if kind == "set":
            flipped.append({"op": "set", "path": op["path"],
                            "from": copy.deepcopy(op.get("to")),
                            "to": copy.deepcopy(op.get("from"))})
        elif kind == "add":
            flipped.append({"op": "remove", "path": op["path"],
                            "from": copy.deepcopy(op.get("to"))})
        elif kind == "remove":
            flipped.append({"op": "add", "path": op["path"],
                            "to": copy.deepcopy(op.get("from"))})
        else:
            raise InputError("未知 diff 操作 %r" % (kind,))
    return flipped


def apply_ops(base: dict[str, Any], ops: list[dict[str, Any]]) -> dict[str, Any]:
    """把 ops 施加到 ``base`` 的深拷贝上（不动入参）。"""
    out = copy.deepcopy(base)
    for op in ops:
        path = _decode_path(op["path"])
        if not path:
            raise InputError("diff 路径不能为空")
        parent = out
        for element in path[:-1]:
            parent = parent[element]
        last = path[-1]
        kind = op["op"]
        if kind in ("set", "add"):
            parent[last] = copy.deepcopy(op["to"])
        elif kind == "remove":
            del parent[last]
        else:
            raise InputError("未知 diff 操作 %r" % (kind,))
    return out


def _changed_checks(baseline: dict[str, Any], candidate: dict[str, Any]) -> list[dict[str, Any]]:
    """人读用：逐条列出结果/字段发生变化的 ``checks[]`` 条目。"""
    before = baseline.get("checks") or []
    after = candidate.get("checks") or []
    rows: list[dict[str, Any]] = []
    for position in range(max(len(before), len(after))):
        left = before[position] if position < len(before) else None
        right = after[position] if position < len(after) else None
        if left is None or right is None:
            rows.append({
                "index": position,
                "check_id": (left or right or {}).get("check_id"),
                "presence": {"from": left is not None, "to": right is not None},
                "changed_fields": ["（条目增删）"],
                "result": {"from": (left or {}).get("result"),
                           "to": (right or {}).get("result")},
            })
            continue
        fields = [key for key in sorted(set(left) | set(right)) if left.get(key) != right.get(key)]
        if not fields:
            continue
        rows.append({
            "index": position,
            "check_id": right.get("check_id"),
            "changed_fields": fields,
            "result": {"from": left.get("result"), "to": right.get("result")},
        })
    return rows
