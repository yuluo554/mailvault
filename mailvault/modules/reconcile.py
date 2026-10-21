"""三方对账（M5）：报文里的 ``Authentication-Results`` **vs** 本工具在同一份快照上的重算。

对账对象（`plan/01` §3 的 M4）：
``Authentication-Results``（RFC 8601）里的结论 **vs** M2–M4 在同一份快照 + 同一份
``query.json`` 上重算出来的 SPF / DKIM / DMARC 结论。

三分类（`constants.RECONCILE_CLASSES`）：

- ``consistent``：报文头里的结论与本工具重算**一致**。
- ``contradiction``：两者**不一致**。这类条目**必须**给 ≥
  :data:`constants.RECONCILE_MIN_EXPLANATIONS` 条可能解释，每条带 ``hypothesis`` +
  ``verify``（"具体要查什么"）。给不出两种解释就把"看不懂"伪装成了"已定论"。
- ``undecidable``：**判不了**。三类情形都归这里（全部 fail-closed）：

  1. ``authserv_id`` 不在 ``trusted_authserv_ids`` 里；
  2. ``authserv_id`` 或整条 ``Authentication-Results`` 不可解析
     （参照 authres_status #86 的教训：不可解析时 **fail-open** 会把他人写的头当成有效证据）；
  3. 重算侧给不出可比结论（本工具不重算该方法、快照缺该判定所需的查询、
     重算结果是 ``undecidable``）。

**``trusted_authserv_ids`` 为空 ≠ 全部可信**：空列表表示"没有配置可信 MTA"，
此时**任何** ``Authentication-Results`` 都不构成证据 → 全部 ``undecidable``。

**零系统时钟**（K7）：``Received`` 链的时间只取报文头里的**字面值**，只做
"沿链是否单调"的**相互比较**，从不与系统时钟比较——与系统时钟比较会让同一份输入
在不同时刻给出不同账本。

**``contradiction`` 不等于 ``fail``**：两张头里写的结论不一样，本工具不知道哪一张描述
的是现实（题面风险 ③：极易被读成"你被黑了"）。所以对账条目在账本里以
``reconcile.cross_check`` **一条**汇总：全一致 → ``pass``；出现矛盾或判不了 →
``undecidable``；一个 ``Authentication-Results`` 都没有 → ``none``。
**没有**把矛盾映射成 ``fail``——那正是要避免的误读。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any

from ..constants import (
    RECONCILE_CLASSES,
    RECONCILE_MIN_EXPLANATIONS,
    RESULTS,
    STRICT_FORBIDDEN,
)
from ..exits import InternalError
from ..ledger import check_entry

#: 条款引用（`docs/ledger-format.md` §2.2 的 `RFC<number>#<section>` 形态）。
REF_AR_HEADER = "RFC8601#2.5"
REF_AR_RESULTS = "RFC8601#5"
REF_AR_PROPERTIES = "RFC8601#4.1"
REF_AR_FOREIGN = "RFC8601#7.1"
REF_RECEIVED = "RFC5321#4.4"
REF_RECEIVED_DATE = "RFC5322#3.6.7"
REF_SPF = "RFC7208#4.6.4"
REF_DKIM = "RFC6376#6.1.3"
REF_DMARC = "RFC9989#4.10"

#: ``authserv-id`` 与 ``method`` 的形态。**刻意收紧**：放宽会让"看起来像个域名"
#: 的任意 token 通过，于是"不可解析"这条 fail-closed 分支永远走不到。
_AUTHSERV_ID = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_METHOD = re.compile(r"\A[a-z][a-z0-9-]*\Z")

#: ``method=value`` 的 result 取值的合法集合：SPF/DKIM/DMARC 复用同一套词（RFC 8601 §2.7）。
_AR_RESULTS = frozenset(RESULTS) | {"unknown"}


@dataclass(frozen=True)
class Claim:
    """一条 ``method=result`` 声明（``Authentication-Results`` 头里的一段）。"""

    index: int
    source: str
    authserv_id: str | None
    authserv_version: str | None
    method: str
    result: str | None
    reason: str | None
    properties: tuple[tuple[str, str], ...]
    raw: str
    parse_note: str | None = None

    @property
    def parsed(self) -> bool:
        return self.parse_note is None

    def property(self, name: str) -> str | None:
        """取 ``ptype.property``（或裸 ``property``）的值；没有 → ``None``。"""
        wanted = name.lower()
        for key, value in self.properties:
            if key.lower() == wanted:
                return value
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "authserv_id": self.authserv_id,
            "authserv_version": self.authserv_version,
            "method": self.method,
            "result": self.result,
            "reason": self.reason,
            "properties": [[k, v] for k, v in self.properties],
            "parsed": self.parsed,
            "parse_note": self.parse_note,
        }


@dataclass(frozen=True)
class Entry:
    """一条对账结论。"""

    klass: str
    claimed: dict[str, Any]
    recomputed: dict[str, Any]
    explanations: tuple[dict[str, str], ...]
    warnings: tuple[str, ...]
    strict_evidence_ok: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "class": self.klass,
            "claimed": self.claimed,
            "recomputed": self.recomputed,
            "explanations": [dict(item) for item in self.explanations],
            "warnings": list(self.warnings),
            "strict_evidence_ok": self.strict_evidence_ok,
        }


@dataclass(frozen=True)
class ReconcileResult:
    """一次对账的完整结论。"""

    entries: tuple[Entry, ...]
    received_chain: dict[str, Any]
    authserv_ids: tuple[str, ...]
    trusted_authserv_ids: tuple[str, ...]
    notes: tuple[str, ...]
    evidence_ref: tuple[str, ...]
    strict_evidence_ok: bool

    @property
    def classes(self) -> dict[str, int]:
        counts = {name: 0 for name in RECONCILE_CLASSES}
        for entry in self.entries:
            counts[entry.klass] = counts.get(entry.klass, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """账本里的 ``reconcile`` 块（`docs/ledger-format.md` §5）。"""
        return {
            "entries": [entry.to_dict() for entry in self.entries],
            "received_chain": self.received_chain,
            "authserv_ids": list(self.authserv_ids),
            "trusted_authserv_ids": list(self.trusted_authserv_ids),
            "notes": list(self.notes),
            "strict_evidence_ok": self.strict_evidence_ok,
        }

    def to_check_entry(self) -> dict[str, Any]:
        """汇总成**一条** ``checks[]`` 条目（见模块 docstring 的口径说明）。"""
        counts = self.classes
        if not self.entries:
            result = "none"
            reason = ("报文里没有可对账的 Authentication-Results 头；"
                      "本项不构成判定（不是通过，也不是失败）")
        elif counts["contradiction"] or counts["undecidable"]:
            result = "undecidable"
            reason = ("对账 %d 条：一致 %d、矛盾 %d、无法判定 %d——"
                      "存在矛盾或无法判定即判 undecidable，不折成 fail"
                      % (len(self.entries), counts["consistent"],
                         counts["contradiction"], counts["undecidable"]))
        else:
            result = "pass"
            reason = "对账 %d 条：报文头里的结论与本工具重算全部一致" % len(self.entries)

        subject = {
            "entries": len(self.entries),
            "consistent": counts["consistent"],
            "contradiction": counts["contradiction"],
            "undecidable": counts["undecidable"],
            "received_hops": self.received_chain.get("hop_count", 0),
            "received_monotonic": self.received_chain.get("monotonic"),
            "trusted_authserv_ids": len(self.trusted_authserv_ids),
        }
        return check_entry(
            check_id="reconcile.cross_check",
            module="M5",
            subject=subject,
            result=result,
            reason=reason,
            evidence_ref=list(self.evidence_ref),
            trace=list(self.received_chain.get("dates") or []),
            warnings=list(self.notes),
            tree=None,
        )


# ── Authentication-Results 解析（RFC 8601 §2.2） ──────────────────────────


def parse_authentication_results(message: Any) -> list[Claim]:
    """从报文里取全部 ``Authentication-Results`` 头，逐条解析。

    每条头解析出：``authserv-id``（可选版本号）+ 若干 ``method=result`` 段
    （段内可带 ``(reason)`` 与 ``ptype.property=value``）。

    **解析不了不抛异常，而是返回带 ``parse_note`` 的 :class:`Claim`**：
    一条坏头不该炸掉整份账本；它该变成一条 ``undecidable`` 的对账结论，
    让读者看见"这里有一张头，我看不懂，所以它不算证据"。
    """
    claims: list[Claim] = []
    for index, value in enumerate(message.get_all("Authentication-Results")):
        claims.extend(_parse_one(value, index=index))
    return claims


def _parse_one(value: str, *, index: int) -> list[Claim]:
    raw = value
    text = " ".join(value.split())
    if not text:
        return [_broken(index, raw, authserv_id=None, note="Authentication-Results 头为空")]

    segments = _split_top_level(text, ";")
    head = segments[0].strip()
    tokens = head.split()
    authserv_id: str | None = None
    authserv_version: str | None = None

    if len(tokens) == 1:
        authserv_id = tokens[0]
    elif len(tokens) == 2 and tokens[1].isdigit():
        # RFC 8601 §2.2：authserv-id 之后可跟一个整数版本号。
        authserv_id = tokens[0]
        authserv_version = tokens[1]
    else:
        return [_broken(index, raw, authserv_id=None,
                        note="authserv-id 段有 %d 个 token（%s），既不是一个 authserv-id，"
                             "也不是『authserv-id + 版本号』→ 按不可解析处理"
                             % (len(tokens), " ".join(tokens[:4])))]
    if not _AUTHSERV_ID.match(authserv_id):
        return [_broken(index, raw, authserv_id=authserv_id,
                        note="authserv-id %r 不是合法的 dot-atom（RFC 8601 §2.5）" % authserv_id)]

    out: list[Claim] = []
    for segment in segments[1:]:
        segment = segment.strip()
        if not segment or segment.lower() == "none":
            # `; none` 是 RFC 8601 §2.2 的显式"没有结论"，不是一条 method 声明。
            continue
        out.append(_parse_segment(segment, index=index, raw=raw,
                                  authserv_id=authserv_id, version=authserv_version))
    if not out:
        out.append(Claim(
            index=index, source="Authentication-Results", authserv_id=authserv_id,
            authserv_version=authserv_version, method="*", result=None, reason=None,
            properties=(), raw=raw,
            parse_note="这张头里没有任何 method=result 声明（只有 authserv-id / 显式 none）",
        ))
    return out


def _parse_segment(segment: str, *, index: int, raw: str,
                   authserv_id: str, version: str | None) -> Claim:
    reason = None
    match = re.search(r"\(([^)]*)\)", segment)
    if match:
        reason = match.group(1).strip() or None
    core = re.sub(r"\([^)]*\)", " ", segment).strip()
    parts = core.split()
    if not parts:
        return _broken(index, raw, authserv_id=authserv_id,
                       note="method 段只剩括号注释（%r）" % segment[:40])

    head = parts[0]
    if "=" in head:
        method, _, value = head.partition("=")
        result = value.strip().lower() or None
    else:
        # RFC 8601 §2.2：`method` 后不带 `=` 时，result-value 默认是 `none`。
        method = head
        result = "none"
    method = method.strip().lower()

    properties: list[tuple[str, str]] = []
    for token in parts[1:]:
        key, _, prop_value = token.partition("=")
        properties.append((key.strip(), prop_value.strip()))

    note = None
    if not _METHOD.match(method):
        note = "method %r 不是合法关键字" % method
        result = None
    elif result is not None and result not in _AR_RESULTS:
        note = "result %r 不在本工具的结果枚举里（RFC 8601 §2.7）" % result
        result = None

    return Claim(
        index=index, source="Authentication-Results", authserv_id=authserv_id,
        authserv_version=version, method=method, result=result, reason=reason,
        properties=tuple(properties), raw=raw, parse_note=note,
    )


def _broken(index: int, raw: str, *, authserv_id: str | None, note: str) -> Claim:
    return Claim(
        index=index, source="Authentication-Results", authserv_id=authserv_id,
        authserv_version=None, method="*", result=None, reason=None,
        properties=(), raw=raw, parse_note=note,
    )


def _split_top_level(text: str, delimiter: str) -> list[str]:
    """按 ``delimiter`` 切分，但**不切括号内**（``(reason)`` 里可以出现 ``;``）。"""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        if char == delimiter and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


# ── Received 链（RFC 5321 §4.4 / RFC 5322 §3.6.7） ───────────────────────


def received_chain(message: Any) -> dict[str, Any]:
    """``Received`` 链的单调性与时钟回退。

    ``Received`` 头由收件方**前插**（RFC 5321 §4.4），所以报文里的物理顺序是
    **最新在前**；沿列表往下走，时间应当**不递增**。任何一处"往下走反而更新"
    就是一次时钟回退，逐处登记（`index` 是物理下标，从 0 起）。

    时间**只取报文头里的字面值**，只做相互比较，**从不与系统时钟比较**（K7）。
    有头但解析不出时间 → ``monotonic = null``（判不了就说判不了，不猜）。
    """
    values = list(message.get_all("Received"))
    dates: list[dict[str, Any]] = []
    parsed: list[tuple[int, Any, str]] = []
    unparsed = 0

    for index, value in enumerate(values):
        stamp, note = _received_stamp(value)
        moment = _parse_stamp(stamp) if stamp else None
        if moment is None and not note:
            note = "时间戳 %r 解析不出（或没有时区偏移，无法跨跳比较）" % stamp
        dates.append({"node": "received.%d" % index,
                      "note": ("%s｜%s" % (stamp, note)) if note else stamp})
        if moment is None:
            unparsed += 1
            continue
        parsed.append((index, moment, stamp))

    regressions: list[dict[str, Any]] = []
    for position in range(1, len(parsed)):
        previous_index, previous_dt, previous_raw = parsed[position - 1]
        index, current_dt, current_raw = parsed[position]
        if current_dt > previous_dt:
            regressions.append({
                "from_index": previous_index,
                "to_index": index,
                "from": previous_raw,
                "to": current_raw,
                "note": "物理顺序靠下的 Received 时间反而更新：沿链时间应不递增",
            })

    monotonic: bool | None
    if unparsed:
        monotonic = None
    else:
        monotonic = not regressions

    notes: list[str] = []
    if unparsed:
        notes.append("%d 个 Received 头的时间无法解析 → 链单调性判不了（不猜）" % unparsed)
    if regressions:
        notes.append("%d 处时钟回退（沿链时间应不递增）" % len(regressions))

    return {
        "monotonic": monotonic,
        "clock_regressions": regressions,
        "hop_count": len(values),
        "unparsed_dates": unparsed,
        "dates": dates,
        "notes": notes,
    }


def _received_stamp(value: str) -> tuple[str | None, str]:
    """取 ``Received`` 头里 ``;`` 之后的日期时间字面值。

    返回 ``(字面值, 说明)``；取不到 → ``(None, 原因)``。
    """
    head, separator, tail = value.rpartition(";")
    if not separator:
        return None, "Received 头里没有 `;` 之后的时间戳"
    stamp = " ".join(tail.split())
    if not stamp:
        return None, "Received 头的 `;` 之后为空"
    return stamp, ""


def _parse_stamp(stamp: str) -> Any:
    """把日期时间字面值解析成可比较的时刻；解析不了 → ``None``。

    **不与系统时钟比较**（K7）：这里只把字面值变成可比较对象，比较发生在调用方，
    对象之间相互比较。无时区偏移的时间戳跨跳不可比（不同跳可能用不同本地时区），
    按"解析不了"处理——猜一个时区去比会给出看起来确定的错答案。
    """
    cleaned = re.sub(r"\([^)]*\)", " ", stamp).strip()
    for candidate in (cleaned, stamp):
        try:
            parsed = parsedate_to_datetime(candidate)
        except (TypeError, ValueError):
            continue
        if parsed is None:
            continue
        return parsed if parsed.tzinfo is not None else None
    return None


# ── 对账主体 ────────────────────────────────────────────────────────────


def evaluate(
    message: Any,
    *,
    spf: Any | None = None,
    dkim: Any | None = None,
    dmarc: Any | None = None,
    query: Any | None = None,
    author_domain: str | None = None,
) -> ReconcileResult:
    """对账。

    参数
    ----
    message
        :class:`mailvault.eml.Message`。
    spf / dkim / dmarc
        M2–M4 的结论对象。``None`` 表示"这一类没有重算"（对应方法一律 ``undecidable``）。
    query
        :class:`mailvault.query.Query`；用于取 ``trusted_authserv_ids`` 与信封域。
    author_domain
        ``RFC5322.From`` 的 Author Domain。由调用方给出（它已经为 DMARC 算过一次）——
        本模块**不**去 import `dmarc.py` 复算：L3 模块之间不互相 import
        （`plan/03` §0 的分层），而且两处各算一次必然出现"两个 Author Domain"。
        ``None`` 时退回 ``dmarc.author_domain``。
    """
    trusted = tuple(getattr(query, "trusted_authserv_ids", ()) or ())
    trusted_lower = {item.lower() for item in trusted}
    mail_from_domain = (getattr(query, "sender_domain", "") or "") if query is not None else ""
    if author_domain is None:
        author_domain = getattr(dmarc, "author_domain", None)
    from_domain = author_domain or ""

    claims = parse_authentication_results(message) if message is not None else []
    recomputed = _recompute_index(spf=spf, dkim=dkim, dmarc=dmarc)

    context = {
        "mail_from_domain": mail_from_domain,
        "from_domain": from_domain,
        "hop_count": len(message.get_all("Received")) if message is not None else 0,
        "dkim_body_hash_failure": _has_dkim_body_hash_failure(dkim),
        "dkim_domains": tuple(sorted(
            {sig.domain.lower() for sig in getattr(dkim, "signatures", ()) if sig.domain})),
    }

    entries: list[Entry] = []
    notes: list[str] = []
    authserv_seen: list[str] = []

    for claim in claims:
        if claim.authserv_id and claim.authserv_id not in authserv_seen:
            authserv_seen.append(claim.authserv_id)
        entries.append(_reconcile_one(
            claim, recomputed, trusted_lower=trusted_lower, context=context))

    if not trusted:
        notes.append(
            "query.json 的 trusted_authserv_ids 为空：**没有配置任何可信 MTA**，"
            "因此报文头里的 Authentication-Results 一律不作为证据（判 undecidable）。"
            "空列表不是『全部可信』——那是把可信判断交给写信头的人（RFC 8601 §7.1）")
    if not claims:
        notes.append("报文里没有 Authentication-Results 头，本次没有可对账的声称值")

    chain = received_chain(message) if message is not None else {
        "monotonic": None, "clock_regressions": [], "hop_count": 0,
        "unparsed_dates": 0, "dates": [], "notes": [],
    }
    notes.extend(chain.get("notes") or [])

    refs = [REF_AR_HEADER, REF_AR_RESULTS, REF_RECEIVED, REF_RECEIVED_DATE, REF_AR_FOREIGN]
    ok = all(entry.strict_evidence_ok for entry in entries)

    return ReconcileResult(
        entries=tuple(entries),
        received_chain=chain,
        authserv_ids=tuple(authserv_seen),
        trusted_authserv_ids=trusted,
        notes=tuple(notes),
        evidence_ref=tuple(refs),
        strict_evidence_ok=ok,
    )


def _reconcile_one(claim: Claim, recomputed: dict[str, Any], *,
                   trusted_lower: set[str], context: dict[str, Any]) -> Entry:
    method = claim.method
    claimed = claim.to_dict()

    trusted = bool(claim.authserv_id) and claim.authserv_id.lower() in trusted_lower
    warnings: list[str] = []
    if not claim.parsed:
        klass = "undecidable"
        warnings.append("头不可解析：%s → fail-closed 判无法判定（RFC 8601 §2.5）"
                        % (claim.parse_note or "原因未记录"))
        recomputed_view = {"result": None, "ref": REF_AR_HEADER}
        explanations: tuple[dict[str, str], ...] = ()
    elif not trusted:
        klass = "undecidable"
        warnings.append(
            "authserv-id %r 不在 trusted_authserv_ids=%s 里 → fail-closed 判无法判定"
            % (claim.authserv_id, sorted(trusted_lower) or "（空）"))
        recomputed_view = _recomputed_view(method, claim, recomputed)
        explanations = ()
    else:
        computed_result, ref, note = _recomputed_result(method, claim, recomputed)
        recomputed_view = {"result": computed_result, "ref": ref}
        if note:
            warnings.append(note)
        verdict, explanations = _classify(
            method=method, claimed_result=claim.result,
            computed_result=computed_result, context=context)
        klass = verdict

    entry = Entry(
        klass=klass, claimed=claimed, recomputed=recomputed_view,
        explanations=explanations, warnings=tuple(warnings),
        strict_evidence_ok=_strict_ok(klass, claimed, recomputed_view, explanations, warnings),
    )
    if entry.klass == "contradiction" and len(entry.explanations) < RECONCILE_MIN_EXPLANATIONS:
        raise InternalError(
            "contradiction 必须给 ≥%d 条解释（题面 M4 硬性要求），实得 %d 条"
            % (RECONCILE_MIN_EXPLANATIONS, len(entry.explanations)))
    return entry


def _classify(*, method: str, claimed_result: str | None, computed_result: str | None,
              context: dict[str, Any]) -> tuple[str, tuple[dict[str, str], ...]]:
    if claimed_result is None or computed_result is None:
        return "undecidable", ()
    if computed_result == "undecidable":
        return "undecidable", ()
    if claimed_result == "unknown":
        return "undecidable", ()
    if claimed_result == computed_result:
        return "consistent", ()
    return "contradiction", _hypotheses(method, claimed_result, computed_result, context)


def _recompute_index(*, spf: Any | None, dkim: Any | None, dmarc: Any | None) -> dict[str, Any]:
    per_domain: dict[str, str] = {}
    results: list[str] = []
    for signature in getattr(dkim, "signatures", ()) or ():
        results.append(signature.result)
        if signature.domain:
            per_domain[signature.domain.lower()] = signature.result
    aggregate: str | None = None
    if dkim is not None:
        if "pass" in results:
            aggregate = "pass"
        elif any(item in ("fail", "permerror", "softfail") for item in results):
            aggregate = "fail"
        elif "undecidable" in results:
            aggregate = "undecidable"
        elif results:
            aggregate = "none"
        else:
            aggregate = "none"
    return {
        "spf": getattr(spf, "result", None),
        "dmarc": getattr(dmarc, "result", None),
        "dkim": aggregate,
        "dkim_per_domain": per_domain,
        "dkim_signatures": len(results),
    }


def _recomputed_view(method: str, claim: Claim, recomputed: dict[str, Any]) -> dict[str, Any]:
    result, ref, _note = _recomputed_result(method, claim, recomputed)
    return {"result": result, "ref": ref}


def _recomputed_result(method: str, claim: Claim,
                       recomputed: dict[str, Any]) -> tuple[str | None, str, str]:
    """返回 ``(重算结果, 条款, 说明)``。``None`` 表示本工具给不出可比结论。"""
    if method == "spf":
        return recomputed.get("spf"), REF_SPF, ""
    if method == "dmarc":
        return recomputed.get("dmarc"), REF_DMARC, ""
    if method == "dkim":
        domain = claim.property("header.d")
        if domain:
            found = recomputed.get("dkim_per_domain", {}).get(domain.lower())
            if found is None:
                return None, REF_DKIM, (
                    "报文里没有 d=%s 的 DKIM 签名（claimed 提到的那条签名不在本工具看到的"
                    "签名集里）→ 判无法判定" % domain)
            return found, REF_DKIM, ""
        return recomputed.get("dkim"), REF_DKIM, (
            "claimed 的 dkim 段没有 header.d，按**全部签名的聚合结果**比较")
    if method in ("auth", "iprev"):
        return None, REF_AR_RESULTS, (
            "method %r 不属于本工具重算的范围（只重算 spf / dkim / dmarc）→ 判无法判定"
            % method)
    return None, REF_AR_RESULTS, (
        "method %r 本工具不重算 → 判无法判定（不猜）" % method)


def _has_dkim_body_hash_failure(dkim: Any | None) -> bool:
    if dkim is None:
        return False
    for signature in getattr(dkim, "signatures", ()) or ():
        failure = signature.failure_at or {}
        if failure.get("kind") == "body_hash":
            return True
    return False


# ── 双解释（每条都要有"具体要查什么"） ───────────────────────────────────


def _hypotheses(method: str, claimed: str, computed: str,
                context: dict[str, Any]) -> tuple[dict[str, str], ...]:
    mail_from = context.get("mail_from_domain") or "（空）"
    from_domain = context.get("from_domain") or "（空）"
    hops = context.get("hop_count", 0)
    out: list[dict[str, str]] = []

    if method == "spf":
        out.append({
            "hypothesis": "转发或重投递改写了信封发件人（例如邮件列表用 SRS 重写 MAIL FROM），"
                          "报文头记录的是改写之前那一次检查",
            "verify": "比对 query.mail_from 的域（%s）与 RFC5322.From 的域（%s）是否不同；"
                      "再看 Received 链（%d 跳）里是否存在转发/列表跳" % (mail_from, from_domain, hops),
        })
        out.append({
            "hypothesis": "接收方当时解析到的 SPF 记录与本次快照里的不同（DNS 变更或视图不同）",
            "verify": "在接收时刻前后各取一份快照（snapshot fetch）用同一份输入重跑，"
                      "看 spf.result 是否翻转；并比对 snap.json 的 fetched_at 与 Received "
                      "首跳时间的先后",
        })
        out.append({
            "hypothesis": "本次快照缺少该判定所需的查询（数据缺口），而不是真的结果不同",
            "verify": "看 spf 条目的 data_gap / warnings 里列了哪条 (qname, qtype)："
                      "缺哪条就 snapshot fetch 补一条再重跑",
        })
    elif method == "dkim":
        if context.get("dkim_body_hash_failure"):
            out.append({
                "hypothesis": "内容网关在验签之后重写了正文（追加页脚、清洗 HTML、重排空白）",
                "verify": "把正文与签名者留存的原件比对；检查正文尾部是否多出网关声明或页脚，"
                          "并看 dkim 条目的 failure_at.kind 是否为 body_hash",
            })
            out.append({
                "hypothesis": "报文在归档或转发途中被改（不是签名者改的）",
                "verify": "用签名者留存的原件重算 bh=；若原件能过而这份过不了，"
                          "说明改动发生在传输/归档环节",
            })
        else:
            out.append({
                "hypothesis": "报文头里的结论由某中间 MTA 在另一份 DNS 视图或另一时刻得出",
                "verify": "在接收时刻附近取快照重跑；比对 selector 与 DNS 里的 key 记录是否一致",
            })
            out.append({
                "hypothesis": "签名头在传输中被重排，或某个字段被网关规范化改写过",
                "verify": "逐条比对 DKIM-Signature 的 h= 列表与报文实际头顺序；"
                          "检查是否有网关追加头；看 dkim 条目的 failure_at.kind",
            })
        domains = context.get("dkim_domains") or ()
        out.append({
            "hypothesis": "报文头声称的签名与报文里现存的签名不是同一条",
            "verify": "比对 claimed 的 header.d / header.s 与报文里每条签名的 d= / s=；"
                      "本工具看到的签名域是 %s"
                      % ("、".join(domains) if domains else "（一条签名都没有）"),
        })
    else:
        out.append({
            "hypothesis": "报文头里的结论由另一份 DNS 视图或另一时刻得出（快照时点不同）",
            "verify": "取接收时刻附近的快照重跑同一份输入，看 %s 的重算结果是否翻转" % method,
        })
        out.append({
            "hypothesis": "报文头里的结论由另一次求值（不同实现或不同口径）得出",
            "verify": "对照两边的口径差异：PSL 版本 / `psd` 语义 / 对齐模式（relaxed vs strict）/"
                      "`pct` 等旧标签是否被采纳",
        })

    while len(out) < RECONCILE_MIN_EXPLANATIONS:
        out.append({
            "hypothesis": "本工具与报文头所依据的规则版本不同",
            "verify": "核对各自引用的 RFC 版本与条款节，逐条对照差异",
        })
    return tuple(out)


# ── strict-evidence 自检 ─────────────────────────────────────────────────


def _strict_ok(klass: str, claimed: dict[str, Any], recomputed: dict[str, Any],
               explanations: tuple[dict[str, str], ...],
               warnings: list[str]) -> bool:
    """对账**自己生成的**归档串做禁词自检（K10）。

    为什么要在装配期查一次：`--strict-evidence` 的失败必须是"账本里真的写了定性词"，
    而不是"渲染时才发现"。这里把该条目的全部字符串（含 claimed 里原样带来的
    ``reason``）都扫一遍——账本会被归档、被转发，原样带进来的定性词同样是风险。
    """
    haystack: list[str] = [klass]
    for key, value in claimed.items():
        haystack.append("%s=%r" % (key, value))
    for key, value in recomputed.items():
        haystack.append("%s=%r" % (key, value))
    for item in explanations:
        haystack.append(item.get("hypothesis", ""))
        haystack.append(item.get("verify", ""))
    haystack.extend(warnings)
    text = "\n".join(haystack).lower()
    return not any(word.lower() in text for word in STRICT_FORBIDDEN)
