"""PSL 冻结件读取 + Organizational Domain（M1 实现，M4 使用）。

为什么"随包冻结"而不是运行时取最新：题面 §2.5 灰区 3 明确要求**输出必须带 PSL 版本与日期**。
如果运行时联网取，同一份 `snap.json` 在不同日子会得到不同的 Organizational Domain，
"两次运行逐字节一致"当场失效，而且失效得很安静。所以：

- 冻结件 = ``mailvault/data/public_suffix_list.dat``（上游原样字节，``.gitattributes`` 标 ``-text``）；
- 版本/日期/来源/校验和 = ``mailvault/data/psl.meta.json``；
- 运行时只读这两个文件，**不联网**（K3：本模块不 import 任何网络模块）。

规则语义按 publicsuffix.org 的算法（"Pulling the list" 一节）：

1. 把域按 ``.`` 切成标签，从**最右**往左逐段匹配；
2. ``!foo.bar`` 是**例外规则**：命中即"公共后缀 = 去掉最左标签后的部分"；
3. ``*.foo.bar`` 是**通配规则**：``*`` 匹配恰好一个标签；
4. 没有规则命中 → 默认规则 ``*``（即"顶层标签本身就是公共后缀"）；
5. **Organizational Domain（注册域）= 公共后缀再往左加一个标签**；若标签数已等于公共后缀长度
   （即域本身就是公共后缀），则没有 Organizational Domain → 返回 ``None``。

实现选择：用**倒序后缀表**（``dict[tuple[str, ...], Rule]``）而不是逐条正则，
匹配是"从最长后缀往短试"，复杂度与域长度成线性，且结果与规则顺序无关（确定性）。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .exits import InputError

#: 随包冻结件的位置（相对本模块）。
DATA_DIR = Path(__file__).resolve().parent / "data"
PSL_FILENAME = "public_suffix_list.dat"
PSL_META_FILENAME = "psl.meta.json"

#: 规则种类（写进结果，便于诊断"为什么这个域被切在这里"）。
RULE_NORMAL = "normal"
RULE_WILDCARD = "wildcard"
RULE_EXCEPTION = "exception"
RULE_DEFAULT = "default"

#: PSL 的两段（ICANN / PRIVATE）。分段落库是为了让调用方可以选择"只用 ICANN 段"。
SECTION_ICANN = "icann"
SECTION_PRIVATE = "private"

_BEGIN_ICANN = "===BEGIN ICANN DOMAINS==="
_END_ICANN = "===END ICANN DOMAINS==="
_BEGIN_PRIVATE = "===BEGIN PRIVATE DOMAINS==="
_END_PRIVATE = "===END PRIVATE DOMAINS==="


@dataclass(frozen=True)
class Rule:
    """命中的一条 PSL 规则。"""

    text: str
    kind: str
    section: str
    labels: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"text": self.text, "kind": self.kind, "section": self.section}


@dataclass(frozen=True)
class DomainInfo:
    """一个域的切分结果。"""

    domain: str
    public_suffix: str
    organizational_domain: str | None
    rule: Rule

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "public_suffix": self.public_suffix,
            "organizational_domain": self.organizational_domain,
            "rule": self.rule.to_dict(),
        }


class PSL:
    """冻结的 Public Suffix List 视图（构造后只读）。"""

    __slots__ = ("_rules", "_exceptions", "_meta", "_source")

    def __init__(self, rules: list[Rule], exceptions: list[Rule],
                 meta: dict[str, Any], source: str) -> None:
        #: 后缀标签元组 → 规则。通配规则在键里保留 ``*`` 字面量，匹配时替换。
        self._rules: dict[tuple[str, ...], Rule] = {}
        for rule in rules:
            self._rules[rule.labels] = rule
        self._exceptions: dict[tuple[str, ...], Rule] = {
            rule.labels: rule for rule in exceptions}
        self._meta = meta
        self._source = source

    # ── 元数据（输出必带，题面 §2.5 灰区 3） ────────────────────────────
    @property
    def version(self) -> str:
        return str(self._meta["version"])

    @property
    def date(self) -> str:
        return str(self._meta["date"])

    @property
    def source_url(self) -> str:
        return str(self._meta["source_url"])

    @property
    def sha256(self) -> str:
        return str(self._meta["sha256"])

    @property
    def meta(self) -> dict[str, Any]:
        return dict(self._meta)

    @property
    def rule_count(self) -> int:
        return len(self._rules) + len(self._exceptions)

    def version_block(self) -> dict[str, str]:
        """账本里"PSL 口径"的标准块。"""
        return {"psl_version": self.version, "psl_date": self.date}

    # ── 查询 ───────────────────────────────────────────────────────────
    def public_suffix(self, domain: str, *, include_private: bool = True) -> Rule:
        """返回命中的规则（其 ``labels`` 即公共后缀的标签序列）。"""
        labels = _split_labels(domain)
        if not labels:
            raise InputError("PSL：域名为空，无法判定公共后缀")

        # 1) 例外规则优先：最长后缀匹配
        for size in range(len(labels), 0, -1):
            candidate = labels[-size:]
            rule = self._exceptions.get(candidate)
            if rule is not None:
                return rule

        # 2) 普通 / 通配规则：从最长后缀往短试
        for size in range(len(labels), 0, -1):
            candidate = labels[-size:]
            rule = self._rules.get(candidate)
            if rule is not None:
                if _section_allowed(rule, include_private):
                    return rule
                continue
            # 通配：把最左标签替换成 `*`
            if size >= 2:
                wildcard_key = ("*",) + candidate[1:]
                rule = self._rules.get(wildcard_key)
                if rule is not None and _section_allowed(rule, include_private):
                    return rule

        # 3) 默认规则：顶层标签即公共后缀（RFC 算法 §"The default rule"）
        return Rule(text="*", kind=RULE_DEFAULT, section=SECTION_ICANN,
                    labels=(labels[-1],))

    def organizational_domain(self, domain: str) -> str | None:
        """Organizational Domain（= 公共后缀 + 加一个标签）。

        域本身就是公共后缀 → ``None``（没有"注册域"这一层，例如 ``com``、``co.uk``）。
        """
        return self.analyze(domain).organizational_domain

    def analyze(self, domain: str, *, include_private: bool = True) -> DomainInfo:
        normalized = _normalize(domain)
        labels = _split_labels(normalized)
        rule = self.public_suffix(normalized, include_private=include_private)

        if rule.kind == RULE_EXCEPTION:
            # 例外规则：公共后缀 = 去掉最左标签后的部分
            suffix_labels = rule.labels[1:]
        else:
            suffix_labels = rule.labels

        suffix_size = len(suffix_labels)
        if len(labels) <= suffix_size:
            org: str | None = None
        else:
            org = ".".join(labels[len(labels) - suffix_size - 1:])

        return DomainInfo(
            domain=normalized,
            public_suffix=".".join(labels[len(labels) - suffix_size:]) if suffix_size else "",
            organizational_domain=org,
            rule=rule,
        )

    def to_dict(self) -> dict[str, Any]:
        return {"meta": self.meta, "rule_count": self.rule_count, "source": self._source}


# ── 加载 ────────────────────────────────────────────────────────────────


def default_psl() -> PSL:
    """加载随包冻结件。"""
    return load_psl(DATA_DIR / PSL_FILENAME, DATA_DIR / PSL_META_FILENAME)


def load_psl(dat_path: str | Path | None = None,
             meta_path: str | Path | None = None) -> PSL:
    """读冻结件 + 元数据，并校验 ``sha256`` 与元数据一致。

    校验和落在元数据里、每次加载都复核：冻结件被误改（例如被 git 归一化换行）时，
    这里会当场报错，而不是悄悄给出不同的 Organizational Domain。
    """
    dat = Path(dat_path) if dat_path is not None else DATA_DIR / PSL_FILENAME
    meta_file = Path(meta_path) if meta_path is not None else DATA_DIR / PSL_META_FILENAME

    try:
        raw = dat.read_bytes()
    except FileNotFoundError:
        raise InputError("PSL 冻结件不存在：%s" % dat) from None
    except OSError as exc:
        raise InputError("PSL 冻结件不可读：%s（%s）" % (dat, exc)) from None

    meta = _load_meta(meta_file)
    actual = _sha256(raw)
    expected = str(meta.get("sha256", ""))
    if not expected:
        raise InputError("PSL 元数据缺 sha256：%s" % meta_file)
    if actual != expected:
        raise InputError(
            "PSL 冻结件 sha256 不匹配（%s）：元数据登记 %s，实际 %s。"
            "冻结件字节即版本证据，被归一化或误改时必须重取。"
            % (dat, expected[:16] + "…", actual[:16] + "…"))

    rules, exceptions = _parse_rules(raw.decode("utf-8", "replace"))
    return PSL(rules, exceptions, meta, source=str(dat))


def _load_meta(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise InputError("PSL 元数据不存在：%s" % path) from None
    except OSError as exc:
        raise InputError("PSL 元数据不可读：%s（%s）" % (path, exc)) from None
    try:
        meta = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InputError("PSL 元数据不是 UTF-8：%s（%s）" % (path, exc)) from None
    except json.JSONDecodeError as exc:
        raise InputError("PSL 元数据 JSON 语法错误：%s 第 %d 行第 %d 列：%s"
                         % (path, exc.lineno, exc.colno, exc.msg)) from None
    if not isinstance(meta, dict):
        raise InputError("PSL 元数据顶层必须是对象：%s" % path)
    for field in ("version", "date", "source_url", "sha256"):
        if not isinstance(meta.get(field), str) or not meta[field].strip():
            raise InputError("PSL 元数据缺 %s：%s" % (field, path))
    return meta


def _parse_rules(text: str) -> tuple[list[Rule], list[Rule]]:
    """解析 PSL 文本。注释行以 ``//`` 开头；空行跳过。"""
    rules: list[Rule] = []
    exceptions: list[Rule] = []
    section = SECTION_ICANN

    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("//"):
            if _BEGIN_PRIVATE in stripped or stripped == "// " + _BEGIN_PRIVATE:
                section = SECTION_PRIVATE
            elif _END_PRIVATE in stripped:
                section = SECTION_ICANN
            continue
        if stripped == _BEGIN_ICANN or stripped == _BEGIN_PRIVATE:
            section = SECTION_ICANN if stripped == _BEGIN_ICANN else SECTION_PRIVATE
            continue
        if stripped == _END_ICANN:
            section = SECTION_ICANN
            continue
        if stripped == _END_PRIVATE:
            section = SECTION_ICANN
            continue

        # 行尾的 `//` 注释
        body = stripped.split("//", 1)[0].strip()
        if not body:
            continue

        if body.startswith("!"):
            rule = Rule(text=body, kind=RULE_EXCEPTION, section=section,
                        labels=_split_labels(body[1:]))
            exceptions.append(rule)
        elif body.startswith("*."):
            rule = Rule(text=body, kind=RULE_WILDCARD, section=section,
                        labels=_split_labels(body))
            rules.append(rule)
        elif body.startswith("*"):
            # 单独一个 `*`（默认规则的显式写法）
            rules.append(Rule(text=body, kind=RULE_WILDCARD, section=section, labels=("*",)))
        else:
            rules.append(Rule(text=body, kind=RULE_NORMAL, section=section,
                              labels=_split_labels(body)))

    return rules, exceptions


def _section_allowed(rule: Rule, include_private: bool) -> bool:
    return include_private or rule.section == SECTION_ICANN


def _normalize(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def _split_labels(domain: str) -> tuple[str, ...]:
    normalized = _normalize(domain)
    if not normalized:
        return ()
    return tuple(label for label in normalized.split(".") if label)


def _sha256(raw: bytes) -> str:
    import hashlib

    return hashlib.sha256(raw).hexdigest()
