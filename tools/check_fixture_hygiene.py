#!/usr/bin/env python3
"""fixture 卫生守门：只用保留域 / 文档 IP 段（K11）。

题面 §2.4 红线"fixture 引用真实域名报文"对应评分栏直接记 0。
这条守门扫 `fixtures/` 与 `examples/` 下的全部文本产物，找"看起来像真实域名/IP"的串
（`examples/` 是 M6 归档的样例产物：它同样是**对外凭证**，必须同一套纪律）。

白名单（题面 §4）：
- 域名：`example.invalid` / `example.com` / `example.net` / `example.org` 及其子域
- IP：192.0.2.0/24、198.51.100.0/24、203.0.113.0/24、2001:db8::/32

**M0 无 fixture → SKIP 并打印扫描数**（"没扫到"必须与"都合规"可区分）。
M1 起有 fixture，本脚本转为 FAIL 判定。

**上游原样件的豁免（M1 登记）**：`fixtures/spf/rfc7208-tests.yml` 与
`fixtures/spf/rfc7208-tests.LICENSE` 是 openspf.org 测试集的 **pyspf 原样副本**，
其许可条款（rfc7208-tests.LICENSE 第 1 条）要求"保留原始版权声明"，且测试集自身
在 CHANGES 里明确写了用 1.2.3.4 等真实 IP 是历史遗留。改写它们会：
(a) 违反许可，(b) 让 203 条用例的期望值与上游漂移。
因此这两份文件**按原文保留**，豁免理由逐条登记在 `EXEMPT_FILES` 里，并在这里打印出来
——"放行了几份、为什么"必须是输出的一部分，不能静默跳过。

但豁免**只对这两份文件本身**：任何其它 fixture 引用真实域名/IP 依然报红。

变异验证：往 `fixtures/` 放一份含 `mail.google.com` 的文件 → 必须报红。

退出码：0 通过或 SKIP / 1 有违规。
"""

from __future__ import annotations

import argparse
import json
import ipaddress
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ALLOWED_DOMAIN_SUFFIXES = ("example.invalid", "example.com", "example.net", "example.org")
SKIP_EXTENSIONS = {".pem", ".key", ".der", ".png", ".jpg", ".pdf", ".zip", ".gz"}

#: 扫描面：`fixtures/`（输入 + 期望值）与 `examples/`（M6 归档的样例产物）。
#: 两者都是**对外凭证**——同一套保留域纪律必须同时管住它们，否则样例产物能夹带真实域名。
SCAN_DIRS = ("fixtures", "examples")

#: 上游原样件的豁免：**只能逐条登记**，每条必须写理由。
#: 判据：这份文件的字节本身是被许可要求保留的对象，改写即违约或改坏被测语义。
EXEMPT_FILES = {
    "fixtures/spf/rfc7208-tests.yml":
        "openspf.org 测试集原样副本；CHANGES 载明 1.2.3.4 等是历史遗留，改写会让 203 条期望漂移",
    "fixtures/spf/rfc7208-tests.LICENSE":
        "上游许可原文；第 1 条要求保留版权声明（含作者域名），改写即违约",
}

#: 只抓"像域名"的串：至少两级、顶级 2–24 个字母。
DOMAIN = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b")
#: IPv4 四段 / IPv6 粗略形态（含 `::`）。
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")

#: 文件名会被 DOMAIN 正则命中（`README.md` / `rua.json`）——它们是**文件引用**，不是域名。
#: 判据侧先剥掉行内代码与"已知文件扩展名"的 token，而不是把常见词一个个塞进白名单
#: （白名单写法会随文档增长而漏，且掩盖真实违规）。
FILE_EXTENSIONS = {
    "md", "json", "yml", "yaml", "txt", "py", "eml", "pem", "key", "dat", "cfg",
    "ini", "toml", "html", "css", "js", "mjs", "gz", "zip", "pdf", "png", "jpg",
    "csv", "tsv", "xml", "log", "rst", "sh", "bat", "cmd",
}

#: 文件名/扩展名常见串，会误命中 DOMAIN，显式放行。
IGNORE_TOKENS = {
    "e.g", "i.e", "etc.al", "www.example", "mailto",
    "rfc7208-tests.yml", "rfc7208-tests.license", "expected.json", "message.eml",
    "snap.json", "query.json", "verdict.json", "verdict.md", "public_suffix_list.dat",
}

#: RFC 8601 §2.2 的 **ptype 关键字**（``smtp.mailfrom=`` / ``header.d=`` / ``body.d=`` /
#: ``policy.*`` / ``dns.*``）。它们是**协议关键字**，不是数据载荷；形态却与两级域名
#: 无法区分（``smtp.mailfrom`` 的"TLD"是 8 个字母，正好落在 DOMAIN 的 2–24 区间）。
#:
#: 为什么剥它**不是放宽判据**：剥掉的是 ``ptype.property=`` 这整个 token，``=`` 右边
#: 真正的域名照旧被扫到——把 ``smtp.mailfrom=alice@list.example.org`` 换成
#: ``smtp.mailfrom=alice@mail.google.com``，``mail.google.com`` 照样报红。
#: 与 :data:`FILE_EXTENSIONS` 同一个思路：剥**结构性前缀**，不建"常见词白名单"。
#: ptype 是 RFC 登记过的闭集，不会随文档增长而需要补词。
AR_PTYPE = re.compile(r"\b(?:smtp|header|body|policy|dns)\.[a-z0-9-]+(?==)")

#: **RFC 引用**形态（``RFC5322.From`` / ``RFC7208.pdf``）：编号 + 后缀。
#: 它是条款引用，不是域名——没有一个真实注册域以"RFC"+数字开头。剥掉它不影响
#: 判据：注释/说明里写"RFC5322.From"照样绿，而写一个真域名照样红。
RFC_CITATION = re.compile(r"\bRFC\d+\.[A-Za-z0-9_]+")

#: 判定节点的**标识符命名空间**（``check_id`` 与 ``trace[].node`` 的首段）。
#: 与 :data:`AR_PTYPE` 同一个思路：剥**结构性前缀**（本项目自己的命名空间，闭集），
#: 不建"常见词白名单"。剥掉首段之后**剩余部分照旧被扫**——所以
#: ``walk.mail.google.com.0`` 会剥成 ``mail.google.com`` 并**照样报红**。
#: 首段**不在这个闭集里就不剥**（fail-closed）：新增命名空间必须在此显式登记，
#: 否则新命名空间会被当成域名候选（同 AR_PTYPE 的"扩闭集"处置）。
NODE_NAMESPACES = frozenset({
    "spf", "dkim", "dmarc", "reconcile", "whatif",   # 五个模块
    "align", "received", "snap", "walk",             # 模块内的子命名空间
    "n0",                                            # 通用求值节点 id
})

#: 命名空间之后的**跳数下标**（``walk.example.com.0`` / ``n0.1``）。
NODE_INDEX = re.compile(r"\.\d+$")

#: 只在**这两个字段**上做命名空间剥离——它们是标识符，不是数据载荷。
NODE_KEYS = frozenset({"check_id", "node"})


def _strip_node_identifier(value: str) -> str:
    """把 ``<命名空间>.<路径>.<下标>`` 剥成 ``<路径>``，让路径里的域名照旧被扫到。"""
    stripped = value.strip()
    head, dot, rest = stripped.partition(".")
    if dot and head in NODE_NAMESPACES:
        stripped = rest
    return NODE_INDEX.sub("", stripped)


def _strip_file_references(line: str) -> str:
    """剥掉行内代码、文件形态 token、RFC 引用与 RFC 8601 的 ``ptype.property=`` 前缀，再交给域名/IP 正则。

    `README.md` 这类 token 是**文件引用**，`smtp.mailfrom=` 这类是**协议关键字**，
    `RFC5322.From` 这类是**条款引用**；三者都不是被测对象。把它们判成"非保留域名"
    会让文档或产物只要提到文件名/属性名/条款就红（假红，且改不好）。
    """
    stripped = re.sub(r"`[^`]*`", " ", line)
    stripped = AR_PTYPE.sub(" ", stripped)
    stripped = RFC_CITATION.sub(" ", stripped)
    return re.sub(r"\b[\w./\-]+\.(?:" + "|".join(sorted(FILE_EXTENSIONS)) + r")\b", " ",
                  stripped)


def _domain_ok(domain: str) -> bool:
    lowered = domain.lower()
    if lowered in IGNORE_TOKENS:
        return True
    return any(lowered == suffix or lowered.endswith("." + suffix)
               for suffix in ALLOWED_DOMAIN_SUFFIXES)


def _json_items(payload: object) -> list[tuple[str, str]]:
    """取出一份 JSON 的**全部字符串值**及其**直接所在键**（不含键本身）。

    **为什么 JSON 只扫值不扫键**：键是 schema 字段名，值才是数据载荷。
    `expected.json` 的 `expect` 按 `plan/04` §2.1 写成**点路径 → 值**（如
    `"dkim.result": "pass"`），点路径与域名在字面上无法区分（`dkim.result` 与
    `mail.example` 同形）。把点路径塞进白名单会随字段增长而漏，并且会掩盖真实违规
    ——所以按**位置**区分：键不是被测对象，值才是。

    另外把**每个值的直接键名**一并带回：`verdict.json` 的 `check_id` / `trace[].node`
    里存的是**标识符**（`dmarc.evaluate` / `dkim.bh` / `walk.example.com.0`），
    与域名同形但仍要**剥命名空间前缀后扫描路径部分**（见 `_strip_node_identifier`）。

    真实域名只可能通过**值**进入 fixture（`snap.json` 的 `qname` / `answer`、
    `.eml` 的地址、`expected.json` 的 `why`），所以这个口径不漏掉任何可执行的引用。
    变异验证见 `tests/test_dkim.py::test_fixture_hygiene_catches_domain_in_json_value`
    与 `::test_fixture_hygiene_still_catches_a_domain_inside_a_node_id`。
    """
    found: list[tuple[str, str]] = []

    def walk(node: object, key: str) -> None:
        if isinstance(node, str):
            found.append((key, node))
        elif isinstance(node, dict):
            for name, value in node.items():
                walk(value, name)
        elif isinstance(node, list):
            for value in node:          # 列表元素继承**外层键名**（trace[] 的 node 等）
                walk(value, key)

    walk(payload, "")
    return found


def _scan_json(path: Path) -> list[tuple[str, str]] | None:
    """扫一份 JSON 的全部字符串值。解析失败 → 交给行扫描（语法坏的文件也要被抓）。"""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, OSError, json.JSONDecodeError):
        return None
    return _json_items(payload)


def _ip_ok(token: str) -> bool:
    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        return True  # 不是合法 IP（如版本号 1.2.3.4 段数不对）→ 不判
    if address.version == 4:
        return any(address in ipaddress.ip_network(net, strict=False) for net in (
            "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
        ))
    return address in ipaddress.ip_network("2001:db8::/32")


def scan(root: Path) -> tuple[list[str], int, list[str]]:
    """返回 (违规列表, 扫描文件数, 被豁免的文件列表)。

    扫描面 = :data:`SCAN_DIRS` 下存在的目录（`fixtures/` 是输入 + 期望值，
    `examples/` 是已归档的样例产物）。两者都是**对外凭证**，都必须只用保留域。
    """
    violations: list[str] = []
    scanned = 0
    exempted: list[str] = []
    scan_roots = [root / name for name in SCAN_DIRS if (root / name).is_dir()]
    if not scan_roots:
        return violations, scanned, exempted
    paths: list[Path] = []
    for scan_root in scan_roots:
        paths.extend(sorted(scan_root.rglob("*")))
    for path in paths:
        if not path.is_file() or path.suffix.lower() in SKIP_EXTENSIONS:
            continue
        rel = path.relative_to(root).as_posix()
        if rel in EXEMPT_FILES:
            exempted.append(rel)
            continue
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(root).as_posix()

        # JSON：只扫**字符串值**（键是 schema 字段名，不是数据；`plan/04` §2.1 的
        # `expect` 点路径与域名同形，扫键会假红）。解析不了就退回逐行扫描。
        json_values = _scan_json(path) if path.suffix.lower() == ".json" else None
        if json_values is not None:
            for key, value in json_values:
                # 标识符字段：先剥命名空间前缀，**路径部分照旧被扫**
                # （`walk.mail.google.com.0` → `mail.google.com` → 报红）。
                probe_value = _strip_node_identifier(value) if key in NODE_KEYS else value
                for match in DOMAIN.finditer(_strip_file_references(probe_value)):
                    token = match.group(0)
                    if not _domain_ok(token):
                        violations.append("%s JSON 值里出现非保留域名 %r" % (rel, token))
                for match in IPV4.finditer(probe_value):
                    if not _ip_ok(match.group(0)):
                        violations.append("%s JSON 值里出现非文档 IP 段 %r"
                                          % (rel, match.group(0)))
                for match in IPV6.finditer(probe_value):
                    token = match.group(0)
                    if token.count(":") >= 2 and not _ip_ok(token):
                        violations.append("%s JSON 值里出现非文档 IPv6 段 %r" % (rel, token))
            continue

        for lineno, line in enumerate(text.split("\n"), 1):
            if line.lstrip().startswith("#") or line.lstrip().startswith(";"):
                continue  # 注释行常用于说明，不参与判定
            probe = _strip_file_references(line)
            for match in DOMAIN.finditer(probe):
                token = match.group(0)
                if not _domain_ok(token):
                    violations.append("%s:%d 非保留域名 %r" % (rel, lineno, token))
            for match in IPV4.finditer(probe):
                if not _ip_ok(match.group(0)):
                    violations.append("%s:%d 非文档 IP 段 %r" % (rel, lineno, match.group(0)))
            for match in IPV6.finditer(probe):
                token = match.group(0)
                if token.count(":") >= 2 and not _ip_ok(token):
                    violations.append("%s:%d 非文档 IPv6 段 %r" % (rel, lineno, token))
    return violations, scanned, exempted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="fixture 卫生守门")
    parser.add_argument("--root", default=None)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else ROOT

    violations, scanned, exempted = scan(root)
    print("fixture 卫生守门 · 只用保留域 / 文档 IP 段（面：fixtures/ + examples/）")
    print("=" * 60)
    if scanned == 0 and not exempted:
        print("SKIP  扫了 0 份 fixture/examples（M0 尚无产物；M1 起 fixtures 转 FAIL 判定，"
              "M6 起 examples 一并扫）")
        print("=" * 60)
        print("这轮扫到：0 份")
        print("结论: SKIP（不是通过）")
        return 0
    for item in violations:
        print("FAIL  %s" % item)
    if not violations:
        print("PASS  %d 份 fixture/examples 全部使用保留域/文档 IP 段" % scanned)
    if exempted:
        print("-" * 60)
        print("EXEMPT  %d 份上游原样件（逐条登记理由，不是静默跳过）:" % len(exempted))
        for rel in exempted:
            print("  - %s：%s" % (rel, EXEMPT_FILES[rel]))
    print("=" * 60)
    print("这轮扫到：%d 份（另豁免 %d 份）" % (scanned, len(exempted)))
    print("结论: %s" % ("全绿" if not violations else "%d 处违规" % len(violations)))
    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main())
