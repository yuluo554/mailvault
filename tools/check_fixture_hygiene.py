#!/usr/bin/env python3
"""fixture 卫生守门：只用保留域 / 文档 IP 段（K11）。

题面 §2.4 红线"fixture 引用真实域名报文"对应评分栏直接记 0。
这条守门扫 `fixtures/` 下的全部文本产物，找"看起来像真实域名/IP"的串。

白名单（题面 §4）：
- 域名：`example.invalid` / `example.com` / `example.net` / `example.org` 及其子域
- IP：192.0.2.0/24、198.51.100.0/24、203.0.113.0/24、2001:db8::/32

**M0 无 fixture → SKIP 并打印扫描数**（"没扫到"必须与"都合规"可区分）。
M1 起有 fixture，本脚本转为 FAIL 判定。

变异验证：往 `fixtures/` 放一份含 `mail.google.com` 的文件 → 必须报红。

退出码：0 通过或 SKIP / 1 有违规。
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ALLOWED_DOMAIN_SUFFIXES = ("example.invalid", "example.com", "example.net", "example.org")
SKIP_EXTENSIONS = {".pem", ".key", ".der", ".png", ".jpg", ".pdf", ".zip", ".gz"}

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


def _strip_file_references(line: str) -> str:
    """剥掉行内代码与文件形态 token，再交给域名/IP 正则。

    `README.md` 这类 token 是**文件引用**，不是被测对象；把它判成"非保留域名"
    会让文档只要提到文件名就红（假红，且改文档改不好）。
    """
    stripped = re.sub(r"`[^`]*`", " ", line)
    return re.sub(r"\b[\w./\-]+\.(?:" + "|".join(sorted(FILE_EXTENSIONS)) + r")\b", " ", stripped)


def _domain_ok(domain: str) -> bool:
    lowered = domain.lower()
    if lowered in IGNORE_TOKENS:
        return True
    return any(lowered == suffix or lowered.endswith("." + suffix)
               for suffix in ALLOWED_DOMAIN_SUFFIXES)


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


def scan(root: Path) -> tuple[list[str], int]:
    violations: list[str] = []
    scanned = 0
    fixtures = root / "fixtures"
    if not fixtures.is_dir():
        return violations, scanned
    for path in sorted(fixtures.rglob("*")):
        if not path.is_file() or path.suffix.lower() in SKIP_EXTENSIONS:
            continue
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(root).as_posix()
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
    return violations, scanned


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="fixture 卫生守门")
    parser.add_argument("--root", default=None)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else ROOT

    violations, scanned = scan(root)
    print("fixture 卫生守门 · 只用保留域 / 文档 IP 段")
    print("=" * 60)
    if scanned == 0:
        print("SKIP  扫了 0 份 fixture（M0 尚无 fixture；M1 起本项转为 FAIL 判定）")
        print("=" * 60)
        print("这轮扫到：0 份")
        print("结论: SKIP（不是通过）")
        return 0
    for item in violations:
        print("FAIL  %s" % item)
    if not violations:
        print("PASS  %d 份 fixture 全部使用保留域/文档 IP 段" % scanned)
    print("=" * 60)
    print("这轮扫到：%d 份" % scanned)
    print("结论: %s" % ("全绿" if not violations else "%d 处违规" % len(violations)))
    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main())
