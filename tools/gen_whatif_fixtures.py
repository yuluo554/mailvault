#!/usr/bin/env python3
"""生成 `fixtures/whatif/` 的反事实样本、RUA 报告与期望值（**开发期工具**）。

样本集：

| 文件 / 目录 | 作用 |
|---|---|
| `rua.json` | 最小 RUA 聚合报告（模拟 parsedmarc 导出形态），用于"上 `p=reject` 会打断谁" |
| `changes.json` | 默认候选变更集合，与 CLI 的 `--change KEY=VALUE` 同形 |
| `spf-tighten/` | 基线 SPF 是 `?all`（neutral）→ 收紧为 `-all`（fail）后**退出码 0 翻成 1** |
| `p-reject/` | 基线 `p=none` 且 SPF 不过 → 改 `p=reject` 后**处置从 none 变 reject** |

为什么需要两个用例而不是一个：

- 只做 `p=reject` 的话，"差分"里永远只有 DMARC 那几个字段在动，看不出 SPF 侧也会变；
- 只做 `all=-all` 的话，RUA 的"会打断谁"没有对应的策略变更可挂。
- `spf-tighten` 还专门证明**退出码会随配置变化**（0 → 1），这是"差分不是装饰"最直观的一条。

幂等性（`plan/04` §2.5）：`--check` 重生成后逐字节比对已入仓文件。

用法：

    py -3.12 tools/gen_whatif_fixtures.py            # 生成/覆盖
    py -3.12 tools/gen_whatif_fixtures.py --check    # 只比对，不写盘；不一致 → 退出码 1

退出码：0 成功 / 1 `--check` 不一致。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURE_DIR = ROOT / "fixtures" / "whatif"

PSL_VERSION = "2026-10-20_08-40-56_UTC"
PSL_DATE = "2026-10-20"
FETCHED_AT = "2026-10-19T18:35:00Z"

TRUSTED_MX = "mx.example.com"

#: 基线 SPF：客户端 198.51.100.9 **不在** ip4 段里。
SPF_LOGIN_LOOSE = "v=spf1 ip4:192.0.2.0/24 ?all"
SPF_LOGIN_LOOSE_SOFTFAIL = "v=spf1 ip4:192.0.2.0/24 ~all"

DMARC_NONE = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"

CLIENT_IP = "198.51.100.9"


def _q(qname: str, answer: list[str] | None = None, *, rcode: str = "NOERROR",
       qtype: str = "TXT") -> dict:
    return {"qname": qname, "qtype": qtype, "rcode": rcode,
            "answer": list(answer or []), "ttl": 300}


def _snap(queries: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "fetched_at": FETCHED_AT,
        "resolver": "synthetic",
        "psl_version": PSL_VERSION,
        "psl_date": PSL_DATE,
        "queries": queries,
    }


def _query(mail_from: str = "alice@example.com") -> dict:
    return {
        "mail_from": mail_from,
        "client_ip": CLIENT_IP,
        "helo": "mail.example.com",
        "trusted_authserv_ids": [TRUSTED_MX],
    }


def _message() -> bytes:
    return (
        b"Received: from mail.example.com by mx.example.com; Thu, 1 Jan 2026 00:00:00 +0000\r\n"
        b"From: Alice <alice@example.com>\r\n"
        b"To: Bob <bob@example.net>\r\n"
        b"Subject: what-if fixture\r\n"
        b"Date: Thu, 1 Jan 2026 00:00:00 +0000\r\n"
        b"Message-ID: <whatif-fixture@example.com>\r\n"
        b"\r\n"
        b"Hello Bob,\r\n"
        b"\r\n"
        b"what-if fixture body.\r\n"
    )


def _expected(case_id: str, changes: list[str], expect: dict, why: str,
              *, rua: str | None = None) -> dict:
    return {
        "case_id": case_id,
        "input": {"snapshot": "snap.json", "query": "query.json", "eml": "message.eml",
                  "changes": changes, "rua": rua},
        "expect": expect,
        "why": why,
    }


def build_cases() -> dict[str, dict]:
    cases: dict[str, dict] = {}

    # ══ spf-tighten：`?all` → `-all`，退出码 0 翻 1 ═══════════════════
    # 基线：Author 域没有 DMARC 记录（`_dmarc.example.com` 与 `_dmarc.com` 都明确
    # 答复 NXDOMAIN——**不是**没查过，否则是数据缺口 → undecidable）。
    # SPF 的 `?all` 命中 → neutral；DKIM 未签名 → none；DMARC 无记录 → none。
    # 三项都不是 fail → 退出码 0。
    # 收紧为 `-all` 后 SPF 变 fail → 退出码 1。SPF 的 `all=` 是**策略松紧**的开关，
    # 这条样本证明"改配置 → 结论真的变了"，而不是"差分里只有时间戳在动"。
    cases["spf-tighten"] = {
        "message": _message(),
        "snap": _snap([
            _q("example.com", [SPF_LOGIN_LOOSE]),
            _q("_dmarc.example.com", [], rcode="NXDOMAIN"),
            _q("_dmarc.com", [], rcode="NXDOMAIN"),
        ]),
        "query": _query(),
        "expected": _expected(
            "whatif-spf-tighten-01",
            ["all=-all"],
            {
                "baseline.spf.result": "neutral",
                "baseline.dmarc.result": "none",
                "baseline.exit_code": 0,
                "candidate.spf.result": "fail",
                "candidate.exit_code": 1,
                "diff.op_count_gt": 0,
                "diff.exit_code.from": 0,
                "diff.exit_code.to": 1,
                "applied[0].key": "all",
                "applied[0].from": SPF_LOGIN_LOOSE,
                "applied[0].to": "v=spf1 ip4:192.0.2.0/24 -all",
                "rua.status": "undecidable",
            },
            "RFC 7208 §5.1：`?all` 命中给 neutral、`-all` 命中给 fail。"
            "基线没有 DMARC 记录（两个 `_dmarc` 都明确 NXDOMAIN，不是数据缺口），"
            "所以基线三项 = neutral / none / none → 退出码 0；"
            "把 `all=` 收紧为 `-all` 后 SPF 判 fail → 退出码 1。"
            "这条样本证明 what-if 的差分**真的改变了判定与退出码**。"
            "未提供 --rua → RUA 关联判 undecidable 并给出所需输入清单（不猜）",
        ),
    }

    # ══ p-reject：`p=none` → `p=reject`，处置从 none 变 reject ═════════
    # 基线：SPF 是 `~all`（softfail，客户端不在 ip4 段里）→ DMARC 因为没有 pass 的
    # 对齐标识判 fail，按 `p=none` 施加 → 处置 none。
    # 改 `p=reject` 后同一份输入下的处置变成 reject——这正是 RUA 关联要回答的问题：
    # "上 p=reject 会打断谁"。
    cases["p-reject"] = {
        "message": _message(),
        "snap": _snap([
            _q("example.com", [SPF_LOGIN_LOOSE_SOFTFAIL]),
            _q("_dmarc.example.com", [DMARC_NONE]),
            _q("_dmarc.com", [], rcode="NXDOMAIN"),
            _q("_dmarc.example.net", [], rcode="NXDOMAIN"),
        ]),
        "query": _query(),
        "expected": _expected(
            "whatif-p-reject-01",
            ["p=reject"],
            {
                "baseline.spf.result": "softfail",
                "baseline.dmarc.result": "fail",
                "baseline.dmarc.subject.disposition": "none",
                "baseline.dmarc.subject.disposition_status": "determined",
                "baseline.exit_code": 1,
                "candidate.dmarc.result": "fail",
                "candidate.dmarc.subject.disposition": "reject",
                "candidate.dmarc.subject.policy_value": "reject",
                "candidate.exit_code": 1,
                "diff.op_count_gt": 0,
                "applied[0].key": "p",
                "applied[0].record": "_dmarc.example.com",
                "rua.status": "complete",
                "rua.affected_total": 1,
                "rua.affected[0].source_ip": "198.51.100.9",
                "rua.period_note_contains": "只覆盖报告期内",
            },
            "RFC 9989 §4.10.1 + §4.7：`p=none` 改 `p=reject` 后，同一份输入里"
            "『没有对齐标识』这件事不变（DMARC 仍判 fail），但**处置**从 none 变 reject。"
            "这正是题面 §3 的 M5 要回答的问题：上 p=reject 会打断谁。"
            "`fixtures/whatif/rua.json` 里只有一条记录的 SPF 与 DKIM **都**没通过，"
            "所以 affected_total=1。输出必须标注『只覆盖报告期内且依赖报告方口径』",
            rua="rua.json",
        ),
    }

    return cases


# ── RUA 报告与变更集合 ──────────────────────────────────────────────────


def build_rua() -> dict:
    """最小 RUA 聚合报告（模拟 parsedmarc 导出；字段名照其 JSON 形态）。

    三条记录，覆盖三种形态，且**只有一条**（198.51.100.9）SPF 与 DKIM 都没过：
    - 192.0.2.10：SPF fail 但 DKIM pass → 对齐成立，`p=reject` **不会**打断；
    - 198.51.100.9：SPF 与 DKIM 都 fail → 对齐不成立，`p=reject` **会**打断；
    - 203.0.113.7：两者都 pass → 不受影响。

    这样 affected 的筛选逻辑（"两个都没过"才算）被真实数据钉住：写错成
    "任一不过就算"会把第一条也列进来，数量立刻从 1 变 2。
    """
    return {
        "report_metadata": {
            "org_name": "Example Receiver Co",
            "email": "dmarc-reports@example.net",
            "report_id": "rua-2026-01-01-example-com",
            "date_range": {"begin": 1767225600, "end": 1767312000},
        },
        "policy_published": {
            "domain": "example.com", "p": "none", "sp": "none",
            "adkim": "r", "aspf": "r",
        },
        "records": [
            {
                "source_ip": "192.0.2.10", "count": 42,
                "identifiers": {"header_from": "example.com"},
                "policy_evaluated": {"disposition": "none", "dkim": "pass", "spf": "fail"},
                "auth_results": {
                    "spf": [{"domain": "example.com", "result": "fail"}],
                    "dkim": [{"domain": "example.com", "result": "pass"}],
                },
            },
            {
                "source_ip": "198.51.100.9", "count": 7,
                "identifiers": {"header_from": "example.com"},
                "policy_evaluated": {"disposition": "none", "dkim": "fail", "spf": "fail"},
                "auth_results": {
                    "spf": [{"domain": "example.com", "result": "fail"}],
                    "dkim": [],
                },
            },
            {
                "source_ip": "203.0.113.7", "count": 128,
                "identifiers": {"header_from": "example.com"},
                "policy_evaluated": {"disposition": "none", "dkim": "pass", "spf": "pass"},
                "auth_results": {
                    "spf": [{"domain": "example.com", "result": "pass"}],
                    "dkim": [{"domain": "example.com", "result": "pass"}],
                },
            },
        ],
    }


def build_changes() -> dict:
    """默认候选变更集合：与 CLI 的 ``--change KEY=VALUE`` **同形**（字符串列表）。

    写成列表而不是对象：CLI 收的就是 `p=reject` 这种字符串，两边同形就不存在
    "fixture 里写成对象、命令行要写字符串"的转换层——那种转换层是漂移的温床。
    """
    return {
        "note": "与 `mailvault whatif --change` 同形；逐条施加到快照副本后重跑 M2–M4",
        "changes": ["p=reject", "all=-all"],
    }


# ── 落盘 ────────────────────────────────────────────────────────────────


def _json(obj: dict) -> bytes:
    from mailvault import canonical

    return (canonical.dumps_pretty(obj) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="生成 fixtures/whatif 样本")
    parser.add_argument("--check", action="store_true",
                        help="只比对已入仓文件，不写盘（plan/04 §2.5 的幂等检查）")
    args = parser.parse_args(argv)

    cases = build_cases()
    artifacts: dict[str, bytes] = {
        "rua.json": _json(build_rua()),
        "changes.json": _json(build_changes()),
    }
    for case_id in sorted(cases):
        case = cases[case_id]
        artifacts["%s/message.eml" % case_id] = case["message"]
        artifacts["%s/snap.json" % case_id] = _json(case["snap"])
        artifacts["%s/query.json" % case_id] = _json(case["query"])
        artifacts["%s/expected.json" % case_id] = _json(case["expected"])

    mismatches: list[str] = []
    written = 0
    for name in sorted(artifacts):
        target = FIXTURE_DIR / name
        payload = artifacts[name]
        if args.check:
            if not target.is_file():
                mismatches.append("%s 缺失" % name)
            elif target.read_bytes() != payload:
                mismatches.append("%s 字节不一致" % name)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            written += 1

    print("whatif fixture 生成器 · %d 个用例 + RUA 报告 + 变更集合" % len(cases))
    print("=" * 60)
    for name in sorted(artifacts):
        print("  %s" % name)
    print("=" * 60)
    if args.check:
        if mismatches:
            for item in mismatches:
                print("FAIL  %s" % item)
            print("结论: %d 处不一致（生成器不幂等）" % len(mismatches))
            return 1
        print("PASS  %d 份产物逐字节一致" % len(artifacts))
        return 0
    print("已写入 %d 份文件" % written)
    return 0


if __name__ == "__main__":
    sys.exit(main())