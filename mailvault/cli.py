"""CLI：参数解析 + 子命令分派 + **异常 → 退出码**（唯一转换点）。

契约（M0 冻结，见 `plan/03` §2）：

```
mailvault [--version] <command> ...
  snapshot fetch --eml <path> --query <path> -o <snap.json> [--resolver <name>]
  audit   --snapshot <snap.json> --eml <msg.eml> --query <query.json>
          [--json <out>] [--md <out>] [--out-dir <dir>] [--strict-evidence]
  whatif  --snapshot ... --eml ... --query ... --change <k=v> [--change ...] [...]
  diff    --baseline <verdict.json> --candidate <verdict.json> [...]
```

`--change` 是**可重复参数**（`action="append"`），不是逗号分隔，也**不加** `choices=`。
理由：文档里写的是 `--change p=reject --change t=y`；给 argparse 加 `choices` 会把整串
当一个值，于是"文档三处对、代码一处拦"，README 第一条命令就 exit 2。

退出码统一（`plan/03` §4）：argparse 的 `SystemExit(2)` 在入口转成 ``3``（输入错误），
否则它会与 `undecidable` 的 ``2`` 撞语义。
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from . import __version__
from .canonical import dump_file, write_text
from .constants import (
    DIFF_JSON_FILENAME,
    DIFF_MD_FILENAME,
    DIFF_SCHEMA_VERSION,
    LEDGER_SCHEMA_VERSION,
    VERDICT_JSON_FILENAME,
    VERDICT_MD_FILENAME,
)
from .exits import ExitCode, InputError, InternalError, ModuleNotReady

EPILOG = """\
两条显式否定：
  1. 不承诺进箱——本工具不输出"进箱概率"，不做内容打分，不做发信测试。
  2. 不卖"离线"——离线重放本身不是差异化（已有工具能 --dns-cache 重放）。
     差异化是条款级账本、三方对账、what-if 差分。

审计阶段零网络：只有 `snapshot fetch` 会联网，且是一次性显式动作。
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mailvault",
        description="离线邮件认证判定账本：SPF/DKIM/DMARC 在同一份 DNS 快照上求值，"
                    "逐条挂 RFC 条款与求值轨迹。",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="mailvault %s" % __version__)

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # ── snapshot fetch（唯一联网点） ──────────────────────────────────
    snapshot = subparsers.add_parser("snapshot", help="快照操作（fetch 是唯一联网动作）")
    snapshot_sub = snapshot.add_subparsers(dest="snapshot_command", metavar="<subcommand>")
    fetch = snapshot_sub.add_parser("fetch", help="抓取一份 DNS 快照到 snap.json")
    fetch.add_argument("--eml", required=True, help="报文路径（用于推导要查哪些记录）")
    fetch.add_argument("--query", required=True, help="query.json 路径")
    fetch.add_argument("-o", "--output", required=True, help="输出的 snap.json 路径")
    fetch.add_argument("--resolver", default=None, help="DNS 解析器（默认系统解析器）")
    fetch.add_argument("--psl", default=None, help="PSL 冻结件路径（默认随包冻结件）")

    # ── audit ─────────────────────────────────────────────────────────
    audit = subparsers.add_parser("audit", help="在快照上审计一份报文，产出判定账本")
    _add_io_args(audit)
    audit.add_argument("--snapshot", required=True, help="snap.json 路径")
    audit.add_argument("--eml", required=True, help="message.eml 路径")
    audit.add_argument("--query", required=True, help="query.json 路径")
    audit.add_argument("--strict-evidence", action="store_true",
                       help="禁词模式：输出不得出现『攻击/伪造/被黑』等定性词")

    # ── whatif ────────────────────────────────────────────────────────
    whatif = subparsers.add_parser("whatif", help="反事实差分：改一条配置，只重跑 M1–M3 并做差分")
    _add_io_args(whatif)
    whatif.add_argument("--snapshot", required=True, help="snap.json 路径")
    whatif.add_argument("--eml", required=True, help="message.eml 路径")
    whatif.add_argument("--query", required=True, help="query.json 路径")
    whatif.add_argument("--change", action="append", default=[], metavar="KEY=VALUE",
                        help="候选变更，可重复：--change p=reject --change t=y")
    whatif.add_argument("--rua", default=None, help="RUA 报告（parsedmarc 导出 JSON），可选")
    whatif.add_argument("--strict-evidence", action="store_true",
                        help="禁词模式：对账解释与差分报告不得出现『攻击/伪造/被黑』等定性词")

    # ── diff ──────────────────────────────────────────────────────────
    diff = subparsers.add_parser("diff", help="比较两份 verdict.json 的判定差异")
    _add_io_args(diff)
    diff.add_argument("--baseline", required=True, help="基线 verdict.json")
    diff.add_argument("--candidate", required=True, help="候选 verdict.json")
    diff.add_argument("--strict-evidence", action="store_true",
                      help="禁词模式：差分报告不得出现定性词")

    return parser


def _add_io_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", dest="json_out", default=None,
                        help="JSON 输出路径（`-` 表示写 stdout）；未给时写 out-dir 下的默认名")
    parser.add_argument("--md", dest="md_out", default=None,
                        help="Markdown 输出路径；未给时写 out-dir 下的默认名")
    parser.add_argument("--out-dir", dest="out_dir", default=None,
                        help="未指定 --json/--md 时的输出目录（默认当前目录）；"
                             "默认文件名 audit/whatif=verdict.*，diff=diff.*")


def main(argv: list[str] | None = None) -> int:
    """入口。返回退出码（0/1/2/3/4），不调用 ``sys.exit``——便于测试。"""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse 默认 exit 2，与 undecidable 撞语义 → 转 3
        code = exc.code
        if code == 0:
            raise
        return int(ExitCode.INPUT_ERROR)

    if not args.command:
        parser.print_help()
        return int(ExitCode.INPUT_ERROR)

    try:
        return _dispatch(args, parser)
    except ModuleNotReady as exc:
        # 未实现 ≠ 输入错误：措辞与退出码都要对得上（2 = undecidable）。
        _stderr("尚未实现：%s" % exc)
        return int(exc.exit_code)
    except InputError as exc:
        _stderr("输入错误：%s" % exc)
        return int(exc.exit_code)
    except InternalError as exc:
        # 不吞异常：打栈，便于定位。
        import traceback

        traceback.print_exc()
        _stderr("内部错误：%s" % exc)
        return int(ExitCode.INTERNAL_ERROR)
    except BrokenPipeError:
        return int(ExitCode.OK)


def _dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.command == "snapshot":
        if getattr(args, "snapshot_command", None) != "fetch":
            _stderr("用法：mailvault snapshot fetch --eml <path> --query <path> -o <snap.json>")
            return int(ExitCode.INPUT_ERROR)
        return _cmd_snapshot_fetch(args)
    if args.command == "audit":
        return _cmd_audit(args)
    if args.command == "whatif":
        return _cmd_whatif(args)
    if args.command == "diff":
        return _cmd_diff(args)
    parser.print_help()
    return int(ExitCode.INPUT_ERROR)


# ── 子命令实现（M0：全是 fail-closed 骨架） ──────────────────────────────


def _cmd_snapshot_fetch(args: argparse.Namespace) -> int:
    """抓一份快照落盘。**这是全仓唯一联网路径**（`plan/03` §0：net.py 是唯一 socket 出口）。"""
    from .net import fetch_snapshot

    snapshot = fetch_snapshot(
        eml=args.eml,
        query=args.query,
        resolver=args.resolver,
        psl_path=args.psl,
    )
    # 落盘必须走 canonical（K2）：键排序 + 零浮点 + 单个尾换行。
    dump_file(args.output, snapshot)
    _stderr("已写入 %s（%d 条查询，resolver=%s）"
            % (args.output, len(snapshot["queries"]), snapshot["resolver"]))
    return int(ExitCode.OK)


def _cmd_audit(args: argparse.Namespace) -> int:
    """审计一份报文：读三件套 → 跑 SPF + DKIM + DMARC → 三方对账 → 装配账本 → 落盘两轨。

    M2 起 ``audit`` 是真的在跑判定（不再是 ``ModuleNotReady``）。退出码由
    ``ledger.summary.exit_code`` 决定，它来自 ``exits.exit_code_for``（优先级唯一出处）
    ——**多模块共用一条优先级**，每个模块不各自算退出码（那必然漂移）。
    """
    from .eml import load_eml
    from .ledger import assemble
    from .modules.reconcile import evaluate as reconcile_evaluate
    from .modules.dmarc import summary_text as dmarc_summary
    from .query import load_query
    from .snapshot import load_snapshot

    # 读入顺序：快照 → 查询 → 报文。先读快照是因为它是"判定所依赖的那份世界"，
    # 缺它时后面的解析再成功也没有意义（报错顺序会影响用户第一眼看到什么）。
    snapshot = load_snapshot(args.snapshot)
    context = load_query(args.query)
    message = load_eml(args.eml)

    trace: list[dict[str, Any]] = []
    spf, dkim, dmarc, checks = _run_checks(snapshot, message, context, trace=trace)
    # 对账吃前三者的**结论** + 报文里的 Authentication-Results / Received。
    reconcile = reconcile_evaluate(
        message, spf=spf, dkim=dkim, dmarc=dmarc, query=context,
        author_domain=dmarc.author_domain)
    checks.append(reconcile.to_check_entry())

    ledger = assemble(
        snapshot_meta=snapshot.meta(),
        query=context.to_dict(),
        checks=checks,
        reconcile=reconcile.to_dict(),
    )
    _strict_guard(args, reconcile)
    markdown = _render(ledger, strict_evidence=args.strict_evidence)
    write_outputs(args, ledger, markdown)
    _stderr("SPF 判定：%s（%s）" % (spf.result, spf.reason))
    _stderr("DKIM 判定：%s" % dkim.summary)
    _stderr(dmarc_summary(dmarc))
    _stderr("对账：%s" % _reconcile_summary(reconcile))
    return int(ledger["summary"]["exit_code"])


def _cmd_whatif(args: argparse.Namespace) -> int:
    """反事实差分：**只重跑** M2–M4（不重写求值器），再对基线账本做结构差分。

    参数面校验在最前面（未知键 / 不可解析的值 → exit 3），这样"参数写错"与
    "功能没做"是两种不同输出（`plan/03` §2 第 3 条）。
    """
    from .eml import load_eml
    from .ledger import assemble
    from .modules.reconcile import evaluate as reconcile_evaluate
    from .modules.whatif import apply_changes, diff_ledgers, parse_changes, rua_association
    from .query import load_query
    from .snapshot import from_dict as snapshot_from_dict
    from .snapshot import load_snapshot

    changes = parse_changes(args.change)

    snapshot = load_snapshot(args.snapshot)
    context = load_query(args.query)
    message = load_eml(args.eml)

    # ── 基线：原样跑一遍 ────────────────────────────────────────────────
    baseline_trace: list[dict[str, Any]] = []
    b_spf, b_dkim, b_dmarc, baseline_checks = _run_checks(
        snapshot, message, context, trace=baseline_trace)
    baseline_reconcile = reconcile_evaluate(
        message, spf=b_spf, dkim=b_dkim, dmarc=b_dmarc, query=context,
        author_domain=b_dmarc.author_domain)
    baseline_checks.append(baseline_reconcile.to_check_entry())
    baseline = assemble(
        snapshot_meta=snapshot.meta(), query=context.to_dict(),
        checks=baseline_checks, reconcile=baseline_reconcile.to_dict())

    # ── 候选：改快照副本，同一套求值器再跑一遍 ──────────────────────────
    spf_domain = context.sender_domain or (context.helo or "") or (b_dmarc.author_domain or "")
    snap_dict, applied = apply_changes(
        snapshot.to_dict(), changes=changes, author_domain=b_dmarc.author_domain,
        spf_domain=spf_domain)
    candidate_snapshot = snapshot_from_dict(snap_dict, source="whatif（变更后的快照副本）")

    candidate_trace: list[dict[str, Any]] = []
    c_spf, c_dkim, c_dmarc, candidate_checks = _run_checks(
        candidate_snapshot, message, context, trace=candidate_trace)
    candidate_reconcile = reconcile_evaluate(
        message, spf=c_spf, dkim=c_dkim, dmarc=c_dmarc, query=context,
        author_domain=c_dmarc.author_domain)
    candidate_checks.append(candidate_reconcile.to_check_entry())

    # 候选账本**本体**走 assemble（拿到与 audit 一致的结构与 ledger_id 口径）。
    candidate_core = assemble(
        snapshot_meta=candidate_snapshot.meta(), query=context.to_dict(),
        checks=candidate_checks, reconcile=candidate_reconcile.to_dict())

    # 差分描述的是**账本本体**（基线账本 → 候选账本）。`whatif` 块是**报告信封**
    # （它是对两份账本的描述），不参与差分、也不参与 `ledger_id`——否则自指。
    diff = diff_ledgers(baseline, candidate_core)
    policy = next((item.value for item in changes if item.key == "p"), "reject")
    candidate = dict(candidate_core)
    candidate["whatif"] = {
        "changes": applied,
        "diff": diff,
        "rua": rua_association(args.rua, policy_value=policy),
        "baseline": {"ledger_id": baseline["ledger_id"], "summary": baseline["summary"]},
        "note": "差分只重跑 M2–M4；报文与 query.json 是既成事实，whatif 只改配置",
    }

    _strict_guard(args, candidate_reconcile)
    markdown = _render(candidate, strict_evidence=args.strict_evidence)
    write_outputs(args, candidate, markdown)
    _stderr("施加 %d 条变更；退出码：基线 %s → 候选 %s"
            % (len(changes), baseline["summary"]["exit_code"],
               candidate["summary"]["exit_code"]))
    _stderr("差分：%d 处结构差异；RUA 关联：%s"
            % (diff["op_count"], candidate["whatif"]["rua"]["status"]))
    return int(candidate["summary"]["exit_code"])


def _cmd_diff(args: argparse.Namespace) -> int:
    """比较两份 ``verdict.json``，输出**可复算**的结构差分。"""
    from .modules.whatif import diff_ledgers
    from .render import render_diff

    baseline = _load_ledger(args.baseline, what="基线账本")
    candidate = _load_ledger(args.candidate, what="候选账本")
    diff = diff_ledgers(baseline, candidate)
    artifact = {
        "schema_version": DIFF_SCHEMA_VERSION,
        "tool_version": __version__,
        "baseline_ledger_id": baseline.get("ledger_id", ""),
        "candidate_ledger_id": candidate.get("ledger_id", ""),
        "diff": diff,
    }
    markdown = render_diff(artifact, strict_evidence=args.strict_evidence)
    write_outputs(args, artifact, markdown,
                  json_name=DIFF_JSON_FILENAME, md_name=DIFF_MD_FILENAME)
    _stderr("差分：%d 处结构差异；退出码 %s → %s"
            % (diff["op_count"], diff["summary"]["exit_code"]["from"],
               diff["summary"]["exit_code"]["to"]))
    # diff 是**比较**命令："有差异"是它正常的输出，不是失败。
    return int(ExitCode.OK)


# ── 共用：跑判定 / 渲染 / 落盘 ──────────────────────────────────────────


def _run_checks(snapshot: Any, message: Any, context: Any, *,
                trace: list[dict[str, Any]]) -> tuple[Any, Any, Any, list[dict[str, Any]]]:
    """跑 SPF → DKIM → DMARC，返回 ``(spf, dkim, dmarc, checks)``。

    ``audit`` 与 ``whatif`` 共用这一条：两边各写一份"怎么调求值器"必然会漂移——
    而 whatif 的全部意义就是"与 audit 用同一套求值器"。
    """
    from .modules.dkim import verify_message
    from .modules.dmarc import evaluate as dmarc_evaluate
    from .modules.spf import Budget, evaluate as spf_evaluate

    budget = Budget()
    spf = spf_evaluate(snapshot, context, budget=budget, trace=trace)
    dkim = verify_message(message, snapshot, trace=trace)
    # DMARC 吃前两者的**结论**：它自己不做 SPF/DKIM 求值（§5.3.4 的输入就是那两份结果）。
    dmarc = dmarc_evaluate(snapshot, message, context, spf=spf, dkim=dkim, trace=trace)

    checks = [spf.to_check_entry(subject={
        "domain": spf.domain,
        "scope": "mail_from" if context.mail_from else "helo",
        "client_ip": context.client_ip,
        "helo": context.helo,
        "message_headers": len(message.headers),
        "dkim_signatures": len(message.dkim_signatures),
    })]
    checks.extend(dkim.to_check_entries())
    checks.append(dmarc.to_check_entry())
    return spf, dkim, dmarc, checks


def _strict_guard(args: argparse.Namespace, reconcile: Any) -> None:
    """``--strict-evidence`` 下禁词自检位为 false → 非零退出（exit 3）。

    判定发生在**装配期**（对账模块自己扫自己生成的串），渲染期还有第二道闸
    （:func:`mailvault.render.render`）。两道都指向 exit 3：用户要么改输入，要么去掉
    ``--strict-evidence``——这是"输入/口径"层面的问题，不是内部错误。
    """
    if not getattr(args, "strict_evidence", False):
        return
    if reconcile is not None and not reconcile.strict_evidence_ok:
        raise InputError(
            "--strict-evidence 下账本仍含禁词（可能来自输入头里原样带来的定性词）；"
            "请改用『与重算不一致，可能解释为 A 或 B』这类措辞，或去掉 --strict-evidence")


def _render(ledger: dict[str, Any], *, strict_evidence: bool) -> str:
    """渲染并对 strict 违规给出干净的退出码（不让 ValueError 冒成未捕获异常）。"""
    from .render import render

    try:
        return render(ledger, strict_evidence=strict_evidence)
    except ValueError as exc:
        raise InputError(str(exc)) from None


def _reconcile_summary(reconcile: Any) -> str:
    counts = reconcile.classes
    return ("%d 条：一致 %d、矛盾 %d、无法判定 %d；Received %d 跳，单调=%s"
            % (len(reconcile.entries), counts["consistent"], counts["contradiction"],
               counts["undecidable"], reconcile.received_chain.get("hop_count", 0),
               reconcile.received_chain.get("monotonic")))


def _load_ledger(path: str, *, what: str) -> dict[str, Any]:
    """读一份 ``verdict.json`` 并校验 ``schema_version``（与快照同一条纪律）。"""
    import json
    from pathlib import Path

    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        raise InputError("%s文件不存在：%s" % (what, path)) from None
    except OSError as exc:
        raise InputError("%s文件不可读：%s（%s）" % (what, path, exc)) from None
    try:
        data = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InputError("%s不是 UTF-8：%s（%s）" % (what, path, exc)) from None
    except json.JSONDecodeError as exc:
        raise InputError("%s JSON 语法错误：%s 第 %d 行第 %d 列：%s"
                         % (what, path, exc.lineno, exc.colno, exc.msg)) from None
    if not isinstance(data, dict):
        raise InputError("%s顶层必须是对象，收到 %s" % (what, type(data).__name__))
    version = data.get("schema_version")
    if version != LEDGER_SCHEMA_VERSION:
        raise InputError(
            "%s的 schema_version=%r 不受支持（本工具支持：%d）"
            % (what, version, LEDGER_SCHEMA_VERSION))
    return data


# ── 输出 ────────────────────────────────────────────────────────────────


def _stderr(message: str) -> None:
    sys.stderr.write(message + "\n")


def write_outputs(args: argparse.Namespace, payload: dict[str, Any], markdown: str,
                  *, json_name: str = VERDICT_JSON_FILENAME,
                  md_name: str = VERDICT_MD_FILENAME) -> None:
    """把两轨产物落盘（`audit` / `whatif` / `diff` 共用）。

    ``json_name`` / ``md_name`` 是未指定路径时的默认文件名：`audit`/`whatif` 写
    `verdict.json`/`verdict.md`，`diff` 写 `diff.json`/`diff.md`——三条命令写在同一个
    目录里时不会互相覆盖。
    """
    out_dir = args.out_dir or "."
    json_path = args.json_out
    md_path = args.md_out

    if json_path == "-":
        from .canonical import dumps

        sys.stdout.write(dumps(payload) + "\n")
    else:
        import os

        target = json_path or os.path.join(out_dir, json_name)
        dump_file(target, payload, pretty=False)

    if md_path is not False:
        import os

        target_md = md_path or os.path.join(out_dir, md_name)
        write_text(target_md, markdown)


if __name__ == "__main__":
    sys.exit(main())
