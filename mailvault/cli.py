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
from .constants import VERDICT_JSON_FILENAME, VERDICT_MD_FILENAME
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

    # ── diff ──────────────────────────────────────────────────────────
    diff = subparsers.add_parser("diff", help="比较两份 verdict.json 的判定差异")
    _add_io_args(diff)
    diff.add_argument("--baseline", required=True, help="基线 verdict.json")
    diff.add_argument("--candidate", required=True, help="候选 verdict.json")

    return parser


def _add_io_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", dest="json_out", default=None,
                        help="verdict.json 输出路径；`-` 表示写 stdout")
    parser.add_argument("--md", dest="md_out", default=None, help="verdict.md 输出路径")
    parser.add_argument("--out-dir", dest="out_dir", default=None,
                        help="未指定 --json/--md 时的输出目录（默认当前目录）")


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
    from .net import fetch_snapshot

    fetch_snapshot(eml=args.eml, query=args.query, resolver=args.resolver)
    return int(ExitCode.OK)  # 不可达：fetch_snapshot 在 M0 抛 ModuleNotReady


def _cmd_audit(args: argparse.Namespace) -> int:
    raise ModuleNotReady(
        "audit 尚未实现（M1 起逐个模块落地）。当前只交付了 CLI 契约与确定性基础设施。"
    )


def _cmd_whatif(args: argparse.Namespace) -> int:
    # 先做参数面校验，让"参数写错"与"功能没做"是两种不同输出。
    if not args.change:
        raise InputError("whatif 至少需要一个 --change KEY=VALUE")
    for item in args.change:
        if "=" not in item:
            raise InputError("--change 需要 KEY=VALUE 形态，收到 %r" % (item,))
    raise ModuleNotReady("whatif 尚未实现（M5）")


def _cmd_diff(args: argparse.Namespace) -> int:
    raise ModuleNotReady("diff 尚未实现（M5）")


# ── 输出 ────────────────────────────────────────────────────────────────


def _stderr(message: str) -> None:
    sys.stderr.write(message + "\n")


def write_outputs(args: argparse.Namespace, ledger: dict[str, Any], markdown: str) -> None:
    """把两轨产物落盘（M1 起被 audit 调用；现在供测试与后续里程碑复用）。"""
    out_dir = args.out_dir or "."
    json_path = args.json_out
    md_path = args.md_out

    if json_path == "-":
        from .canonical import dumps

        sys.stdout.write(dumps(ledger) + "\n")
    else:
        import os

        target = json_path or os.path.join(out_dir, VERDICT_JSON_FILENAME)
        dump_file(target, ledger, pretty=False)

    if md_path is not False:
        import os

        target_md = md_path or os.path.join(out_dir, VERDICT_MD_FILENAME)
        write_text(target_md, markdown)


if __name__ == "__main__":
    sys.exit(main())
