#!/usr/bin/env python3
"""断网冒烟：证明 `audit` 路径**从不打开 socket**。

做法不是"关掉网络"，而是在进程内把 `socket.socket` / `socket.create_connection`
替换成抛异常的桩 —— 任何联网尝试都会当场炸掉。这比 `PATH=""` 这类隔离手段可靠：
它不依赖机器上装了什么，也不需要容器级隔离。

**M2 起断言收紧为固定退出码**（M0/M1 期是 `∈ {0,1,2,3}`）：

1. 三件套缺失 → 必须是 **3**（输入错误）。这证明 `audit` 真的走到了"读文件"那一步，
   而不是在更早的地方就 fail-closed 成"没实现"（2）。M1 时两者都可能是 3，
   因为 `ModuleNotReady` 已被 `cli.main` 单独捕获；现在必须精确到 3。
2. **一份完整可判定的输入** → 必须是 **0**（`pass`）。这一条是关键：它证明
   `audit` 在断网环境下**真的算出了判定**，而不是"没崩就算过"。
   只断言"不联网"是弱证据——一个什么都不做的实现也能满足它。
3. 全程零 socket 尝试。这条永不放宽。

用法：python tools/offline_smoke.py
退出码：0 通过 / 1 失败。
"""

from __future__ import annotations

import socket
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    attempts: list[str] = []

    def blocked(*args, **kwargs):
        attempts.append(repr(args[:1]))
        raise AssertionError("审计路径不得打开 socket")

    original_socket = socket.socket
    original_create = socket.create_connection
    socket.socket = blocked  # type: ignore[assignment]
    socket.create_connection = blocked  # type: ignore[assignment]
    missing_code = None
    judged_code = None
    judged_note = ""
    runtime_ok = True
    runtime_note = ""
    try:
        from mailvault.cli import main as cli_main

        # ① 三件套缺失 → 3（证明 audit 真的在读输入，不是"没实现"）
        missing_code = cli_main([
            "audit",
            "--snapshot", "missing.json",
            "--eml", "missing.eml",
            "--query", "missing.json",
            "--out-dir", ".",
        ])

        # ② 完整输入 → 真实判定（断网下必须能算出 pass）
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            _write_fixtures(workdir)
            judged_code = cli_main([
                "audit",
                "--snapshot", str(workdir / "snap.json"),
                "--eml", str(workdir / "message.eml"),
                "--query", str(workdir / "query.json"),
                "--json", str(workdir / "verdict.json"),
                "--md", str(workdir / "verdict.md"),
            ])
            judged_note = "verdict.json 已落盘" if (workdir / "verdict.json").is_file() else "未落盘"

        # ③ M1 数据面自足性：PSL 冻结件读取 + 组织域计算 + 快照解析全程零 socket。
        try:
            from mailvault.psl import default_psl
            from mailvault.snapshot import from_dict

            psl = default_psl()
            org = psl.organizational_domain("www.example.co.uk")
            assert org == "example.co.uk", org
            assert psl.version and psl.date
            snap = from_dict({
                "schema_version": 1, "fetched_at": "2026-10-19T18:35:00Z",
                "resolver": "synthetic", "psl_version": psl.version, "psl_date": psl.date,
                "queries": [{"qname": "example.com", "qtype": "TXT", "rcode": "NOERROR",
                             "answer": ["v=spf1 -all"], "ttl": 300}],
            })
            resolved = snap.resolve("example.com", "TXT")
            assert resolved.answer == ("v=spf1 -all",)
            runtime_note = "PSL 冻结件 + 组织域 + 快照解析：零 socket"
        except Exception as exc:  # noqa: BLE001 - 冒烟脚本要把失败原因原样报出来
            runtime_ok = False
            runtime_note = "数据面失败：%r" % (exc,)
    finally:
        socket.socket = original_socket  # type: ignore[assignment]
        socket.create_connection = original_create  # type: ignore[assignment]

    print("断网冒烟：audit 路径 + M1 数据面零 socket")
    print("=" * 50)
    print("缺输入时的返回值: %r（期望 3 = 输入错误）" % missing_code)
    print("完整输入时的返回值: %r（期望 0 = pass）%s" % (judged_code, judged_note))
    print("socket 尝试次数: %d" % len(attempts))
    print("数据面: %s" % runtime_note)

    if attempts:
        print("FAIL  审计路径尝试联网: %s" % attempts)
        return 1
    if not runtime_ok:
        print("FAIL  M1 数据面在断网下不可用（PSL/快照解析必须自足）")
        return 1
    if missing_code != 3:
        print("FAIL  缺输入时期望 3（输入错误），实得 %r" % (missing_code,))
        return 1
    if judged_code != 0:
        print("FAIL  完整输入时期望 0（pass），实得 %r——audit 在断网下没算出判定"
              % (judged_code,))
        return 1
    print("PASS  零联网 + 缺输入→3 + 完整输入→0（真实判定）")
    return 0


def _write_fixtures(workdir: Path) -> None:
    """写一份最小但**完整可判定**的输入三件套（保留域 + 文档 IP 段，K11）。

    M4 起"完整"的含义变了：DMARC 需要 `_dmarc` 的 TXT 查询，否则 tree walk 第一跳就是
    数据缺口 → `undecidable` → 退出码 2（那是 K13 的**正确**行为，不是故障，但它让
    "完整输入 → 0"这条断言失去意义）。所以这里把 DMARC 的两跳都补上：
    `_dmarc.example.com` 有记录、`_dmarc.com` 明确答复 NXDOMAIN。
    """
    from mailvault import canonical

    canonical.dump_file(workdir / "snap.json", {
        "schema_version": 1,
        "fetched_at": "2026-10-19T18:35:00Z",
        "resolver": "synthetic",
        "psl_version": "2026-10-20_08-40-56_UTC",
        "psl_date": "2026-10-20",
        "queries": [
            {
                "qname": "example.com", "qtype": "TXT", "rcode": "NOERROR",
                "answer": ["v=spf1 ip4:192.0.2.0/24 -all"], "ttl": 300,
            },
            {
                "qname": "_dmarc.example.com", "qtype": "TXT", "rcode": "NOERROR",
                "answer": ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"], "ttl": 300,
            },
            {
                # tree walk 第二跳（§4.10 步骤 7）：必须"问过且没有"，否则又是数据缺口。
                "qname": "_dmarc.com", "qtype": "TXT", "rcode": "NXDOMAIN",
                "answer": [], "ttl": 300,
            },
        ],
    })
    canonical.dump_file(workdir / "query.json", {
        "mail_from": "sender@example.com",
        "client_ip": "192.0.2.10",
        "helo": "mail.example.com",
    })
    (workdir / "message.eml").write_bytes(
        b"From: sender@example.com\r\nSubject: smoke\r\n\r\nbody\r\n")


if __name__ == "__main__":
    sys.exit(main())
