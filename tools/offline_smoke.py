#!/usr/bin/env python3
"""断网冒烟：证明 `audit` 路径**从不打开 socket**。

做法不是"关掉网络"，而是在进程内把 `socket.socket` / `socket.create_connection`
替换成抛异常的桩 —— 任何联网尝试都会当场炸掉。这比 `PATH=""` 这类隔离手段可靠：
它不依赖机器上装了什么，也不需要容器级隔离。

骨架期的期望是 `audit` 返回 2（`ModuleNotReady` 走 undecidable 语义）。
M1 起改为断言返回值 ∈ {0, 1, 2} 且全程零 socket 尝试。

用法：python tools/offline_smoke.py
退出码：0 通过 / 1 失败。
"""

from __future__ import annotations

import socket
import sys
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
    try:
        from mailvault.cli import main as cli_main

        code = cli_main([
            "audit",
            "--snapshot", "missing.json",
            "--eml", "missing.eml",
            "--query", "missing.json",
            "--out-dir", ".",
        ])
    finally:
        socket.socket = original_socket  # type: ignore[assignment]
        socket.create_connection = original_create  # type: ignore[assignment]

    print("断网冒烟：audit 路径零 socket")
    print("=" * 50)
    print("返回值: %r" % code)
    print("socket 尝试次数: %d" % len(attempts))
    if attempts:
        print("FAIL  审计路径尝试联网: %s" % attempts)
        return 1
    if code != 2:
        print("FAIL  骨架期期望 2（fail-closed undecidable），实得 %r" % code)
        return 1
    print("PASS  fail-closed 且零联网")
    return 0


if __name__ == "__main__":
    sys.exit(main())
