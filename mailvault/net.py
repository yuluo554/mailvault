"""HTTP(S) / DNS 访问的**唯一出口**。

为什么单独一个模块：题面 §7 的隐私红线是"审计阶段零网络"。光靠"我记得别联网"不算保证，
必须有一条能跑红的门。做法是把所有 socket 相关 import 收进本文件，
再用 `tools/check_no_network.py` 扫其余全部模块（AST 级）。

**本文件是 M1 的内容**：M0 只留下接口，`fetch_snapshot()` 抛 `ModuleNotReady`。
"""

from __future__ import annotations

from .exits import ModuleNotReady

# 提示：本文件之外的模块禁止出现以下 import（由 tools/check_no_network.py 断言）：
#   import socket / ssl / http.client / urllib.request / ftplib / telnetlib
#   from socket import ... 等
#
# M1 会在这里实现 DNS 查询（UDP/TCP 53）与可选的 DoH 通道。


def fetch_snapshot(*, eml: str, query: str, resolver: str | None = None) -> dict:
    """抓取一份 DNS 快照（M1 实现）。

    当前是骨架：**明确失败**而不是返回空快照——空快照会让下游把"没数据"读成"没有记录"，
    那是把"没做"伪装成"没找到"。
    """
    raise ModuleNotReady(
        "snapshot fetch 尚未实现（M1）；骨架期请直接手写或复用 fixtures 里的 snap.json"
    )
