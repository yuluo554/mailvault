"""mailvault —— 离线邮件认证判定账本。

定位：把 SPF / DKIM / DMARC 的判定放在**同一份 DNS 快照**上算一遍，
再与报文里的 `Authentication-Results` / `Received-SPF` / `Received` 链对账，
逐条挂上 RFC 条款号与求值轨迹。

两条显式否定（写进 README 首屏与 `--help` 尾注）：

- **不承诺进箱**：不输出"进箱概率"，不做内容打分，不做发信测试。
- **不卖"离线"**：离线重放不是差异化卖点（`mailauth --dns-cache` 已能重放）。
  卖点是条款级账本 + 三方对账 + what-if 差分。

``__version__`` 是**版本唯一真源**（`pyproject.toml` 用 `dynamic` 引用它）。
"""

__all__ = ["__version__"]

__version__ = "1.0.0"
