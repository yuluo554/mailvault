# mailvault

**离线邮件认证判定账本**：把 SPF / DKIM / DMARC 的判定放在**同一份 DNS 快照**上算一遍，再跟报文里的 `Authentication-Results` / `Received-SPF` / `Received` 链对账，逐条挂上 RFC 条款号与求值轨迹。

> `checkdmarc` 管记录健不健康，`mailauth` 管这条消息能不能过，`parsedmarc` 管历史上谁在发——没人把三者放在同一份 DNS 快照上对账，并给每条判定挂 RFC 条款与求值轨迹。本工具做的是可归档的判定账本，不是又一个 SPF 检查器，也不承诺邮件进箱。

## 它不做什么

- **不承诺进箱**，不给"进箱概率"，不做内容打分，不做发信测试。
- **不卖"离线"**：离线重放本身不是差异化（已有工具能 `--dns-cache` 重放）。差异化是条款级账本、三方对账、what-if 差分。
- 审计阶段**零网络**。只有 `snapshot fetch` 这一个子命令会联网，且是一次性显式动作。

## 状态

出题与计划阶段。实现进度见 [`plan/00-README总览.md`](plan/00-README总览.md) 的里程碑表。

## 文档

| 文件 | 内容 |
|---|---|
| [`plan/01-题目文档.md`](plan/01-题目文档.md) | 题目定稿：五模块要求与验收 |
| [`plan/00-README总览.md`](plan/00-README总览.md) | 决策记录、承诺-证据台账、里程碑 |
| [`data/README.md`](data/README.md) | 查证记录、数据许可、合成数据纪律、数值口径 |
| [`docs/ledger-format.md`](docs/ledger-format.md) | 账本字段与 `evidence_ref` 约定 |

## 快速开始（计划）

```bash
# 1) 抓一份快照（唯一联网动作）
mailvault snapshot fetch --eml message.eml --query query.json -o snap.json

# 2) 断网审计
mailvault audit --snapshot snap.json --eml message.eml --query query.json

# 3) 反事实差分
mailvault whatif --snapshot snap.json --eml message.eml --change p=reject
```

> 以上命令为首期约定形态，尚未实现。以 `plan/01-题目文档.md` §4 为准。

## 许可

待定（发布前写入）。
