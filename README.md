# mailvault

**离线邮件认证判定账本**：把 SPF / DKIM / DMARC 的判定放在**同一份 DNS 快照**上算一遍，再跟报文里的 `Authentication-Results` / `Received-SPF` / `Received` 链对账，逐条挂上 RFC 条款号与求值轨迹。

> `checkdmarc` 管记录健不健康，`mailauth` 管这条消息能不能过，`parsedmarc` 管历史上谁在发——没人把三者放在同一份 DNS 快照上对账，并给每条判定挂 RFC 条款与求值轨迹。本工具做的是可归档的判定账本，不是又一个 SPF 检查器，也不承诺邮件进箱。

## 它不做什么

- **不承诺进箱**，不给"进箱概率"，不做内容打分，不做发信测试。
- **不卖"离线"**：离线重放本身不是差异化（已有工具能 `--dns-cache` 重放）。差异化是条款级账本、三方对账、what-if 差分。
- 审计阶段**零网络**。只有 `snapshot fetch` 这一个子命令会联网，且是一次性显式动作。

## 状态

版本 `v0.1.0.dev0`（开发中）。**骨架阶段**：CLI 契约、确定性序列化、退出码、AST 守门已落地；求值器（SPF / DKIM / DMARC / 对账 / what-if）尚未实现，未实现的子命令**明确返回退出码 2**，不会假装成功。

| 里程碑 | 内容 | 状态 |
| --- | --- | --- |
| **M0** | 方法论装订 + 计划套件 + 可运行骨架（CLI 契约 / 退出码 / 确定性序列化 / AST 守门 / CI） | ✅ 2026-10-21 |
| **M1** | 数据先行：快照 schema + 抓取器 + RFC 7208 测试集 + PSL 冻结件 | ⬜ 未开始 |
| **M2** | SPF `check_host()` + 预算账本 + 完整 include 树 | ⬜ 未开始 |
| **M3** | DKIM 验签（零依赖 RSA）+ 五类失败 fixture | ⬜ 未开始 |
| **M4** | DMARC tree walk + 双算对齐 + 处置 | ⬜ 未开始 |
| **M5** | 三方对账 + what-if 差分 + RUA 关联 | ⬜ 未开始 |
| **M6** | 发布：tag + Release + 留档 | ⬜ 未开始 |

> 发布状态以 Release 页与 `plan/` 为准；随包 README 只描述版本与能力。
> 本仓库尚无远端：CI 为本地等价校验，**未跑过真实 CI**（首推待 M6）。

## 30 秒上手

```bash
# 零依赖；只需要 Python 3.11+
py -3.12 -m mailvault --version
py -3.12 -m mailvault --help

# 跑工程门（布局门 + 三条 AST 守门）
py -3.12 tools/check_sprint_layout.py
py -3.12 tools/check_no_network.py
py -3.12 tools/check_no_direct_json.py
py -3.12 tools/check_no_clock.py

# 跑测试
py -3.12 -m pytest
```

## 计划中的用法

```bash
# 1) 抓一份快照（唯一联网动作）
mailvault snapshot fetch --eml message.eml --query query.json -o snap.json

# 2) 断网审计：产出 verdict.json + verdict.md
mailvault audit --snapshot snap.json --eml message.eml --query query.json

# 3) 反事实差分（--change 可重复）
mailvault whatif --snapshot snap.json --eml message.eml --query query.json \
                 --change p=reject --change t=y

# 4) 比较两份账本
mailvault diff --baseline before.json --candidate after.json
```

> 以上命令的**参数形态已冻结**（`plan/03` §2），实现随 M1–M5 补齐。
> 无 RUA 数据时 what-if 输出 `undecidable` + 所需输入清单，不猜。

## 退出码

| 码 | 含义 |
|---|---|
| `0` | 全 pass / none |
| `1` | 存在 fail（含 softfail / permerror） |
| `2` | 存在 undecidable |
| `3` | 输入或快照错误 |
| `4` | 内部错误 |

优先级 `4 > 3 > 2 > 1 > 0`，只在 `mailvault/exits.py` 定义。

## 文档

| 文件 | 内容 |
|---|---|
| [`plan/00-README总览.md`](plan/00-README总览.md) | 决策记录、承诺-证据台账、里程碑 |
| [`plan/01-题目文档.md`](plan/01-题目文档.md) | 题目定稿：五模块要求与验收 |
| [`plan/02-架构与技术选型.md`](plan/02-架构与技术选型.md) | 分层、确定性设计、构建形态 |
| [`plan/03-模块详设.md`](plan/03-模块详设.md) | CLI 契约、K1–K12 口径、各模块详设 |
| [`plan/04-数据计划.md`](plan/04-数据计划.md) | 数据清单、真值纪律、数值口径 |
| [`plan/05-里程碑与发布.md`](plan/05-里程碑与发布.md) | DoD、门验证、发布口径 |
| [`plan/06-交付对标与决策.md`](plan/06-交付对标与决策.md) | 评分对标、缺口、风险登记 |
| [`data/README.md`](data/README.md) | 查证记录、数据许可、合成数据纪律 |
| [`docs/ledger-format.md`](docs/ledger-format.md) | 账本字段与 `evidence_ref` 约定 |
| [`AGENTS.md`](AGENTS.md) | 方法论锚点与布局门（新对话先读） |

## 许可

MIT（见 `LICENSE`）。
