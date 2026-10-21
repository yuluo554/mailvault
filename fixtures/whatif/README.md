# fixtures/whatif —— 反事实与 RUA 关联样本

本组证"差分可复算 + 能反推基线 + 报告期口径"（题面 §3 的 M5 验收）。
**由 `tools/gen_whatif_fixtures.py` 生成**（`--check` 逐字节幂等）。

| 文件 / 目录 | 作用 |
|---|---|
| `rua.json` | 最小 RUA 聚合报告（模拟 parsedmarc 导出形态），用于"上 `p=reject` 会打断谁" |
| `changes.json` | 默认候选变更集合，与 CLI 的 `--change KEY=VALUE` **同形**（字符串列表） |
| `spf-tighten/` | 基线 SPF 是 `?all`（neutral）→ 收紧为 `-all`（fail）后**退出码 0 翻成 1** |
| `p-reject/` | 基线 `p=none` 且 SPF 不过 → 改 `p=reject` 后**处置从 none 变 reject**，并挂 `rua.json` |

两个用例的输入各是 `snap.json` / `message.eml` / `query.json` / `expected.json`
（`expected.json` 的 `input` 里另有 `changes` 与 `rua`，把"跑哪条命令"也钉在 fixture 里）。

## 纪律

- 差分**只重跑 M2–M4**，不重写求值器（题面 M5 明文要求）。
- 差分**可复算**：`ops` 施加到基线得到候选，`ops` 反转施加到候选得到基线。
  两个方向都由 `tests/test_whatif.py` 用**两份独立的 CLI 产物**断言。
- 输出必须标注：**只覆盖报告期内且依赖报告方口径**（`period_note`）。
- 无 RUA 数据 → `undecidable` + 所需输入清单（`required_inputs`），**不猜**。
  注意：`--rua` 缺省**不影响退出码**——退出码仍由 `checks[]` 决定，否则
  "不带 `--rua` 就永远非零"会把这条可选功能变成噪声。
- `rua.json` 里三条记录覆盖三种形态，且**只有一条** SPF 与 DKIM 都没通过：
  写成"任一不过就算会被 p=reject 打断"会把数量从 1 变 2，测试立刻变红。
