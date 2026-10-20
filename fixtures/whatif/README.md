# fixtures/whatif —— 反事实与 RUA 关联样本

本组证"差分可复算 + 能反推基线"（题面 M5 验收）：

| 文件 | 作用 |
|---|---|
| `rua.json` | 最小 RUA 报告结构（模拟 parsedmarc 导出），用于"上 `p=reject` 会打断谁" |
| `changes.json` | 候选变更集合，与 CLI 的 `--change KEY=VALUE` 同形 |

## 纪律

- 差分**只重跑 M1–M3**，不重写求值器。
- 输出必须标注：**只覆盖报告期内且依赖报告方口径**。
- 无 RUA 数据 → `undecidable` + 所需输入清单，**不猜**。
