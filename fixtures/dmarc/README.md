# fixtures/dmarc —— DMARC tree walk 与对齐样本

本组证三件事（题面 M3 验收）：

| 编号 | 形态 | 期望 |
|---|---|---|
| B.4.1 | RFC 9989 Appendix B.4.1 的 tree-walk 示例 | 逐跳输出与附录一致 |
| B.4.2 | 同上，`psd` 归属不同 | 同上 |
| B.4.3 | 同上，`np` 参与 | 同上 |
| `pct` | 旧标签 | 出现即告警"已被 RFC 9989 删除"，**不得静默忽略** |
| `psd`/`np` | 新旧标签混用 | 归属判定独立 fixture |

## 纪律

组织域（Organizational Domain）的计算依赖 PSL 冻结件；每个样本都要能指出用的是哪个
`psl_version`（写在 `snap.json` 里）。跨 PSL 版本的结果差异**不是 bug**，但要能在
输出里看到版本号。
