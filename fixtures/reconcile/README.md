# fixtures/reconcile —— 三方对账样本

本组证三分类与"双解释"（题面 M4 验收）：

| 编号 | 形态 | 期望 |
|---|---|---|
| R1 | 转发器导致 SPF fail 但 DKIM 过 | `contradiction`，解释含"转发改写信封发件人" |
| R2 | 网关重写正文导致 `bh` 不匹配 | `contradiction`，`failure_at` 指到正文 |
| R3 | 注入伪造 `Authentication-Results` | `undecidable`（authserv-id 不可信时 fail-closed） |

## 硬约束

- 每条 `contradiction` 必须有 **≥ 2 条解释**，每条带**具体的验证方法**（查什么、怎么看）。
- `--strict-evidence` 下全文不得出现"攻击/伪造/被黑"等定性词。
- 报文、IP、域名全部合成（保留域 / 文档 IP 段）。
