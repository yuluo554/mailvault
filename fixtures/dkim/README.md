# fixtures/dkim —— DKIM 验签样本

本组证五类失败各有一条可复现样本（题面 M2 验收 1）：

| 编号 | 形态 | 期望 |
|---|---|---|
| D1 | body 被改 | `bh` 不匹配，`failure_at.body_line` 指到第一处差异行 |
| D2 | header 被改 | 签名头规范化后不匹配，`failure_at.header` 指到具体头 |
| D3 | `l=` 截断 | 只覆盖前 N 字节，正文尾部改动不影响判定（RFC 6376 §3.5） |
| D4 | key 缺失 | `key_status: missing` → `undecidable`（**不是 fail**） |
| D5 | key 过短 | RSA-512 与 RSA-1024 各一条（RFC 8301 §3.2） |

## 密钥纪律

`keys/` 下的私钥**仅 fixture 使用，不得用于生产**，每个文件头写一行说明。
生成方式与参数记在 `keys/README.md`（M3 落地）。
