# 数据与查证记录

本文件记录题面的证据来源、检索口径、数据源许可与合成数据纪律。**所有数值都是"检索时间窗快照"，不是持续更新的指标，也不进代码。**

---

## 1 检索窗口（原样记录，勿改）

| 项 | 值 |
|---|---|
| 检索 UTC 窗口 | **2026-10-19T18:35Z – 2026-10-19T19:06Z** |
| 标签 | 本批标签 `10-21` 是**系列编号，不是日期**；不要据此推导检索日期 |
| 检索方式 | `gh api` search/repositories / search/issues 等 |
| 可达性限制 | **Reddit 403 不可达** → 本仓库**没有 Reddit 原话**，不得编造、不得以二手转述冒充原话 |

### 1.1 三态标记约定

- ✅ **已核实**：页面可达、原话已读、可给出 URL。
- ⬜ **软论据**：检索结果为 0 / 计数很小等旁证，只说明"没人用这套词"，**不作为需求存在性的证明**。
- ❌ **核实失败**：查过但不成立，相关说法**禁止**进入产品文案。

---

## 2 证据清单（依据查证记录·三态）

### 2.1 ✅ 已核实：竞品边界

| 项目 | 核实内容 |
|---|---|
| mailauth（postalsys/mailauth） | `authenticate()` 覆盖 SPF/DKIM/DMARC/ARC/BIMI；CLI `report --dns-cache dns.json` **已支持离线重放**（已读 `cli.md` 原文）；已支持 RFC 9989 §4.10 tree walk |
| checkdmarc | SPF 记录校验 + lookup/void 计数、DMARC（含 RFC 9989 `psd`/`np`/`t` 与 tree walk）、BIMI、MTA-STS、TLS-RPT、DNSSEC；**不做 `check_host()`**（仅 ptr_match 辅助）；**CLI 无离线输入**；不读 `.eml`；不做 DKIM 验签；输出 JSON 事实而非条款账本；issue #172：用户希望看到完整 include 总量而非在第 11 次停下 |
| pyspf | 完整 `check_host()`、10 lookup + 2 void 限制；**自带 RFC 7208 测试集（203 个 `spec:` 用例、16 分组）**；DNS 层可替换；无 CLI、无报告、无 DMARC |
| dkimpy | DKIM/ARC/TLSRPT；`verify(dnsfunc=...)` 可注入；**纯库，零 CLI** |
| parsedmarc | RUA/RUF 解析（已支持 RFC 9990/9991）、IMAP/Graph 拉取、ES 投递；**只解析报告，不评估配置** |
| OpenDMARC | milter 运行期判定，不做事后审计 |
| rspamd | MTA 插件，非审计器，评分不可离线复算 |
| Zonemaster / DNSControl | DNS 健康测试 / IaC；与本题重叠但不做报文级判定 |
| MailVerity / Edict / Herald | 0★ / 1★ / 1★：离线 DNS fixture、RFC 9989 标签、simulate 对齐模拟；离线 PyQt6 "永不联网"；Edict 明说 "follows no `include:` chain" |

元数据快照（仅记录，随时间失效，不写进代码）：checkdmarc PyPI 6.0.4（2026-10-13 发布，约 93,456 次/月，322★）；pyspf PyPI 2.0.14（约 94,765 次/月，GitHub 镜像 56★，2025-10-31）；dkimpy PyPI 1.1.8（约 1,260,501 次/月）；parsedmarc PyPI 1.307（约 56,633 次/月，1,307★）；OpenDMARC 138★（2026-08-22）；rspamd 2,554★；Zonemaster 543★；DNSControl 3,975★；mailauth 148★。

### 2.2 ✅ 已核实：需求原话

| 来源 | 原话 | 状态 |
|---|---|---|
| SO 42080552 | "I have configured DKIM, SPF and DMARC correct and from the email headers it seems to be working fine but the emails I sent from my SMTP server are marked as spam." | 0 赞 1 答，未解决 |
| SO 71781216 | "Email still dropping into SPAM after SPF etc.; why?" | **0 回答** |
| SO 51643001 | "We have noticed that a lot of our emails are falsely flagged as spam…" | — |
| SO 55708086 | "I can't get my SPF straight… I'm testing my emails with mail-tester.com and keep on running into new issues." | — |
| HN 37737612 | "the SPF Lookup Limit… could cause receiver servers to bounce your email back with an 'SPF PermError'. … The tricky part of that to diagnose" | — |
| HN 45479279 | "Score of 100 on mail-tester, SPF, DKIM, DMARC… Everything green. Microsoft however? Denied, 100% of the time… Why? No idea" | — |
| HN 43474725 | "they have some weird middleware that rewrites things… dkim signatures don't validate" | — |
| HN 39897718 | "you break SPF if you don't touch the envelope from. There's SRS to fix that. But if you do that, you break DMARC alignment. So… something is always broken?" | — |
| HN 33523237 | "they were in my spam folder, because I forward my email from a custom domain to my gmail account, and that means SPF checks always fail." | — |
| HN 34904522 | "with SPF, DKIM, and DMARC (or something), this has broken and such received mail gets marked as spam and/or phishing." | — |
| GitHub pimlie/authres_status #86（open） | "`trusted_mtas` fails open when `authserv-id` is unparseable (forged Authentication-Results shown as valid)" | — |

URL 见 `plan/01-题目文档.md` §2.2。

### 2.3 ⬜ 软论据：开源空白检索

检索式与计数见 `plan/01-题目文档.md` §2.3。要点：`spf dmarc audit report in:description` 共 **16** 个仓库，最高 **1★**；`dmarc policy simulation in:description` 仅 **1**（MailVerity 0★）；11 个检索式为 **0 结果**。这些**只作旁证**。

### 2.4 ❌ 核实失败：禁止进文案

- **BIMI 没有对应的 IETF RFC 编号**：9698–9703 逐个查过，9701 是 JWT Token Introspection，其余不匹配。
  → 文案只能写"BIMI Group 规范 / IETF draft"，**不得写 RFC 编号**。
- **Reddit 不可达（403）** → 无 Reddit 原话。

---

## 3 数据源可获取性与许可

| 数据源 | 用途 | 获取方式 | 许可与再分发 |
|---|---|---|---|
| pyspf `test/rfc7208-tests.yml` | M1 验收基准（203 用例 / 16 分组） | 随仓库引入 | BSD 式许可，**必须保留原版权声明与许可文本**（`fixtures/spf/rfc7208-tests.LICENSE`）；只取测试数据，取其 DNS 桩结构不取实现 |
| Public Suffix List（PSL） | Organizational Domain 计算 | **随包冻结** | MPL 2.0；冻结件需标注版本、日期、来源 URL 与校验和；运行时只读，禁止联网更新 |
| RFC 7208 / 6376 / 8301 / 8601 / 5321 / 5322 / 9989 / 8617 原文 | 条款引用 | 公开 | IETF Trust 文档条款，题面只做短引用与 § 号指向 |
| dkimpy | 仅作交叉验证参照 | PyPI | BSD-like，已核实 |
| checkdmarc | 仅作对照（不嵌入代码） | PyPI | Apache-2.0，已核实 |
| 自建 `.eml` 与 snapshot | fixture | 本地合成 | 本仓库所有 |

**不引入**：任何需联网运行的服务、任何带遥测的 SDK、任何需要 API key 的数据源。

---

## 4 合成数据纪律

1. **域名**：只使用保留域 `example.invalid` / `example.com` / `example.net` / `example.org`，或 RFC 2606 保留名；**禁止**出现可解析的真实域名。
2. **IP**：只使用文档保留段 `192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`。
3. **报文**：`.eml` 全部本地合成，header 中的 `Received` / `Message-ID` / `Authentication-Results` 一律自造；**不得**引用任何真实邮件或真实用户报文。
4. **密钥**：DKIM fixture 的私钥为测试专用生成，注明"仅 fixture 使用，不得用于生产"。
5. **快照**：`snap.json` 中的 DNS 答复全部为人工构造，`fetched_at` 用合成时间；`resolver` 字段标 `synthetic`。
6. **匿名化**：任何从公开渠道摘录的片段只保留 RFC 条款层面内容，不摘录第三方报文。

---

## 5 数值口径纪律（一处定义）

以下数值/枚举**只允许在 `mailvault/` 的常量模块中定义一次**，其它位置（文档、fixture 说明、测试断言）只能引用其名称，不得复制数值：

| 口径 | 定义位置（首期） | 约定 |
|---|---|---|
| SPF term 上限 | 常量模块 | 10（RFC 7208 §4.6.4），第 11 个 → permerror |
| MX / PTR 单机制上限 | 常量模块 | 各 10（RFC 7208 §4.6.4） |
| void lookup 上限 | 常量模块 | SHOULD 2（RFC 7208 §4.6.4）→ 超限标 `undecidable` 语义，不硬判 fail |
| 退出码 | 常量模块 | `0` pass/none、`1` fail、`2` undecidable、`3` 输入/快照错误、`4` 内部错误 |
| 快照 `schema_version` | 常量模块 | 单一整数字面量；schema 变更必须升版本并写迁移说明 |
| 账本字段名与 `evidence_ref` 格式 | `docs/ledger-format.md` + 常量模块 | 字段名不得在模块间各写一套 |
| RSA 最小位数 | 常量模块 | 1024（RFC 8301 §3.2，低于即无效） |
| PSL 版本 | 冻结件元数据 | 输出必须带版本与日期 |

**禁止**把星数、下载量、issue 数、检索总数为任何形式的常量或默认输出写入代码。

---

## 6 复现检索的说明

上方所有计数均可用 `gh api -X GET search/repositories -f q='...'` 在**任意时间**重跑；重跑结果会不同，属正常。本文件记录的是 2026-10-19T18:35Z–19:06Z 窗口的快照，用于说明"当时是什么状态"，**不作为长期指标引用**。
