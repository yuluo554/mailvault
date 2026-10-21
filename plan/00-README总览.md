# 10-21-mailvault 项目总览

> 本项目遵循 `ai-tool-project-sprint` 方法论；布局门 `tools/check_sprint_layout.py`；装订日期 2026-10-21。

离线邮件认证判定账本。纯本地 Python CLI。审计阶段零网络。

**定位宣言**

> `checkdmarc` 管记录健不健康，`mailauth` 管这条消息能不能过，`parsedmarc` 管历史上谁在发——**没人把三者放在同一份 DNS 快照上对账，并给每条判定挂 RFC 条款与求值轨迹**。本工具做的是可归档的判定账本，不是又一个 SPF 检查器，也不承诺邮件进箱。

不承诺进箱 / 不卖"离线"（离线重放已有 `mailauth --dns-cache`）。

---

## 文档索引

| 文件 | 作用 |
|---|---|
| `plan/01-题目文档.md` | 题目定稿：十段式题面、五模块要求与验收、评分、含金量锚点、边界与非目标 |
| `plan/00-README总览.md` | 本文件：索引、决策记录、承诺-证据台账、里程碑 |
| `data/README.md` | 查证记录（三态 + 时间窗）、数据源可获取性与许可、合成数据纪律、数值口径纪律 |
| `README.md` | 项目门面（30 秒能跑通） |
| `docs/ledger-format.md` | 账本字段与 `evidence_ref` 约定 |
| `docs/backlog.md` | 范围外需求登记 |

---

## 决策记录

### 风险三条（必须先读）

**风险 ① "离线重放"不是空白**
`mailauth` 的 CLI `report --dns-cache dns.json` **已经能离线重放**（已读其 `cli.md` 原文确认）。因此卖点**禁止**写"能离线跑"。
→ 差异化只放在：**条款级账本（每条判定挂 § 号 + 求值轨迹）+ 三方对账（M4）+ what-if 差分（M5）**。

**风险 ② 新标准护城河很窄**
`checkdmarc` 6.0.4（2026-10-13）已跟进 RFC 9989 §4.10 tree walk 与 `psd`/`np`/`t` 标签。也就是说"支持 DMARCbis"本身只能领先几个月。
→ 不把"支持新标准"当唯一卖点；把可复算账本与对账做成主结构，新标准只是必答题。

**风险 ③ 诚实边界就是产品，但也最容易被误读**
M4 会输出形如"报文头里写 `spf=pass`，我用同一份快照算出 `fail`"。用户极易读成"我的邮件被黑了"。
→ 强制：**每条矛盾必须给两种可能解释 + 各自的验证方法**；`--strict-evidence` 模式下禁用"攻击/伪造"字样；authserv-id 不可解析时 fail-closed 判 `无法判定`（对应 authres_status #86 的教训）。

### 弃选项（及理由）

| 弃项 | 理由 |
|---|---|
| TLS/证书链本地验证 | 需求信号近零；zlint 447★ / certigo 1036★ / `openssl verify` 已饱和；且易滑向"远程扫描"，与隐私红线冲突 |
| DNS 记录一致性审计（单独立项） | Zonemaster 543★ / DNSControl 3975★ 已重叠 → 降为**输入层与告警源**，不单独做产品 |
| 邮件头完整性（单独立项） | Herald / MailHeaderAnalyzer / dkim-verify 129★ / mailauth 已成阵型 → 只保留 **AR 矛盾**一条，作为 M4 的一部分 |
| 垃圾箱打分 / 进箱预测 | 需真实发信，分数不可复算；mail-tester 类不可归档 → 明确列为"不做" |
| SPF flatten | 31 仓已有、头部 43★，赛道满；且 flatten 会引入维护负债 |
| SRS 实现 | 破坏 DMARC 对齐、属运行期行为 → 只做影响模拟 |
| ARC 当主卖点 | Experimental（RFC 8617），且拟转 Historic；只作辅助证据 |
| DMARC 看板可视化 | dmarc-visualizer 781★ 已占 |

### 口径决策

1. **不写漂移硬数字**：星数/下载量只出现在 `data/README.md` 的"检索窗口快照"里，**不进代码、不进 CLI 输出、不进 README 卖点句**。
2. **数值口径一处定义**：SPF 预算计数、void 上限、退出码、快照 `schema_version`、账本字段名，全部只在一处定义（首期 `mailvault/` 内的常量模块 + `docs/ledger-format.md`），其它地方引用不复制。
3. **灰区一律 `undecidable`**：五条灰区见 `plan/01-题目文档.md` §2.5，不得降级为 `fail`。
4. **PSL 随包冻结**：输出必须带 PSL 版本与日期，禁止运行时联网取最新 PSL。

---

## 承诺-证据台账

| 承诺 | 证据 | 状态 |
|---|---|---|
| 三工具各管一段，无人做同快照对账 | 各项目源码/文档已读；检索计数见 `data/README.md` | ✅ |
| 真实需求存在且未被解决 | 11 条原话（SO/HN/GitHub issue），其中 1 条 0 回答 | ✅ |
| RFC 条款可逐条引用 | 条款已核对原文（7208/6376/8301/8601/5321/5322/9989/8617） | ✅ |
| 空白可用检索证明 | 主检索式最高 1★（16 仓） | ⬜ 软论据 |
| 不进箱那部分不可判定 | HN 45479279 满分仍被拒 | ✅ |
| 本工具不承诺进箱 | 定位宣言 + 评分红线 | ✅ 设计承诺 |
| BIMI 有 RFC 编号 | 未找到（9698–9703 逐个查过，9701 是 JWT Token Introspection） | ❌ 核实失败 → 文案只写"BIMI Group 规范 / IETF draft" |
| SPF 求值器与 RFC 7208 测试集逐条对得上 | `tests/test_spf.py` 跑 202/203 = 99.5%；1 条口径差异逐条登记在 `data/rfc7208-failures.md`；参照实现 pyspf 2.0.14 同份测试集 203/203（仅开发期核对，运行时零依赖） | ✅ M2 2026-10-21 |
| 判定结果可复算且不读时钟 | 两次 `audit` 的 `verdict.json` sha256 相同；`check_no_clock` 15 文件全绿；`%{t}` 宏因此不展开（已登记 G7） | ✅ M2 2026-10-21 |
| DKIM 验签与 RFC 原文逐条对得上 | 规范化对表 RFC 6376 §3.4.5 三个示例 + §3.4.3/§3.4.4 空正文基准哈希（原文给定字节）；`fixtures/dkim/` 11 例含正样本与多签名；零依赖 RSA 与 `cryptography` 逐例一致；dkimpy 1.1.8 对账 9 例一致 + 2 例按 RFC 的有意差异（`plan/04` §3.2） | ✅ M3 2026-10-21 |
| DMARC tree walk 与 RFC 原文逐条对得上 | RFC 9989 B.4.1–B.4.3 三个 tree-walk 示例**逐跳**复现（含 13 标签 Author 的跳步：第 2 跳直接落到 7 标签处，全程 8 次查询）+ §4.10.2 三个 Organizational Domain 选择例子 + §4.4 Table 1 三行；`fixtures/dmarc/` 6 例（B.4.1 / B.4.2 / B.4.3 + `psd=n` + `np` + `pct`）含 4 个 pass 与 2 个 fail；relaxed/strict **双算不合并**；`pct`/`rf`/`ri` 出现即告警『已被 RFC 9989 删除』且不被采纳；`gen_dmarc_fixtures.py --check` 逐字节幂等；走查 trace id 带起点域名（一次评估多次走查不撞号，K12）；8 组变异全部如期变红 | ✅ M4 2026-10-21 |
| 三方对账能给出三分类且矛盾有双解释 | RFC 8601 §2.2 的语法向量逐条钉死；`fixtures/reconcile/` 3 例（转发 SPF fail/DKIM 过 → 2 条**一致**、网关改正文 → 1 条**矛盾**含 ≥2 解释且每条带 verify、不可信 authserv-id → 2 条**无法判定**）；不可信/不可解析 authserv-id 与空可信列表一律 fail-closed；Received 链单调性与时钟回退**只比字面值**（解析不出判 `null`）；矛盾汇总**不折成 fail**；禁词自检位能被证伪；分类真值表由**手算实现**独立比对 | ✅ M5 2026-10-21 |
| what-if 差分可复算且能反推基线 | `fixtures/whatif/` 2 例（`?all`→`-all` 让退出码 0→1；`p=none`→`p=reject` 让处置 none→reject）+ RUA 报告 + 变更集合；`apply_ops(候选, invert(ops))` 与**另一次独立 `audit` 产物**逐字节相等（含 `ledger_id`）；差分双跑一致；RUA 缺数据判 `undecidable` + 所需输入清单且**不影响退出码**；两个生成器 `--check` 幂等 | ✅ M5 2026-10-21 |
| 语义类口径有能跑红的守门 | `tools/verify_module_mutations.py` **11/11 全部如期变红**（B01–B09 对账/what-if，B10/B11 DMARC 跳步与数据缺口）；每组要求"指定的那条测试"变红且植入后文件**仍能编译**（排除语法错导致的假红） | ✅ M5 2026-10-21 |
| 裸 clone 直跑（发布前置） | 临时 bare 仓库 round-trip：克隆出来的仓库 `pytest` 441 passed + 七条门全绿 + 四个生成器 `--check` 逐字节一致。修了 `.eml` fixture 缺 `-text` 的归一化缺陷（不带规则时克隆后 25 处 CRLF 归一成 0 处、生成器全报不一致）；另加断言盯住 | ✅ 2026-10-21（本地 bare 仓库 round-trip；GitHub 真下载复核见 V6） |

---

## 里程碑

| 里程碑 | 内容 | 完成判据（DoD） | 状态 |
|---|---|---|---|
| **M0** | 方法论装订 + 计划套件 00–06 + 可运行骨架 | `AGENTS.md` + 布局门 + `plan/00` 装订行；CLI 四条子命令注册；AST 守门（零网络/零时钟/单一序列化）；`pytest` 全绿 | ✅ 2026-10-21 |
| **M1 数据先行** | `snap.json` schema 定稿、抓取器（唯一联网点）、RFC 7208 测试集接入（pyspf `test/rfc7208-tests.yml`，保留 BSD 式版权声明）、PSL 冻结件 | schema 版本化；测试集可被本地 runner 读取；断网下测试集能跑（用内置 DNS 桩） | ✅ 2026-10-21 |
| **M2 SPF** | `check_host()` 确定性求值 + 预算账本 + 完整 include 树 | 203 用例 ≥95% 通过（实得 202/203 = 99.5%）；失败逐条登记；两次运行字节级一致 | ✅ 2026-10-21 |
| **M3 DKIM** | 验签 + 五类失败 fixture + `undecidable` 语义 | RFC 6376 §3.4/§3.5、RFC 8301 §3.2 落地；无 key 不判 fail | ✅ 2026-10-21 |
| **M4 DMARC** | tree walk + 双算对齐 + 处置 + PSL 版本 + 旧标签告警 | RFC 9989 B.4.1–B.4.3 复现；`pct` 告警 | ✅ 2026-10-21 |
| **M5 对账与 what-if** | 三方对账（双解释 + strict 模式）+ 差分 + RUA 关联 | 3 个对账 fixture 通过；差分可复算；标注报告期口径 | ✅ 2026-10-21 |
| **M6 发布** | `git tag v1.0.0` + GitHub Release 附产物 + 发布留档三件套 | 见 `plan/05` §4 | ⬜ 未开始 |

**M6 DoD 三件套**：① `git tag` 与 GitHub Release（附 `verdict.json`/`verdict.md` 示例、fixture 清单、PSL 版本）；② 发布留档（README 首屏可跑通 + `data/README.md` 数据纪律 + `docs/ledger-format.md`）；③ 仓库公开发布，署名 `yuluo554`。

---

## 目录

```
plan/     题目与总览（含 RELEASE-M6 发布留档）
data/     查证记录与数据纪律
fixtures/ 五组 fixture（输入 + 期望值）
examples/ 已归档的样例产物（verdict / diff；禁词门与 Release 附件的扫描面）
mailvault/ 包源码
docs/     账本格式、backlog
tools/    守门与生成器（含 check_release.py 发布门）
```
