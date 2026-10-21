# mailvault

**离线邮件认证判定账本**：把 SPF / DKIM / DMARC 的判定放在**同一份 DNS 快照**上算一遍，再跟报文里的 `Authentication-Results` / `Received-SPF` / `Received` 链对账，逐条挂上 RFC 条款号与求值轨迹。

> `checkdmarc` 管记录健不健康，`mailauth` 管这条消息能不能过，`parsedmarc` 管历史上谁在发——没人把三者放在同一份 DNS 快照上对账，并给每条判定挂 RFC 条款与求值轨迹。本工具做的是可归档的判定账本，不是又一个 SPF 检查器，也不承诺邮件进箱。

## 它不做什么

- **不承诺进箱**，不给"进箱概率"，不做内容打分，不做发信测试。
- **不卖"离线"**：离线重放本身不是差异化（已有工具能 `--dns-cache` 重放）。差异化是条款级账本、三方对账、what-if 差分。
- 审计阶段**零网络**。只有 `snapshot fetch` 这一个子命令会联网，且是一次性显式动作。

## 状态

版本 `v1.0.0`。**M6 发布**：`mailvault audit` 在同一份快照上跑
**SPF（RFC 7208 §4–§7）、DKIM 验签（RFC 6376 + RFC 8301）、DMARC（RFC 9989 §4.10）
与三方对账（RFC 8601）**，产出两轨账本；`whatif` / `diff` 也已接上真实现。

- **SPF**：RFC 7208 测试集 **202/203 = 99.5%**（门槛 95%），唯一一条差异是 void 超限判
  `undecidable`（原文是 SHOULD）——逐条登记在 `data/rfc7208-failures.md`，由三条断言盯着。
  预算账本逐格可读（term / MX / PTR / void / depth），include 树**完整展开**并标出切点。
- **DKIM**：多签名**逐条独立求值、不短路**；每条给 `selector/d/i/a/c`、`bh_matches`、
  `key_bits`、`key_status`（`ok`/`revoked`/`missing`/`weak`/`invalid`）与失败定位。
  **零依赖 RSA**（`crypto/der.py` + `crypto/rsa.py`，只用标准库 `hashlib`/`pow`）。
  规范化对表 RFC 6376 §3.4.5 的三个示例与 §3.4.3/§3.4.4 的空正文基准哈希。
  **无快照密钥 → `undecidable`（不是 `fail`）**；RSA < 1024 位 → `fail`（RFC 8301 §3.2 MUST）。
- **DMARC**：`_dmarc` **DNS Tree Walk**（RFC 9989 §4.10 步骤 1–7，含 ≥8 标签时的跳步），
  Author → Organizational → PSD 的发现顺序；`psd=n` / `psd=y` 按 §4.10.2 改变
  Organizational Domain。`spf_align` 与 `dkim_align` 各出 **relaxed / strict 两个值，不合并**。
  `disposition` 按 `p=` / `sp=` / `np=` + 存在性推导，`t=y` 降一级。
  **`pct=` / `rf=` / `ri=` 出现即告警"已被 RFC 9989 删除"，不静默忽略**。
  输出带 `psl_version` / `psl_date`（来自快照）与 PSL 对照值。
- **三方对账**：把报文里的 `Authentication-Results` 与本工具的重算结论对起来，三分类
  **一致 / 矛盾 / 无法判定**。每条**矛盾**给 **≥2 条可能解释 + 各自要查什么**
  （例：内容网关在验签之后重写了正文 vs 报文在归档途中被改）。
  `authserv-id` 不在 `trusted_authserv_ids` 里、**或不可解析** → fail-closed 判
  `undecidable`（空的可信列表**不等于**全部可信）。`Received` 链给跳数、单调性与
  时钟回退——时间**只取报文头里的字面值**，从不与系统时钟比较。
  **`--strict-evidence`** 下账本不得出现"攻击/伪造"等定性词（对账在装配期自检）。
- **what-if 反事实**：`--change p=reject` 这样改一条配置，**只重跑**同一套求值器，
  再与基线账本做**结构差分**；差分**双向可逆**（把差分反转施加到候选，逐字节得到基线）。
  `--rua` 可挂一份 RUA 聚合报告，回答"上 `p=reject` 会打断谁"——输出标注
  **只覆盖报告期内、且依赖报告方口径**；没有 RUA 数据时判 `undecidable` 并列出所需输入。
- 同一输入两次运行 `verdict.json` 字节级一致；断网下 `audit` 返回真实退出码；
  退出码由 `exits.exit_code_for` **一处**计算（多模块共用优先级，不各自算）。

| 里程碑 | 内容 | 状态 |
| --- | --- | --- |
| **M0** | 方法论装订 + 计划套件 + 可运行骨架（CLI 契约 / 退出码 / 确定性序列化 / AST 守门 / CI） | ✅ 2026-10-21 |
| **M1** | 数据先行：快照 schema + 抓取器 + RFC 7208 测试集 + PSL 冻结件 | ✅ 2026-10-21 |
| **M2** | SPF `check_host()` + 预算账本 + 完整 include 树 | ✅ 2026-10-21 |
| **M3** | DKIM 验签（零依赖 RSA）+ 五类失败 fixture | ✅ 2026-10-21 |
| **M4** | DMARC tree walk + 双算对齐 + 处置 | ✅ 2026-10-21 |
| **M5** | 三方对账 + what-if 差分 + RUA 关联 | ✅ 2026-10-21 |
| **M6** | 发布：tag + Release + 留档 | ✅ 2026-10-21 |

> 发布状态以 [Release 页](https://github.com/yuluo554/mailvault/releases/tag/v1.0.0) 与 `plan/` 为准；
> 随包 README 只描述版本与能力。CI 实测：3.11 / 3.13 × ubuntu / windows 四矩阵 + 无网络容器 job
> 共 5/5 全绿（`plan/RELEASE-M6.md` §2）。

## 30 秒上手

```bash
# 零依赖；只需要 Python 3.11+
py -3.12 -m mailvault --version
py -3.12 -m mailvault --help

# 跑工程门（布局门 + 三条 AST 守门 + fixture 卫生 + 断网冒烟 + 发布门）
py -3.12 tools/check_sprint_layout.py
py -3.12 tools/check_no_network.py
py -3.12 tools/check_no_direct_json.py
py -3.12 tools/check_no_clock.py
py -3.12 tools/check_fixture_hygiene.py
py -3.12 tools/offline_smoke.py
py -3.12 tools/check_release.py --offline    # 发布门（不碰网络的那一档）

# 跑守门的变异验证（每条守门都必须能跑红，否则它是假门）
py -3.12 tools/verify_layout_gate.py        # 11/11
py -3.12 tools/verify_ast_gates.py          # 8/8
py -3.12 tools/verify_module_mutations.py   # 11/11（判定逻辑）

# 跑测试（开发期需 pytest + pyyaml + cryptography；运行时零第三方依赖）
py -3.12 -m pip install -e ".[dev]"
py -3.12 -m pytest
```

## 用法

```bash
# 1) 抓一份快照（唯一联网动作；不给 --resolver 时用固定公共解析器，保证可复算）
mailvault snapshot fetch --eml message.eml --query query.json -o snap.json

# 2) 断网审计：产出 verdict.json + verdict.md（SPF + DKIM + DMARC + 三方对账）
mailvault audit --snapshot snap.json --eml message.eml --query query.json
mailvault audit ... --strict-evidence          # 禁用"攻击/伪造"等定性词

# 3) 反事实差分（--change 可重复；include: 用冒号形态）
mailvault whatif --snapshot snap.json --eml message.eml --query query.json \
                 --change p=reject --change t=y
mailvault whatif ... --change include:_spf.example.net --rua rua.json

# 4) 比较两份账本（写 diff.json + diff.md，不覆盖 verdict.*）
mailvault diff --baseline before.json --candidate after.json
```

> 以上命令的**参数形态已冻结**（`plan/03` §2），四条子命令全部可用。
> `--change` 的合法键：`p=` / `sp=` / `np=` / `t=` / `all=` / `include:<domain>`；
> 未知键或非法值 → 退出码 3（不做静默忽略）。
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
| [`data/rfc7208-failures.md`](data/rfc7208-failures.md) | RFC 7208 实跑结果 + 失败/口径差异逐条登记（M2） |
| [`docs/ledger-format.md`](docs/ledger-format.md) | 账本字段与 `evidence_ref` 约定 |
| [`examples/`](examples/README.md) | 已归档的样例产物：`audit` / `whatif` / `diff` 各一例（真 CLI 跑真 fixture 生成，带 `--strict-evidence`） |
| [`AGENTS.md`](AGENTS.md) | 方法论锚点与布局门（新对话先读） |

## 许可

MIT（见 `LICENSE`）。
