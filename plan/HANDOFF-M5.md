# HANDOFF-M5（M4 收尾 → M5 开工）

> 用法（用户侧启动命令）：`/goal 读取 "<项目绝对路径>\plan\HANDOFF-M5.md" 继续完成任务`
> **第一动作 = 跑布局门**：`py -3.12 tools/check_sprint_layout.py`（必须全绿，红了先修布局）。
> 本文件内一律相对路径。

---

## 一、当前进度 + 证据

**已完成：M0（装订 + 骨架）+ M1（数据先行）+ M2（SPF）+ M3（DKIM）+ M4（DMARC）**，均 2026-10-21。

| 交付 | 证据（实测命令 + 结果） |
|---|---|
| 布局门 | `py -3.12 tools/check_sprint_layout.py` → **全绿**（8 PASS / 0 FAIL / 1 SKIP=RELEASE） |
| 布局门变异 | `py -3.12 tools/verify_layout_gate.py` → **11/11 全部如期变红** |
| AST 守门 | `check_no_network` 19 文件全绿；`check_no_direct_json` 19 文件全绿；`check_no_clock` 20 文件全绿 |
| AST 变异 | `py -3.12 tools/verify_ast_gates.py` → **6/6 全部如期变红** |
| fixture 卫生 | `py -3.12 tools/check_fixture_hygiene.py` → PASS 75 份 + EXEMPT 2 份（理由打印） |
| 禁词门 | `py -3.12 tools/check_forbidden_terms.py` → SKIP 0 份（M6 才转真判定） |
| 断网冒烟 | `py -3.12 tools/offline_smoke.py` → **缺输入→3、完整输入→0、socket 尝试 0** |
| 测试 | `PYTHONUTF8=1 py -3.12 -m pytest` → **348 passed**（M3 时 296；DMARC 新增 52） |
| **DMARC fixtures** | 6 例全绿：B.4.1 / B.4.2 / B.4.3 / `psd-n` / `np` / `pct`（4 pass + 2 fail / 2 种处置） |
| **RFC 原文逐跳复现** | B.4.1（2 跳）、B.4.2（**8 标签跳步 → 8 次查询**）、B.4.3（`psd=y` 停在第二跳） |
| **§4.10.2 三个例子** | 标签最少者 / `psd=n` 就地停 / `psd=y` 取**下面一层** —— 各一条测试，逐字对应原文 |
| **§4.4 Table 1 三行** | relaxed / strict 与独立手算实现逐条比对（同源实现不算对账） |
| fixture 生成器幂等 | `py -3.12 tools/gen_dmarc_fixtures.py --check` → **逐字节一致**（6×4 份） |
| CLI 端到端 | `audit` 的 `checks[]` 三条：`spf.check_host` + `dkim.verify_signature` + `dmarc.evaluate` |
| 双跑一致 | 同一输入两次 `audit` 的 `verdict.json` / `verdict.md` sha256 相同 |
| 退出码 | `np` / `pct` 两例 → exit **1**（fail）；`b41`/`b42`/`b43`/`psd-n` → exit **0**（pass） |

**M4 交付面**（新增/改动的代码）：

| 模块 | 内容 |
|---|---|
| `mailvault/modules/dmarc.py` | **新增 ~1100 行**：§4.10 步骤 1–7 的走查（含 8 标签跳步）、§4.10.2 三段 Org 域选择、§4.10.1 策略发现与选择、双算对齐、`t=` 降级、旧标签告警 |
| `mailvault/constants.py` | 新增 `DMARC_*` 一组常量（记录标签 / 版本 / 8 标签上限 / 保留 7 / 默认对齐 / `psd` 值 / 已删除标签 / `t` 降级表 / 走查状态 / DNS 错误码） |
| `mailvault/cli.py` | `_cmd_audit` 接 DMARC：`checks[]` 追加 `dmarc.evaluate`；stderr 多一行摘要 |
| `tests/test_dmarc.py` | **52 条**：RFC 原文向量 / fixture 全量 / 独立手算对账 / 反自证 / 层约束 |
| `tools/gen_dmarc_fixtures.py` | 生成 6 例 × 4 份产物；`--check` 逐字节幂等；DKIM 侧用**真签名**（复用 `gen_dkim_fixtures` 的签名器） |
| `tools/offline_smoke.py` | 补齐 DMARC 的两跳（`_dmarc.example.com` 有记录 + `_dmarc.com` NXDOMAIN），否则"完整输入→0"失去意义 |
| `fixtures/dmarc/` | 6 个用例目录 × 4 份产物 + 改写后的 `README.md` |
| `docs/ledger-format.md` | 新增 §3.2（DMARC 条目的 `subject` 与字段口径） |
| `plan/03` §3.4 | 按实装重写；新增 K16/K17/K18 |
| `plan/04` §3.3 | M4 的域映射、真值三层、为什么不引参照实现 |
| `plan/05` M4 DoD | 勾选 + **M4 口径更正三条** |
| `plan/06` | G1/G3 更新；新增 G13/G14/G15 |
| `plan/00` | 里程碑表 + **承诺-证据台账**新增 M4 行 |

**M4 实装期间的按-RFC-更正（重要）**：空反向路径（`MAIL FROM:<>`）**不是**"没有 SPF 身份"——§3.2.4 指向 RFC 7208 §2.4，身份是 `postmaster@<HELO>`，所以 SPF 域取 HELO 域。初版按"无身份"实装过一轮（会把本该 relaxed 对齐判 pass 的报文判 fail），已更正并加测试。

**未做**：远端仓库、CI 实跑、M5–M6。

---

## 二、当前事实·状态不变量（**动手前必须知道**）

1. **`mailvault/__init__.py::__version__` 是版本唯一真源**。`pyproject.toml` 用 `dynamic`。定版只改这一处。
2. **`mailvault/constants.py` 是全部数值口径的唯一出处**。M4 新增 `DMARC_*` 一组。
3. **`canonical.py` 是全仓唯一 JSON 出口**（K2）。M4 没有新增序列化路径。
4. **网络 import 只在 `net.py`**（K3）。`mailvault/modules/dmarc.py` 在此约束下（19 源文件全绿）。
5. **时钟豁免精确到函数**（K7）：`net.py::utc_now_z` 是**唯一**允许读时钟的位置。
   DMARC 的判定路径**零时钟**（`t=`/`psd=` 都不需要"现在几点"）。
6. **状态副本 = 4 处**（`plan/00` 里程碑表 + `plan/05` 状态表 + `README.md` 状态行 +
   `plan/00` 承诺-证据台账）。翻状态**四处一起改**。`plan/06` 缺口表是第五处（只描述、不点名文件）。
7. **`plan/05` 与 `plan/06` 的表格首列不要用 `| M<n> |` 形态**做非状态用途——布局门会误判。
8. **未实现的能力必须 fail-closed 到 2**。`whatif` / `diff` 仍是 `ModuleNotReady` → 2；
   **`audit` 现在是 SPF + DKIM + DMARC 三条真判定**。
9. **`requires-python = ">=3.11"`，本机无 3.11**（只有 3.8.8 / 3.12.10）。一律 `py -3.12`。
10. **本仓库无远端**。DoD 里不许写"CI 绿"。
11. **运行时零第三方依赖**。`pyyaml` / `cryptography` 都只在 `dev` extra。
    `dmarc.py` 里的 `test_dmarc_module_imports_only_allowed_layers` 与
    `test_runtime_does_not_import_reference_implementation` 是 DMARC 侧的守门。
12. **"没查过" ≠ "没有"**（K13）：DMARC 的 `not_queried` 跳 → `undecidable` + `data_gaps`；
    快照答复 NXDOMAIN → `nxdomain`（走查继续）。**M5 的对账也要照同一口径**。
13. **Organizational Domain 只由 tree walk 得出**（K16）。PSL 值存 `psl_organizational_domain`，
    **仅作对照**。RFC 9989 §4.10 已用走查替换 RFC 7489 的 PSL 做法。
14. **`np=` 的存在性歧义不猜**（K17）：`disposition = null` + `disposition_status = "undecidable"`。
    唯一例外：`np=` 与 `sp=/p=` 折算出的**处置相同**（结论一样），此时判 `determined` 并出告警。
15. **旧标签 `pct`/`rf`/`ri` 出现即告警、语义不被采纳**（K18）。`pct=0` **不会**让策略变 `none`。
16. **`disposition_status` 三值**：`determined` / `not_applicable` / `undecidable`。
    **`undecidable` 时 `disposition` 必为 `null`**。
17. **`adkim=` 只管 DKIM 侧、`aspf=` 只管 SPF 侧**，两者不交叉。
18. **SPF 身份只认 MAIL FROM**（§4.4.2），但**空反向路径时身份就是 HELO 域**：
    §3.2.4 指向 RFC 7208 §2.4，原文 "the 'MAIL FROM' identity [is] the mailbox composed
    of the local-part 'postmaster' and the 'HELO' identity"。所以 `MAIL FROM:<>` +
    `HELO: mail.example.com` → SPF 域是 `mail.example.com`，仍参与对齐。
    只有 HELO 也为空时才没有 SPF 身份。**M4 实装时先按"无身份"写，后来按 RFC 原文更正**
    （`test_dmarc.py::test_null_reverse_path_uses_helo_as_spf_domain` 守着）。
19. **`check_entry` 的字段集对所有条目一致**：DMARC 条目 `tree` 恒为 `null`（键仍存在）。
20. **`dmarc.py` 不算退出码**。它只给 `result`；退出码走 `exits.exit_code_for`。
21. **`.eml` 的正文归一**：`body_crlf` 按 `\r?\n` 切行。DMARC 不读正文，只读 `From`。
22. **fixture 域映射**：RFC 9989 的示例用裸保留 TLD，卫生门只认 `example.com` 等四类后缀，
    所以示例整体落到 `.example.com` 下。**不放宽卫生门**（见 `fixtures/dmarc/README.md`）。

---

## 三、下一棒待办（M5：三方对账 + what-if 差分 + RUA 关联）

按 `plan/05` §2 的 M5 DoD、`plan/01` 的 M4/M5 段、`plan/03` §3.5/§3.6：

1. **`mailvault/modules/reconcile.py`**：三分类 `consistent` / `contradiction` / `undecidable`
   （`constants.RECONCILE_CLASSES`）。输入是报文里的 `Authentication-Results` 头 +
   本工具重算的 SPF/DKIM/DMARC 结论。
   - `contradiction` 的 `explanations` **必须 ≥ 2**，每条带 `hypothesis` + `verify`（具体要查什么）。
   - `authserv_id` 不在 `trusted_authserv_ids` 里、**或不可解析** → `undecidable`（fail-closed，
     参照 authres_status #86 的教训）。`trusted_authserv_ids` 为空时**不得**当成"全部可信"。
   - `--strict-evidence` 下全文禁词（K10）；`strict_evidence_ok` 自检位为 false 时非零退出。
2. **`Received` 链**（`reconcile.received_chain`）：`monotonic` / `clock_regressions` / `hop_count`。
   **时间只取报文头的字面值**，不与系统时钟比较（K7）。
3. **`mailvault/modules/whatif.py`**：`--change KEY=VALUE` 可重复，只重跑 M1–M3 + DMARC 做差分。
   - 未知 `--change` 键或不可解析的值 → `InputError`（exit 3），**不做静默忽略**（`plan/03` §2 第 3 条）。
   - 差分**可复算**：能从差分结果反推出基线（测试要断言这一点）。
4. **`--rua` 关联**（`fixtures/whatif/rua.json`）：无 RUA 数据 → `undecidable` + 所需输入清单。
   **标注报告期口径**（RUA 是聚合报告，时间窗口与本次审计的时刻不是一回事，K7 的推论）。
5. **三个对账 fixture**（`plan/05` M5 DoD）：转发导致 SPF fail / DKIM 过、网关改正文、
   注入伪造 AR（`authserv_id` 不可信）。
6. **`cli._cmd_whatif` / `_cmd_diff` 接上真实现**；`checks[]` 或 `reconcile` 节相应填充。
   退出码仍走 `exit_code_for`。
7. **测试**：`tests/test_dmarc.py` 是模板（RFC 原文向量 / fixture 全量 / 参照对账 / 反自证四层）。
   对账的"参照"是**人工构造的矛盾点写进 `why`**（`plan/04` §2.2），不是引第三方库。

---

## 四、既定口径清单（K 编号，动了会打挂测试）

| # | 口径 | 守在哪 |
|---|---|---|
| K1 | 退出码只在 `exits.py`；优先级 `4>3>2>1>0` | `tests/test_contract.py` |
| K2 | `json.dumps` 只在 `canonical.py` | `tools/check_no_direct_json.py` |
| K3 | 网络 import 只在 `net.py` | `tools/check_no_network.py` |
| K4 | 结果枚举只在 `constants.RESULTS`；`undecidable` 不折叠成 `fail` | `test_contract` / `test_ledger` / `test_spf` / `test_dkim` / `test_dmarc` |
| K5 | `evidence_ref` 缺失 → 构造期降级 `undecidable` | `ledger.check_entry` + `test_ledger` |
| K6 | `schema_version` 单点定义；未知版本 → exit 3 | `constants` + `tests/test_inputs.py` |
| K7 | 零系统时钟；**唯一豁免 `net.py::utc_now_z`**（函数级） | `tools/check_no_clock.py` + `test_determinism` |
| K8 | 比率 = 6 位定点字符串；账本内无裸浮点 | `canonical.fixed6` + `dumps` 拒浮点 |
| K9 | 账本内无绝对路径 | `render._assert_no_absolute_path` |
| K10 | `--strict-evidence` 禁词表 | `render.STRICT_FORBIDDEN` + `check_forbidden_terms` |
| K11 | fixture 只用保留域 / 文档 IP 段；上游原样件逐条登记豁免 | `tools/check_fixture_hygiene.py` |
| K12 | 判定节点 id 稳定（`n0`, `n0.1`），**只由路径决定** | `test_spf.py::test_tree_root_and_child_ids_are_stable` |
| K13 | **`found=False`（快照没查过）不得当成"没有记录"**；判 `undecidable` 并带 `data_gap` | `test_spf.py` + `test_dkim.py` + `test_dmarc.py`（三模块各一例） |
| K14 | **单向哈希类失败不编造定位**；给 `kind` + `basis` | `test_dkim.py::test_failure_at_for_*_does_not_invent_*` |
| K15 | **fixture 卫生门只扫 JSON 的字符串值、不扫键** | `test_dkim.py::test_fixture_hygiene_catches_domain_in_json_value` |
| **K16** | **DMARC 的 Organizational Domain 只由 §4.10.2 的 tree walk 得出**；PSL 值另存为 `psl_organizational_domain`，仅作对照 | `test_dmarc.py::test_psl_organizational_domain_is_reference_only` |
| **K17** | **`np=` 的存在性歧义不猜**：`disposition=null` + `disposition_status="undecidable"` | `test_dmarc.py::test_np_with_unknown_existence_is_undecidable_not_guessed` |
| **K18** | **旧标签 `pct`/`rf`/`ri` 出现即告警，且语义不被采纳** | `test_dmarc.py::test_removed_tags_are_warned_not_silently_ignored` |

---

## 五、本机环境坑（全部实测）

| 坑 | 实测 | 处置 |
|---|---|---|
| `python` 是商店占位符 | — | 一律 `py -3.12` |
| 无 Python 3.11 | `py -0p` → 3.8.8-64 / 3.12.10-64 | 3.11 行为以 CI 为准 |
| Git Bash `/tmp` 与 Python 路径认知不一致 | `py -3.12` 看不到 `/tmp/x` | **用 `cygpath -w "$TEMP"` 转成 Windows 路径**（M2/M3/M4 各踩一次） |
| `/tmp` 下有同名 `.py` 会**遮蔽标准库** | 在 `/tmp/probe.py` 里 `import inspect` 拿到了别人的 `inspect` → `AttributeError: module 'inspect' has no attribute 'get_annotations'` | **临时脚本写进仓库内目录**（如 `.probe/`），跑完删；不要放 `/tmp` |
| Git Bash heredoc 里写中文/`%` 会乱码 | `py -3.12 - <<'EOF'` 直接跑含中文的脚本会炸；**中文引号 `"` 在 Python 字符串里会 SyntaxError** | **把脚本写到文件再跑**（用 `'...'` 单引号包中文），或 `PYTHONUTF8=1` |
| Windows 控制台打印中文乱码 | 布局门输出的 PASS 行显示成乱码 | 只是显示问题；判据按 UTF-8 读文件。看"结论:"那行 |
| `cryptography` 拒绝生成 <1024 位密钥 | `rsa.generate_private_key(512)` → `ValueError` | 用纯 Python 素数搜索（`gen_dkim_fixtures.py::_gen_small_rsa`） |
| `cryptography` 的 `sign(data, pad, hash_alg)` **会自己再哈希一遍** | 传摘要进去 → 签名对应 `SHA256(SHA256(x))`，每条都验不过 | 必须用 `utils.Prehashed(hash_alg)` |
| dkimpy 拒绝 `t=` 在未来 | `ValidationError: t= value is in the future` | fixture 用过去的时间戳（2026-01-01） |
| dkimpy 的模块级 `verify()` 遇首个坏签名就抛异常 | 多签名时拿不到逐条结果 | 对账用 `DKIM(raw).verify(idx=i)` 逐条调 |
| dkimpy 的 `signature_fields` 是 dict 不是 list | 数签名条数用它 → 恒为 0 | 用 `len([1 for n,v in d.headers if n.lower()==b"dkim-signature"])` |
| 布局门变异靶子随进度失效 | M06/M07 曾写死 M1/M2 | 变异脚本**探测当前待办里程碑**；靶子找不到就断言失败 |
| fixture 卫生门会扫 `fixtures/*/README.md` | 引用上游真实 IP/域名会自己变红 | 文档里描述上游件时**不要写字面域名/IP**，用文字转述 |
| **卫生门也扫 `expected.json` 的 `why`**（值是字符串） | M4 在 `b43` 的 `why` 里写了 RFC 原文的示例域 → 红 | 描述原文域时**不要写字面值**（写"原文的示例域"），或整体映射到保留域 |
| `argparse` 缺参 `SystemExit(2)` | 与 `undecidable` 撞语义 | 入口已转 3；`test_contract` 锁定 |
| `ModuleNotReady` 继承 `InputError` | 措辞会打印成"输入错误" | `cli.main` 单独捕获，打印"尚未实现" |
| pyflakes 会抓 `%` 字符串里的 `%{` | `"%{p} ..." % x` 报 unsupported format char | 该转义就写 `%%{p}` |
| 测试文件 docstring 里的 `\*` | 触发 `SyntaxWarning: invalid escape sequence` | 用 `raw` 字符串或改措辞 |
| **`dict`/`list` 进 `subject`** | 渲染层按 `k=v` 平铺，嵌套值变成不可读的 repr | DMARC 的 `subject` 只放**标量**；逐跳明细进 `trace`（`test_check_entry_shape_matches_ledger_contract` 断言） |
| **`s.replace()` 批量改测试文件** | M4 用正则批量替换 `dkim=None` 时把文件改乱了（12 处替换成不存在的变量） | 批量改**先小范围验证**；改完立刻跑测试；测试文件宁可整份重写 |

---

## 六、DoD 逐项 checklist（本棒，全部已实测）

- [x] RFC 9989 B.4.1–B.4.3 三个 tree-walk 示例**逐跳**复现
- [x] **B.4.2 的 8 标签跳步实测**：13 标签 Author 第 2 跳直接落到 7 标签处，全程 8 次查询
      （漏跳步的实现会红——变异 M1 验证过）
- [x] §4.10.2 三个 Organizational Domain 例子逐条复现（标签最少 / `psd=n` / `psd=y`）
- [x] §4.4 Table 1 三行 + B.4.1 两个域对与**独立手算实现**比对
- [x] `pct=` 出现即告警（`rf`/`ri` 同样），且 `pct=0` **不**让策略变 `none`
- [x] `psd=y`（`b43`）与 `psd=n`（`psd-n`）各有独立 fixture，且两者给出**不同** Org 域
- [x] `np=` 与 `sp=` 取值**不同**的独立 fixture（选错立刻可见）
- [x] 输出带 `psl_version` + `psl_date`（来自快照）+ `psl_organizational_domain`（对照）
- [x] 双算对齐：`relaxed` / `strict` 各一个布尔值，不合并；`adkim=` 与 `aspf=` 各管一侧
- [x] `disposition` 按 `p=` / `sp=` / `np=` + 存在性推导；`t=y` 降一级并留痕
- [x] `np=` 歧义 → `undecidable` + `disposition=null`（**不猜**）；同值时不误判
- [x] 数据缺口 → `undecidable` + `data_gaps`（**不**落 `none`）；NXDOMAIN 走查继续
- [x] 多条记录 → 全部丢弃（§4.10 步骤 2），不取第一条
- [x] DNS 错误（SERVFAIL/TIMEOUT）→ `undecidable`（§5.3.6），**不**落 `none`
- [x] `v=` 必须第一个且值大小写敏感（四条逐条断言）
- [x] fixture 生成器 `--check` 逐字节幂等（6 × 4 份）
- [x] `audit` 接上 DMARC；`checks[]` 三条；退出码走 `exit_code_for`
- [x] `pytest` 348 passed（DMARC 52 条）；九条门全绿；变异 11/11 + 6/6
- [x] **8 组 DMARC 变异全部如期变红**：跳步 / `psd=y` 取自身 / 数据缺口当没有 /
      `np=` 永远优先 / `pct` 静默 / strict 并入 relaxed / 空反向路径当无身份 /
      走查 trace id 撞号
- [x] 双跑 `verdict.json` + `verdict.md` 字节级一致
- [x] 4 处状态副本 + `plan/06` 缺口表同步；`plan/04` §3.3 记 M4 数据口径

**DoD 未达成项（如实登记）**：

- CI 实跑：**未接远端，未跑过**。首推后需回填 run id。
- Python 3.11 行为：**本机验不了**，以 CI 矩阵为准。
- `np=` 在缺 Author 域存在性证据时给不出处置：**有意为之**（G13）。补抓一条查询即可判定。
- `rua=`/`ruf=` 只做形态校验，不解析 scheme：**有意为之**（G14，§4.7 是实现自由）。
- IDN 的 U-label→A-label 只用标准库 `idna` codec：**不完全**支持 IDNA2008（G15）。
- 与 checkdmarc / mailauth 的 DMARC 对账：**未做**。这两家的 PSL/`psd` 口径与本项目不同，
  拿它们当真值会把它们的口径当标准（`plan/04` §3.3 有理由）。

---

## 七、关键命令速查

```bash
# 0) 第一动作：布局门
py -3.12 tools/check_sprint_layout.py

# 1) 门的变异验证（改门/改文档后必跑）
py -3.12 tools/verify_layout_gate.py     # 11/11 必须红
py -3.12 tools/verify_ast_gates.py       # 6/6 必须红

# 2) 各守门
py -3.12 tools/check_no_network.py
py -3.12 tools/check_no_direct_json.py
py -3.12 tools/check_no_clock.py
py -3.12 tools/check_fixture_hygiene.py
py -3.12 tools/check_forbidden_terms.py
py -3.12 tools/offline_smoke.py

# 3) 测试与 CLI
py -3.12 -m pip install -e ".[dev]"      # 开发期需要 pytest + pyyaml + cryptography
PYTHONUTF8=1 py -3.12 -m pytest
PYTHONUTF8=1 py -3.12 -m pytest tests/test_dmarc.py -q      # 只跑 DMARC（52 条）
py -3.12 -m mailvault --version

# 4) DMARC fixture 幂等复核（改生成器后必跑）
py -3.12 tools/gen_dmarc_fixtures.py --check

# 5) 端到端 audit（断网可跑；Git Bash 里必须用 cygpath 转 Windows 路径）
OUT="$(cygpath -w "$TEMP")\\mv5"; mkdir -p "$(cygpath -u "$OUT")"
py -3.12 -m mailvault audit \
    --snapshot fixtures/dmarc/b43/snap.json \
    --eml fixtures/dmarc/b43/message.eml \
    --query fixtures/dmarc/b43/query.json --out-dir "$OUT"; echo "exit=$?"
#   期望 exit 0（pass）。b43 的快照只含 DMARC + Author 域查询，SPF 会判 none/undecidable。

# 6) 逐跳看 tree walk（最直观的一步）
py -3.12 -m mailvault audit \
    --snapshot fixtures/dmarc/b42/snap.json \
    --eml fixtures/dmarc/b42/message.eml \
    --query fixtures/dmarc/b42/query.json --md "$OUT/b42.md" >/dev/null 2>&1
grep -E "walk\." "$(cygpath -u "$OUT")/b42.md"
#   期望 8 条 walk.<起点域名>.<序号>，第 2 条是 _dmarc.g.h.i.j.k.example.com
#   （跳步的现场证据）。id 带起点域名：一次评估会有多次走查，不 namespace 会撞 id（K12）

# 7) 只读检查：本棒交付面
git status --short
git ls-files
```
