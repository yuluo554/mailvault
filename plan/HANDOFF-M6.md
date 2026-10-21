# HANDOFF-M6（M6 收尾 —— **本项目最后一个里程碑，已全部完成**）

> 用法（用户侧启动命令）：`/goal 读取 "<项目绝对路径>\plan\HANDOFF-M6.md" 继续完成任务`
> **第一动作 = 跑布局门**：`py -3.12 tools/check_sprint_layout.py`（必须全绿，红了先修布局）。
> 本文件内一律相对路径。
>
> **状态**：M0–M6 全部 ✅（2026-10-21）。本文件同时是**收尾交接单**：读它是为了
> 复核/续做，不是为了"接着往下做"——已无待办里程碑。

---

## 一、当前进度 + 证据

**已完成：M0（装订 + 骨架）+ M1（数据先行）+ M2（SPF）+ M3（DKIM）+ M4（DMARC）+
M5（三方对账 + what-if 差分 + RUA 关联）+ M6（发布）**，均 2026-10-21。
**发布已落地**：https://github.com/yuluo554/mailvault/releases/tag/v1.0.0

| 交付 | 证据（实测命令 + 结果） |
|---|---|
| 布局门 | `py -3.12 tools/check_sprint_layout.py` → **全绿**（8 PASS / 0 FAIL / 1 SKIP=RELEASE） |
| 布局门变异 | `py -3.12 tools/verify_layout_gate.py` → **11/11 全部如期变红** |
| AST 守门 | `check_no_network` 21 文件全绿；`check_no_direct_json` 21 文件全绿；`check_no_clock` 22 文件全绿 |
| AST 变异 | `py -3.12 tools/verify_ast_gates.py` → **6/6 全部如期变红** |
| **语义变异（M5 新增）** | `py -3.12 tools/verify_module_mutations.py` → **11/11 全部如期变红**（B01–B09 对账/what-if，B10/B11 DMARC 跳步与数据缺口；每组都断言"植入后仍能编译"+"指定的那条测试"变红） |
| fixture 卫生 | `py -3.12 tools/check_fixture_hygiene.py` → PASS **97 份** + EXEMPT 2 份（理由打印） |
| 禁词门 | `py -3.12 tools/check_forbidden_terms.py` → SKIP 0 份（M6 才转真判定） |
| 断网冒烟 | `py -3.12 tools/offline_smoke.py` → **缺输入→3、完整输入→0、socket 尝试 0** |
| 测试 | `PYTHONUTF8=1 py -3.12 -m pytest` → **441 passed**（M4 时 348；M5 净增 93：`test_reconcile.py` 39 + `test_whatif.py` 50 + `test_contract.py` 新增 3 + `.eml` 字节口径断言 1） |
| **对账 fixtures** | 3 例全绿：`r1-forwarded`（2×consistent）/ `r2-gateway-body`（1×contradiction，3 条解释）/ `r3-untrusted-ar`（2×undecidable） |
| **三分类都有样本** | `test_fixture_shapes_are_the_three_required_scenarios`：`consistent` / `contradiction` / `undecidable` 各 ≥1 |
| **分类真值表** | 9 组 (claimed, recomputed, trusted) 与**手算实现** `_hand_class()` 逐条一致 |
| **矛盾双解释** | 每条 ≥2（`RECONCILE_MIN_EXPLANATIONS`），每条带非空 `hypothesis` + `verify`；<2 条时模块内 `InternalError` |
| **AR 语法向量** | RFC 8601 §2.2 四条逐条钉死：版本号 token / `method` 无 `=` 默认 `none` / `(reason)` 里的 `;` / 明显坏头给 `parse_note` |
| **fail-closed** | 不可信 authserv-id、不可解析头、空可信列表 → 全 `undecidable`；且"重算结果恰好一致"也不构成证据 |
| **矛盾不折 fail** | `reconcile.cross_check` 汇总：一致→pass、矛盾/判不了→undecidable、无 AR→none |
| **Received 链** | 单调性 + 时钟回退 + 跳数；解析不出的时间戳 → `monotonic=null`（不猜）；只比字面值（零系统时钟） |
| **what-if 差分可复算** | `apply_ops(candidate, invert(ops)) == 另一次独立 audit 产物`（**逐字节**，含 `ledger_id`）；`apply_ops(baseline, ops) == candidate_core` |
| **退出码随配置变** | `fixtures/whatif/spf-tighten`：`?all`→`-all` → 退出码 **0 → 1**（实测） |
| **RUA 关联** | `p-reject` 例：`status=complete`、`affected_total=1`（只有 `198.51.100.9` 既不过 SPF 也不过 DKIM）；`period_note` 写明报告期口径；缺 `--rua` → `undecidable` + `required_inputs`（**不影响退出码**） |
| 差分双跑一致 | 同一输入两次 `whatif` 的 `verdict.json` 字节相同 |
| 生成器幂等 | `gen_reconcile_fixtures.py --check` / `gen_whatif_fixtures.py --check` → 逐字节一致（4×3 + 10 份） |
| **裸 clone 直跑（本地验证）** | 临时 bare 仓库 round-trip：克隆出来的仓库 `pytest` **441 passed** + 七条门全绿 + **四个**生成器 `--check` 逐字节一致。途中修掉一个**只在克隆后显形**的缺陷：`.eml` fixture 缺 `.gitattributes` 的 `-text`（不带规则时 `git add` 把 25 处 CRLF 归一成 0 处 → 裸 clone 后生成器全报 `message.eml 字节不一致`、DKIM 全变 `body_hash`）。**这是 M6 第 2 步的前置条件**（但仍**不替代** M6 的"真下载 + 解包"复核，见 V6） |
| CLI 端到端 | `audit` 的 `checks[]` 四条：`spf.check_host` + `dkim.verify_signature` + `dmarc.evaluate` + `reconcile.cross_check` |
| `diff` 子命令 | 写 `diff.json`/`diff.md`（**不覆盖** `verdict.*`）；退出码恒 0；ops 双向可逆（用两份 CLI 产物实测） |

**M5 交付面**（新增/改动的代码）：

| 模块 | 内容 |
|---|---|
| `mailvault/modules/reconcile.py` | **新增 ~600 行**：AR 解析（RFC 8601 §2.2）、三分类、双解释生成器、Received 链、`strict_evidence_ok` 自检位、`reconcile.cross_check` 汇总条目 |
| `mailvault/modules/whatif.py` | **新增 ~570 行**：`parse_changes` / `apply_changes`（改快照副本）/ `rua_association` / `diff_ledgers` / `apply_ops` / `invert_ops` |
| `mailvault/constants.py` | 新增 `RECONCILE_*` / `STRICT_FORBIDDEN`（从 `render.py` **提上来**）/ `WHATIF_*` / `DIFF_SCHEMA_VERSION` / `DIFF_*_FILENAME` |
| `mailvault/render.py` | `STRICT_FORBIDDEN` 改为引用常量；新增 Received 链渲染、`whatif` 块渲染（第 5 节）、`render_diff()` |
| `mailvault/cli.py` | `_run_checks()`（`audit`/`whatif` **共用**）；`_cmd_audit` 接对账；`_cmd_whatif` / `_cmd_diff` 接真实现；`whatif`/`diff` 也支持 `--strict-evidence`；`write_outputs()` 参数化默认文件名 |
| `tests/test_reconcile.py` | **39 条**：RFC 8601 语法矢量 / fixture 点路径全量消费 / 手算真值表 / Received 链 / 反自证 / 分层 AST / 卫生门阴性对照 |
| `tests/test_whatif.py` | **50 条**：变更校验与施加 / 差分双向可逆 / fixture 全量 / RUA 口径 / `diff` 子命令 / 反自证 / 分层 AST |
| `tools/gen_reconcile_fixtures.py` | 生成 3 例 × 4 份产物；`--check` 逐字节幂等 |
| `tools/gen_whatif_fixtures.py` | 生成 2 例 × 4 份 + `rua.json` + `changes.json`；`--check` 幂等 |
| `tools/verify_module_mutations.py` | **新增**：11 组语义变异（三连断言：变了 / 仍能编译 / 指定的测试红） |
| `tools/check_fixture_hygiene.py` | 新增 `AR_PTYPE` 结构性前缀剥离（+ 阴性对照） |
| `fixtures/reconcile/` `fixtures/whatif/` | 3 + 2 用例 + RUA 报告 + 变更集合 + 改写后的 `README.md` |
| `docs/ledger-format.md` | §5 按实装重写；新增 §5.1 `whatif` / §5.2 `rua` / §5.3 diff 产物；§6/§7 更新 |
| `plan/03` §2/§3.5/§3.6 + K19–K25；`plan/04` §1/§2.2/§3.4–§3.6；`plan/05` M5；`plan/06`；`plan/00`；`plan/02` §5；`README.md`；`data/README.md` §5 | 逐处同步 |

**M5 实装期的口径决定（重要，逐条见 `plan/05` M5 段与 `plan/06` D7–D10）**：

1. **对账的 `contradiction` 在账本里汇总成 `undecidable`，不是 `fail`**（K19）。矛盾的意思是
   "哪一侧描述的是现实本工具不知道"；报成 `fail` 会被读成"你被黑了"。
2. **`trusted_authserv_ids` 为空 ≠ 全部可信**（K20），一律 fail-closed。
3. **`diff` 的退出码恒 0**：它是比较命令，"有差异"是正常输出。
4. **`--change` 的 `include:` 用冒号形态**（K25），且键集是 `p|sp|np|t|all|include`。
5. **`--strict-evidence` 扩到 `whatif` / `diff`**（K24）。
6. **`--rua` 缺省不算 undecidable**（K23）：可选输入缺省若影响退出码，它会变成噪声。
7. **差分 ops 不在"不等长列表"上按下标递归**（K22）：重建顺序无法唯一定义。
8. 卫生门新增 `AR_PTYPE` 剥离（`plan/04` §3.6），**不改 fixture 去迁就门**。

**未做**：远端仓库、CI 实跑、M6 全部。

---

## 二、当前事实·状态不变量（**动手前必须知道**）

1. **`mailvault/__init__.py::__version__` 是版本唯一真源**。`pyproject.toml` 用 `dynamic`。定版只改这一处。
2. **`mailvault/constants.py` 是全部数值/枚举口径的唯一出处**。M5 新增 `RECONCILE_*` /
   `STRICT_FORBIDDEN` / `WHATIF_*` / `DIFF_SCHEMA_VERSION` / `DIFF_*_FILENAME`。
3. **`canonical.py` 是全仓唯一 JSON 出口**（K2）。M5 没有新增序列化路径（`diff_ledgers`
   只产出**普通 dict**，落盘仍走 `canonical.dump_file`）。
4. **网络 import 只在 `net.py`**（K3）。M5 的 `reconcile.py` / `whatif.py` 在此约束下（21 源文件全绿）。
5. **时钟豁免精确到函数**（K7）：`net.py::utc_now_z` 是**唯一**允许读时钟的位置。
   M5 的判定路径零时钟：Received 的时间只取**字面值**并**相互**比较
   （用 `email.utils.parsedate_to_datetime` 解析，**不读时钟**）。
6. **状态副本 = 4 处**（`plan/00` 里程碑表 + `plan/05` 状态表 + `README.md` 状态行 +
   `plan/00` 承诺-证据台账）。翻状态**四处一起改**。`plan/06` 缺口表是第五处（只描述、不点名文件）。
7. **`plan/05` 与 `plan/06` 的表格首列不要用 `| M<n> |` 形态**做非状态用途——布局门会误判。
8. **`audit` 现在是 SPF + DKIM + DMARC + 对账四条真判定**；`whatif` / `diff` 也已实现。
   没有 `ModuleNotReady` 的出口了（`cli.main` 仍捕获它，作为将来新增子命令的 fail-closed 兜底）。
9. **`requires-python = ">=3.11"`，本机无 3.11**（只有 3.8.8 / 3.12.10）。一律 `py -3.12`。
10. **本仓库无远端**。DoD 里不许写"CI 绿"。
11. **运行时零第三方依赖**。`pyyaml` / `cryptography` 都只在 `dev` extra（M5 的两个生成器
    也只在 `gen_reconcile_fixtures.py` 里用 `cryptography` 签名）。
12. **"没查过" ≠ "没有"**（K13）：SPF/DKIM/DMARC 三模块各一例守门。对账侧同理——
    "本工具不重算该 method" 判 `undecidable`，**不判** `pass`/`none`。
13. **Organizational Domain 只由 tree walk 得出**（K16）；PSL 值只作对照。
14. **`np=` 的存在性歧义不猜**（K17）。
15. **旧标签 `pct`/`rf`/`ri` 出现即告警、语义不被采纳**（K18）。
16. **`disposition_status` 三值**：`determined` / `not_applicable` / `undecidable`。
17. **`adkim=` 只管 DKIM 侧、`aspf=` 只管 SPF 侧**。
18. **空反向路径时 SPF 域就是 HELO 域**（§3.2.4 → RFC 7208 §2.4）。
19. **`check_entry` 的字段集对所有条目一致**：对账条目 `tree` 恒为 `null`（键仍存在）。
20. **`dmarc.py` / `reconcile.py` / `whatif.py` 都不算退出码**：它们只给结论；
    退出码走 `ledger.assemble` 的 `summary.exit_code`（= `exits.exit_code_for`）。
21. **`.eml` 的正文归一**：`body_crlf` 按 `\r?\n` 切行。
22. **fixture 域映射**：示例整体落到 `.example.com` / `.example.net` / `.example.org` 下。
    **不放宽卫生门**（M5 只加了 `AR_PTYPE` 剥离，见第 15 条坑）。
23. **`whatif` 块是报告信封**：不参与差分、不参与 `ledger_id`（K22）。差分描述的是**账本本体**。
24. **`_run_checks()` 是 `audit` 与 `whatif` 的唯一求值入口**（K22 的前提：两边同一套求值器）。
    新加"跑一遍判定"的地方必须走它，别另写一份。
25. **`whatif` / `diff` 也有 `--strict-evidence`**（M0 冻结的契约块里没有它，M5 补上并写进
    `plan/03` §2 与 README）。
26. **`diff.json` 的默认文件名是 `diff.json` / `diff.md`**，与 `verdict.*` 分开。
27. **`.eml` fixture 靠 `.gitattributes` 的 `*.eml -text` 保字节**（M5 修的）。往 `fixtures/`
    加新的字节敏感样本（CRLF 样张、登记过 sha 的产物）时**必须**同步加规则，否则
    裸 clone 后才显形。守门：`test_determinism.py::test_eml_fixtures_need_crlf_and_must_be_declared_minus_text`。
28. **`--change` 键集/取值在 `constants`**；`--help`、`plan/03` §2 与 README 必须同步
    （M0 的 `test_change_has_no_choices_restriction` 直接吃 `include:_spf.example.invalid` 这个示形）。

---

## 三、本棒（M6）已完成 —— 逐条对照原待办

原待办九条全部落地，逐条给出**实测证据**：

| # | 原待办 | 结果 |
|---|---|---|
| 1 | 脱敏四步 + 产物扫描 | `examples/` 4 用例 / 10 份真产物（`gen_examples.py`，真 CLI 跑真 fixture + `--strict-evidence`，`--check` 逐字节 + 退出码幂等）；禁词门 **PASS 11 份**（从 SKIP 转真判定）；卫生门扫描面扩到 `fixtures/` + `examples/` → **PASS 108 份**；样例绝对路径直扫 PASS（`tests/test_examples.py`） |
| 2 | 干净环境验证 | **三种形态各 18/18**：`git archive` 目录 / 本地 bare clone round-trip / **发布件真下载解包**。`pytest` 470 passed；三类变异 11/11 · 8/8 · 11/11；五个生成器 `--check` 幂等 |
| 3 | 建远端 + 首推 + CI run id 入库 | `gh repo create yuluo554/mailvault --public` 完成；**push 数 = run 数 = 6**（截至 `858f944`；不变量「每次 push 恰好一条 run」由 `--online` 断言）；run id 全部回填（见 `plan/RELEASE-M6.md` §2.2） |
| 4 | 定版 + `v1.0.0` tag | `__version__` `0.1.0.dev0` → `1.0.0`（只改一处）；`tests/test_version_consistency.py` 4 条；tag 已推 |
| 5 | GitHub Release | 已发布，附 `git archive` 源码包（sha256 `4140fcf9…8df524`）+ 4 例示例产物 + 五组 fixture 清单 + PSL 版本/日期/sha256 |
| 6 | `plan/RELEASE-M6.md` 两栏 + 覆盖对账 | 两栏 + `覆盖对账` 小节 + **9 条三态行**；`LAYOUT.RELEASE` 实测 `两栏:True 覆盖对账:True 三态行:9` |
| 7 | 发布门三模可复跑 | `tools/check_release.py`：`--offline` 7 条全绿（CI 两 job 都跑）、`--pre-tag` tag 前全绿 / tag 后如期红、`--online` **19 条全绿** |
| 8 | 四处状态副本翻 ✅ + V 表更新 | 四处一起翻 ✅（`LAYOUT.STATUS` 4 处 × 7 里程碑全一致）；V1/V2/V6 转 ✅，V7/V8/V9 仍 ⬜（只能等真实用户反馈） |
| 9 | `docs/backlog.md` 的 G17/G19 是否进二期 | 未动（二期决策，不属发布面） |

**M6 期发现的、只在远端才显形的缺陷（重要）**：

- `container.options: --network none` 与 Actions 的 job 容器模型**互斥**
  （`docker: conflicting options ... network-modes`，实测 run `39526291036`）。
  本机没有 docker，这个缺陷在本机**永远看不出来**。
- 修法：`offline` job 改为普通 runner + `docker run --network none` 起**嵌套**容器，
  镜像由新增 `.github/offline.Dockerfile` 构建。修复后 run `39526981564` / `39527171060` 各 5/5 全绿。
- `v1.0.0` 首指 `195b68d`（CI 一红），修完后 `push --force` 重指到 `c84b0c8`。
  **交付面（`mailvault/` + `pyproject.toml`）两次 tag 之间零差异**。

**无剩余待办**。若要继续，只有二选一：① 收真实用户反馈补 V7/V8/V9；
② 按 `docs/backlog.md` 开二期（G17 Received 深分析 / G19 SRS 模拟）。

---

## 四、既定口径清单（K 编号，动了会打挂测试）

| # | 口径 | 守在哪 |
|---|---|---|
| K1 | 退出码只在 `exits.py`；优先级 `4>3>2>1>0` | `tests/test_contract.py` |
| K2 | `json.dumps` 只在 `canonical.py` | `tools/check_no_direct_json.py` |
| K3 | 网络 import 只在 `net.py` | `tools/check_no_network.py` |
| K4 | 结果枚举只在 `constants.RESULTS`；`undecidable` 不折叠成 `fail` | 五个模块的测试 |
| K5 | `evidence_ref` 缺失 → 构造期降级 `undecidable` | `ledger.check_entry` + `test_ledger` |
| K6 | `schema_version` 单点定义；未知版本 → exit 3 | `constants` + `tests/test_inputs.py` |
| K7 | 零系统时钟；**唯一豁免 `net.py::utc_now_z`**（函数级） | `tools/check_no_clock.py` + `test_determinism` |
| K8 | 比率 = 6 位定点字符串；账本内无裸浮点 | `canonical.fixed6` + `dumps` 拒浮点 |
| K9 | 账本内无绝对路径 | `render._assert_no_absolute_path` |
| K10 | `--strict-evidence` 禁词表 | `constants.STRICT_FORBIDDEN` + `render` + `reconcile` 自检 |
| K11 | fixture 只用保留域 / 文档 IP 段；上游原样件逐条登记豁免 | `tools/check_fixture_hygiene.py` |
| K12 | 判定节点 id 稳定（`n0`, `n0.1`），**只由路径决定** | `test_spf.py` + `test_dmarc.py`（走查 id 带起点域名） |
| K13 | **`found=False`（快照没查过）不得当成"没有记录"**；判 `undecidable` 并带 `data_gap` | `test_spf` / `test_dkim` / `test_dmarc` 各一例 |
| K14 | **单向哈希类失败不编造定位**；给 `kind` + `basis` | `test_dkim.py::test_failure_at_for_*` |
| K15 | **fixture 卫生门只扫 JSON 的字符串值、不扫键** | `test_dkim.py::test_fixture_hygiene_catches_domain_in_json_value` |
| K16 | **DMARC 的 Organizational Domain 只由 §4.10.2 的 tree walk 得出**；PSL 值仅对照 | `test_dmarc.py::test_psl_organizational_domain_is_reference_only` |
| K17 | **`np=` 的存在性歧义不猜** | `test_dmarc.py::test_np_with_unknown_existence_is_undecidable_not_guessed` |
| K18 | **旧标签 `pct`/`rf`/`ri` 出现即告警且语义不被采纳** | `test_dmarc.py::test_removed_tags_are_warned_not_silently_ignored` |
| **K19** | **对账的 `contradiction` 不折成 `fail`**；汇总映射：一致→`pass`、矛盾/判不了→`undecidable`、无 AR→`none` | `test_reconcile.py::test_contradiction_is_never_reported_as_fail` + `::test_cross_check_maps_the_three_cases` |
| **K20** | **`trusted_authserv_ids` 为空 ≠ 全部可信**；不可信/不可解析 → fail-closed `undecidable` | `test_reconcile.py::test_trusted_list_empty_is_not_all_trusted` + `::test_untrusted_authserv_id_beats_matching_result` |
| **K21** | **Received 链时间只取字面值、只做相互比较**；解析不出 → `monotonic=null` | `test_reconcile.py::test_unparsed_received_date_makes_monotonic_undecidable_not_guessed` + `::test_received_chain_never_consults_the_system_clock` |
| **K22** | **what-if 只改快照副本**；差分**双向可逆**；`whatif` 块是报告信封（不参与差分与 `ledger_id`） | `test_whatif.py::test_diff_is_invertible_both_directions` + `::test_cli_artifact_can_be_used_to_reverse_derive_the_baseline` |
| **K23** | **RUA 缺数据 → `undecidable` + `required_inputs`**；`--rua` 缺省不影响退出码 | `test_whatif.py::test_missing_rua_is_undecidable_with_required_inputs` + `::test_rua_is_not_part_of_the_exit_code` |
| **K24** | **禁词表唯一出处 `constants.STRICT_FORBIDDEN`**；装配期自检 + 渲染期第二闸；strict 违规 → exit 3 | `test_reconcile.py::test_strict_evidence_selfcheck_can_actually_fail` + `::test_strict_evidence_rejects_a_forbidden_word_in_the_input_header` |
| **K25** | **`--change include:<domain>` 用冒号**；未知键/非法值 → exit 3 | `test_whatif.py::test_include_uses_the_frozen_colon_form` + `::test_bad_change_is_an_error_not_ignored` |

---

## 五、本机环境坑（全部实测；M5 新增 6 条，M6 新增 6 条）

| 坑 | 实测 | 处置 |
|---|---|---|
| `python` 是商店占位符 | — | 一律 `py -3.12` |
| 无 Python 3.11 | `py -0p` → 3.8.8-64 / 3.12.10-64 | 3.11 行为以 CI 为准 |
| Git Bash `/tmp` 与 Python 路径认知不一致 | `py -3.12` 看不到 `/tmp/x` | **用 `cygpath -w "$TEMP"` 转成 Windows 路径**（M2–M5 各踩一次；直接 `cygpath -u "$TEMP"` 得到的仍是 `/tmp`） |
| `/tmp` 下有同名 `.py` 会**遮蔽标准库** | `import inspect` 拿到别人的模块 | **临时脚本写进仓库内目录**（如 `.probe/`），跑完删 |
| Git Bash heredoc 里写中文会乱码 | — | **把脚本写到文件再跑**，或 `PYTHONUTF8=1` |
| Windows 控制台打印中文乱码 | — | 只是显示问题；判据按 UTF-8 读文件 |
| `cryptography` 拒绝生成 <1024 位密钥 | `rsa.generate_private_key(512)` → `ValueError` | 用纯 Python 素数搜索（`gen_dkim_fixtures.py::_gen_small_rsa`） |
| `cryptography` 的 `sign(data, pad, hash_alg)` **会自己再哈希一遍** | 每条都验不过 | 必须用 `utils.Prehashed(hash_alg)` |
| dkimpy 拒绝 `t=` 在未来 | `t= value is in the future` | fixture 用过去的时间戳 |
| dkimpy 的模块级 `verify()` 遇首个坏签名就抛异常 | — | 对账用 `DKIM(raw).verify(idx=i)` 逐条调 |
| dkimpy 的 `signature_fields` 是 dict 不是 list | 数签名条数恒为 0 | 数 `d.headers` 里 `dkim-signature` 的出现次数 |
| 布局门变异靶子随进度失效 | M06/M07 曾写死 M1/M2 | 变异脚本**探测当前待办里程碑**；靶子找不到就断言失败 |
| fixture 卫生门会扫 `fixtures/*/README.md` | 引用上游真实域名会自己变红 | 文档里描述上游件时**不要写字面域名/IP**（M5 又踩一次：README 里写了某个真实域名示例 → 红） |
| 卫生门也扫 `expected.json` 的 `why` | M4 在 `why` 里写了 RFC 原文示例域 → 红 | 描述原文域时不要写字面值 |
| **RFC 8601 的 `ptype` 关键字会被 DOMAIN 正则命中** | `smtp.mailfrom` 的"TLD" 8 个字母 → 卫生门判成非保留域名 | 门已剥 `(smtp\|header\|body\|policy\|dns).property=` 前缀；新增 ptype 且不在闭集里时，扩 `AR_PTYPE`（**闭集**，不是"常见词白名单"） |
| **`--change include:` 没有 `=`** | 只按 `=` 切的解析器把文档里的冻结示例判成非法 | `parse_changes` 先认 `include:` 前缀；`include=` 也接受（同一语义两种写法） |
| **`.gitattributes` 的 `text=auto eol=lf` 会吃掉 `.eml` 的 CRLF** | 临时 bare 仓库 round-trip 实测：`git add` 后索引 blob 里 CRLF **0** 处（工作区 25 处）；裸 clone 起来生成器全报不一致、DKIM 全变 `body_hash` | `.gitattributes` 加 `*.eml -text`；**本机工作区看不出来**（文件没被碰过），所以必须有断言盯着。往 `fixtures/` 加字节敏感样本时同步加规则（第 27 条） |
| **测试往 `fixtures/` 写产物会污染门** | 卫生门会去扫测试副产物；`--check` 会看到不该看到的文件 | 测试产物一律写 `tmp_path`（`test_reconcile.py::test_reconcile_render_passes_strict_evidence_on_clean_fixtures` 是反例改正后的样子） |
| **`render()` 在 strict 下抛 `ValueError`** | 未捕获会冒成 traceback | `cli._render()` 把它转成 `InputError`（exit 3）；新增渲染路径要接同一个包装 |
| **`--change` 的键集与文档示例要对齐** | M0 的 `test_change_has_no_choices_restriction` 就用 `include:_spf.example.invalid` | 改键集必须同时改 `constants.WHATIF_CHANGE_KEYS`、`--help`、`plan/03` §2 与 README |
| **`verify_module_mutations.py` 要跑真 pytest** | 每组 ~5–10s，11 组约 1–2 分钟 | 别在循环里跑全量测试；用 `-k <node id 子串>` 收窄；植入后必须断言"仍能编译"（否则假红） |
| pyflakes 会抓 `%` 字符串里的 `%{` | — | 该转义就写 `%%{p}` |
| 测试文件 docstring 里的 `\*` | `SyntaxWarning: invalid escape sequence` | 用 `raw` 字符串或改措辞 |
| 测试 docstring 里写中文引号 `"` | Python 字符串 SyntaxError（`"显式 none 必须说清"这里没有 method 声明""`） | 用 `『』` 或转义 |
| **`dict`/`list` 进 `subject`** | 渲染层按 `k=v` 平铺，嵌套值变成不可读的 repr | `subject` 只放**标量**；逐跳/逐条明细进 `trace` |
| **Actions 的 job 容器不能写 `--network none`**（M6 实测） | `container.options: --network none` → `docker: conflicting options: cannot attach both user-defined and non-user-defined network-modes`（run `39526291036` 的 `Initialize containers` exit 125）。**本机没有 docker，这个缺陷永远看不出来** | 不把 job 放进容器；改用普通 runner + `docker run --network none` 起**嵌套**容器（`.github/offline.Dockerfile`）。`--network none` 只在 `docker run` 这一层合法 |
| **`gh api` 的 endpoint 不能以 `/` 开头**（Git Bash） | `/user/repos` 被当成 `D:/program/Git/user/repos`（路径改写） | 写 `gh api user/repos`（不带前导 `/`） |
| **`git ls-remote` / `git push` 走 HTTPS 在本机超时** | `github.com:443` 连不上（21s 超时），但 `api.github.com` 通、SSH 通 | 远端用 **SSH**：`git@github.com:yuluo554/mailvault.git`；查远端状态用 `gh api` / `gh run` |
| **Git Bash 的 `tar` 把 `C:` 当远端主机** | `tar -xzf C:/...tar.gz` → `Cannot connect to C: resolve failed` | 用 `py -3.12 -c "import tarfile..."` 解包，或 `cygpath -u` 后传 POSIX 路径 |
| **布局门变异的靶子会随进度失效（M06 又踩一次）** | 全部里程碑 ✅ 后，"找待办里程碑翻成完成"找不到靶子 | `m06` 改为**两态探测**：有待办就翻成完成，全完成就把一个已完成翻回待办（都是单副本冲突）。另加"必须改动字节"的断言，防静默空跑 |
| **发布门的判据不能写成"所有历史 run 都绿"** | 历史不可变：首推的 2 条红 run 永远红，那样写会得到一条永远红、然后被删掉的门 | 判据改为「**认证发布树的 run 全绿**」+「**历史失败逐条登记**」（漏记即红）。假门的反面不是更严，是**判据指错了对象** |
| **`push 数 = run 数` 写成绝对数字是自指的** | 留档写 `5 = 5` → 下次改文档的提交让它变 6 → 再改数字再推 → 无穷 | 判据落在**不变量**：每次 push 恰好一条 run（按「提交 + ref」去重——同一提交既作分支 HEAD 又作 tag 指向是**合法**的两条）+ 两个数字彼此相等 + 计数锚在一个**可核对的提交**上。绝对数字只作快照保留 |

---

## 六、DoD 逐项 checklist

### 6.1 M5 的 DoD（已实测，保留备查）

- [x] 三个对账 fixture：转发 SPF fail/DKIM 过（`r1-forwarded`）、网关改正文（`r2-gateway-body`）、注入伪造 AR（`r3-untrusted-ar`）
- [x] 每条 `contradiction` 有 ≥2 条解释 + 各自验证方法（且 <2 条时模块内 `InternalError`）
- [x] `--strict-evidence` 禁词扫描通过（对账装配期自检 + 渲染期第二闸；违规 → exit 3）
- [x] what-if 差分可复算；能反推出基线（与**另一次独立** `audit` 产物逐字节相等，含 `ledger_id`）
- [x] 无 RUA 数据 → `undecidable` + 所需输入清单（`required_inputs`；且不影响退出码）
- [x] 三分类都有样本（`consistent` / `contradiction` / `undecidable` 各 ≥1）
- [x] RFC 8601 §2.2 语法四条逐条钉死（版本号 / 无 `=` 默认 none / 括号里的 `;` / 坏头给 note）
- [x] 不可信 authserv-id + 不可解析头 + **空可信列表** → 全 fail-closed `undecidable`
- [x] 矛盾**不折成** `fail`（`reconcile.cross_check` 三态映射有测试）
- [x] Received 链：单调性 / 时钟回退 / 跳数；解析不出 → `monotonic=null`
- [x] 分类逻辑与**手算实现**逐条比对（9 组真值表）
- [x] `spf-tighten` 实测**退出码 0 → 1**（差分不是装饰）
- [x] RUA 的 `affected` 口径被真实报告钉住（写成"任一不过"会把 1 变 2）
- [x] `diff` 子命令：写 `diff.json`/`diff.md`、退出码 0、ops 双向可逆
- [x] `whatif` / `diff` 支持 `--strict-evidence`
- [x] 两个生成器 `--check` 逐字节幂等（3×4 + 10 份）
- [x] `pytest` **441 passed**；全部门全绿；变异 11/11（布局）+ 6/6（AST）+ **11/11（语义）**
- [x] 11 组语义变异全部如期变红（B01–B11），且每组断言"植入后仍能编译"
- [x] 差分双跑 `verdict.json` 字节级一致
- [x] **本地 bare 仓库 round-trip 直跑**：克隆出来的仓库 `pytest` 436 + 七条门 + 四个生成器 `--check` 全绿（并修掉 `.eml` 缺 `-text` 的归一化缺陷 + 加断言盯住）
- [x] 4 处状态副本 + `plan/06` 缺口表同步；`plan/04` §3.5/§3.6 记 M5 数据与判据口径

**M5 期 DoD 未达成项 —— M6 已结清其中两条**：

- ~~CI 实跑：未接远端，未跑过~~ → **已结清**（M6：run `39526981564` / `39527171060` 各 5/5 全绿）。
- ~~Python 3.11 行为：本机验不了~~ → **已结清**（CI `py3.11 · ubuntu` / `py3.11 · windows` 全绿）。

**仍未达成（如实登记，均为已知限制，不是欠账）**：

- 对账只重算 `spf`/`dkim`/`dmarc` 三类 method；`iprev`/`auth`/`arc` 一律 `undecidable`（G16）。
- Received 链不做"乱序 / 跳数异常 / 跨时区压缩"的语义分析（G17）。
- ARC 辅助证据未实现；预留的恒 `null` `arc` 键**已删掉**（G18）。
- SRS 影响模拟未实现；`--change` 只支持六个键（G19）。
- what-if 只改**快照**，不改 `query.json`（"换发信 IP 会怎样"做不到，G20）。
- 对账与 what-if 在**真实收件方的** `Authentication-Results` / 真实 RUA 报告上的表现：
  **未验**，登记 `plan/05` §5 的 V8/V9（只能等真实用户反馈）。

### 6.2 M6 的 DoD（本棒，全部已实测）

- [x] 脱敏四步：禁词门 **PASS 11 份**（从 `SKIP` 转真判定）；卫生门 **PASS 108 份**（面扩到 `examples/`）；样例无绝对路径；样例 `tool_version` 全部 `=1.0.0`
- [x] 干净环境验证：`git archive` 目录 / 本地 bare clone / **发布件真下载解包** 三种形态各 **18/18**
- [x] 建仓 `gh repo create yuluo554/mailvault --public` + 首推；**push 数 = run 数 = 6**；run id 已回填
- [x] `git tag v1.0.0`（annotated，重指到 `c84b0c8`）+ GitHub Release 已发布
- [x] `plan/RELEASE-M6.md` 两栏 + 覆盖对账 + 9 条三态行（`LAYOUT.RELEASE` 实测通过）
- [x] 发布门三态可复跑：`--offline` 7 条 / `--pre-tag` 9 条 / `--online` **19 条** 全绿（各自只在成立的那一态为绿）
- [x] 版本三处一致（`tests/test_version_consistency.py` 4 条）；`pytest` **470 passed**
- [x] 变异验证：布局 **11/11**（M06 已改为"全完成态也能构造单副本冲突"）+ AST **8/8**（新增 A07/A08）+ 语义 **11/11**
- [x] 发布件复核 V6：`gh release download` → sha256 `4140fcf9…8df524` 与本地 `git archive` 及 GitHub asset digest **三方一致**；解包后 18/18
- [x] 四处状态副本 + `plan/06` 缺口表（G4/G5 关闭）+ `plan/05` §5 的 V1/V2/V6 转 ✅ 同步

---

## 七、关键命令速查

```bash
# 0) 第一动作：布局门
py -3.12 tools/check_sprint_layout.py

# 1) 三类变异验证（改门/改判定后必跑）
py -3.12 tools/verify_layout_gate.py       # 11/11 必须红
py -3.12 tools/verify_ast_gates.py         # 8/8 必须红
py -3.12 tools/verify_module_mutations.py  # 11/11 必须红（每组 ~5–10s）

# 2) 各守门
py -3.12 tools/check_no_network.py
py -3.12 tools/check_no_direct_json.py
py -3.12 tools/check_no_clock.py
py -3.12 tools/check_fixture_hygiene.py
py -3.12 tools/check_forbidden_terms.py
py -3.12 tools/offline_smoke.py

# 2b) 发布门三态（CI 只跑 --offline；--pre-tag 在 tag 后必然红，属预期）
py -3.12 tools/check_release.py --offline
py -3.12 tools/check_release.py --pre-tag     # 仅 tag 之前
py -3.12 tools/check_release.py --online      # 推送/Release 之后（19 条判据）

# 3) 测试与 CLI
py -3.12 -m pip install -e ".[dev]"      # 开发期需要 pytest + pyyaml + cryptography
PYTHONUTF8=1 py -3.12 -m pytest
PYTHONUTF8=1 py -3.12 -m pytest tests/test_reconcile.py tests/test_whatif.py -q
py -3.12 -m mailvault --version

# 4) 生成器幂等复核（改生成器后必跑）
py -3.12 tools/gen_dkim_fixtures.py --check
py -3.12 tools/gen_dmarc_fixtures.py --check
py -3.12 tools/gen_reconcile_fixtures.py --check
py -3.12 tools/gen_whatif_fixtures.py --check
py -3.12 tools/gen_examples.py --check     # M6：examples/ 逐字节 + 退出码未漂

# 4b) 干净环境 / 发布件复核（M6）
git archive HEAD | tar -x -C "$(cygpath -m "$TEMP")/clean"     # 或本地 bare clone
py -3.12 tools/check_release.py --online                        # 远端/tag/Release/CI 实录
gh release download v1.0.0 --pattern "mailvault-1.0.0.tar.gz" --dir "$DL"   # V6 真下载

# 5) 端到端：对账（Git Bash 里必须用 cygpath 转 Windows 路径）
OUT="$(cygpath -w "$TEMP")\\mv6"; mkdir -p "$(cygpath -u "$OUT")"
py -3.12 -m mailvault audit \
    --snapshot fixtures/reconcile/r2-gateway-body/snap.json \
    --eml fixtures/reconcile/r2-gateway-body/message.eml \
    --query fixtures/reconcile/r2-gateway-body/query.json --out-dir "$OUT"; echo "exit=$?"
#   期望 exit 2（矛盾 → cross_check undecidable）
grep -A 6 "对账" "$(cygpath -u "$OUT")/verdict.md"   # 应看到 3 条解释 + 各自 verify

# 6) 端到端：what-if 差分（退出码 0 → 1）
py -3.12 -m mailvault whatif \
    --snapshot fixtures/whatif/spf-tighten/snap.json \
    --eml fixtures/whatif/spf-tighten/message.eml \
    --query fixtures/whatif/spf-tighten/query.json \
    --change all=-all --json "$OUT/spft.json" --md "$OUT/spft.md"; echo "exit=$?"

# 7) 端到端：RUA 关联 + 反推基线
py -3.12 -m mailvault audit \
    --snapshot fixtures/whatif/p-reject/snap.json \
    --eml fixtures/whatif/p-reject/message.eml \
    --query fixtures/whatif/p-reject/query.json --json "$OUT/base.json" >/dev/null
py -3.12 -m mailvault whatif \
    --snapshot fixtures/whatif/p-reject/snap.json \
    --eml fixtures/whatif/p-reject/message.eml \
    --query fixtures/whatif/p-reject/query.json \
    --change p=reject --rua fixtures/whatif/rua.json \
    --json "$OUT/cand.json" --md "$OUT/cand.md"
py -3.12 -m mailvault diff --baseline "$OUT/base.json" --candidate "$OUT/cand.json" \
    --json "$OUT/diff.json" --md "$OUT/diff.md"
#   `$OUT/cand.json` 的 whatif.diff.ops 反转后施加到 cand.json（去掉 whatif 键）
#   必须**逐字节等于** $OUT/base.json —— test_whatif.py 已断言这一点

# 8) 只读检查：本棒交付面
git status --short
git ls-files
```