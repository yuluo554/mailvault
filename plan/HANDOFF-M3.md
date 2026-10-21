# HANDOFF-M3（M2 收尾 → M3 开工）

> 用法（用户侧启动命令）：`/goal 读取 "<项目绝对路径>\plan\HANDOFF-M3.md" 继续完成任务`
> **第一动作 = 跑布局门**：`py -3.12 tools/check_sprint_layout.py`（必须全绿，红了先修布局）。
> 本文件内一律相对路径。

---

## 一、当前进度 + 证据

**已完成：M0（方法论装订 + 骨架）+ M1（数据先行）+ M2（SPF 求值器）**，均 2026-10-21。

| 交付 | 证据（实测命令 + 结果） |
|---|---|
| 布局门 | `py -3.12 tools/check_sprint_layout.py` → **全绿**（8 PASS / 0 FAIL / 1 SKIP=RELEASE） |
| 布局门变异 | `py -3.12 tools/verify_layout_gate.py` → **11/11 全部如期变红** |
| AST 守门 | `check_no_network` 14 文件全绿；`check_no_direct_json` 14 文件全绿；`check_no_clock` 15 文件全绿 |
| AST 变异 | `py -3.12 tools/verify_ast_gates.py` → **6/6 全部如期变红** |
| fixture 卫生 | `py -3.12 tools/check_fixture_hygiene.py` → PASS 5 份 + EXEMPT 2 份（理由打印） |
| 禁词门 | `py -3.12 tools/check_forbidden_terms.py` → SKIP 0 份（M6 才转真判定） |
| 断网冒烟 | `py -3.12 tools/offline_smoke.py` → **缺输入→3、完整输入→0、socket 尝试 0**（断言已收紧） |
| 测试 | `PYTHONUTF8=1 py -3.12 -m pytest` → **230 passed**（M1 时 178） |
| **RFC 7208 通过率** | **202/203 = 99.5%**（DoD 门槛 95%）；1 条为已登记口径差异 |
| CLI | `py -3.12 -m mailvault --version` → `mailvault 0.1.0.dev0` |
| 断网 audit | 完整三件套 → exit `0`（pass）；缺三件套 → exit `3` |
| **双跑一致** | 同一输入两次 `audit` → `verdict.json` sha256 相同（`c8af3a6a…`）、`verdict.md` 相同 |

**M2 交付面**（新增/改动的代码）：

| 模块 | 内容 |
|---|---|
| `mailvault/modules/__init__.py` | L3 包声明（只许 import L1/L2，不得 import 网络层） |
| `mailvault/modules/spf.py` | `check_host()` + `Budget` + 宏展开（§7）+ include 树 + `DataGap` |
| `mailvault/cli.py` | `_cmd_audit` 接上 SPF：读三件套 → 求值 → 装配 → 落盘两轨 |
| `mailvault/ledger.py` | `check_entry` 增 `tree` 字段（**所有条目都有此键**，无树时为 `null`） |
| `mailvault/render.py` | 渲染 include 树（缩进列表 + 切点标注） |
| `mailvault/constants.py` | 新增 `SPF_MAX_DEPTH`(20) / `SPF_TREE_MAX_NODES`(256) |
| `tests/rfc7208_suite.py` | `StubResolver` 超时语义照上游修（局部 `timeout` 标志）；`to_snapshot(extra=)` 补全；新增 `run_case()` 迭代补全与 `reverse_lookup_name()` |
| `tests/test_spf.py` | **46 条**：通过率、预算逐格、树切点、宏、灰区、确定性、反自证 |
| `data/rfc7208-failures.md` | 实跑结果 + 1 条失败 + 3 条口径更正，逐条带四要素 |
| `tests/test_contract.py` | 三条新断言：`audit` 输入缺失→3 / 端到端→0 / 双跑 sha256 一致 |

**未做**：远端仓库、CI 实跑、M3–M6。

---

## 二、当前事实·状态不变量（**动手前必须知道**）

1. **`mailvault/__init__.py::__version__` 是版本唯一真源**。`pyproject.toml` 用 `dynamic`。定版只改这一处。
2. **`mailvault/constants.py` 是全部数值口径的唯一出处**。M2 新增 `SPF_MAX_DEPTH` / `SPF_TREE_MAX_NODES`。
3. **`canonical.py` 是全仓唯一 JSON 出口**（K2）。M2 没有新增序列化路径。
4. **网络 import 只在 `net.py`**（K3）。`mailvault/modules/` 也在此约束下（门扫 `mailvault/**`）。
5. **时钟豁免精确到函数**（K7）：`net.py::utc_now_z` 是**唯一**允许读时钟的位置。
   **M2 新增的后果**：SPF 的 `%{t}` 宏**不展开**（展开它必须读时钟）。这不是未实现，
   是确定性纪律的直接后果——详见 `plan/06` 缺口 G7 与 `tests/test_spf.py::test_macro_t_is_reported_not_silently_wrong`。
6. **状态副本 = 4 处**（`plan/00` 里程碑表 + `plan/05` 状态表 + `README.md` 状态行 + `plan/00` 承诺-证据台账）。
   翻状态**四处一起改**。`plan/06` 的缺口表是第五处（只描述、不点名文件）。
7. **`plan/05` 与 `plan/06` 的表格首列不要用 `| M<n> |` 形态**做非状态用途——布局门会误判。
8. **未实现的能力必须 fail-closed 到 2**。`whatif` / `diff` 仍是 `ModuleNotReady` → 2；
   **`audit` 已不再是**（M2 起真的在跑判定）。
9. **`requires-python = ">=3.11"`，本机无 3.11**（只有 3.8.8 / 3.12.10）。一律 `py -3.12`。
10. **本仓库无远端**。DoD 里不许写"CI 绿"。
11. **运行时零第三方依赖**：`pyyaml` 只在 `dev` extra，**只给 `tests/rfc7208_suite.py` 用**。
    **M3 写 `modules/dkim.py` 时不得 import yaml，也不得 import 参照实现**
    （`test_spf.py::test_runtime_does_not_import_reference_implementation` 是模板）。
12. **"没查过" ≠ "没有"**（K13，M2 新增）：`Snapshot.resolve()` 的 `found=False` 必须走
    `SpfResult.data_gap` + `undecidable`，**不得**当成"没有记录 → none"。
    M3 对 DKIM key 查询要照同一口径做：**快照无 key → `undecidable`**，不是 `fail`。
13. **SPF 的 `evidence_ref` 挂命中机制自己的条款节**（§5.1–§5.7 + §4.6.2），不是笼统的 §4.6.4。
    M3 照同一粒度做（RFC 6376 §3.4/§3.5、RFC 8301 §3.2 各挂各的）。
14. **`check_entry` 的字段集对所有条目一致**：`tree` 键总是存在（无树时 `null`）。
    M3 的 DKIM 条目不要省略该键。

---

## 三、下一棒待办（M3：DKIM 验签）

按 `plan/05` §2 的 M3 DoD 与 `plan/03` §3.3：

1. **`mailvault/modules/dkim.py`**：遍历 `DKIM-Signature` **全部**条目，逐条独立求值，**不短路**。
   每条输出：`selector` / `d` / `i` / `a` / `c` / `bh_matches` / `failure_at` / `key_bits` /
   `key_status` / `result`。
2. **零依赖 RSA**：`mailvault/crypto/der.py`（DER TLV 取 SubjectPublicKeyInfo 的 n/e）+
   `mailvault/crypto/rsa.py`（PKCS#1 v1.5 验签）。**只能用标准库**（`hashlib` / `hmac`）。
3. **规范化**（RFC 6376 §3.4）：relaxed / simple 两种 header 与 body 规范化都要实现。
   **`l=` 不得大于规范化正文长度**（§3.5）——超了按 permerror 语义处理。
4. **`key_status` 四值**：`ok` / `revoked`（`p=` 为空）/ `missing`（快照无记录）/ `weak`（<1024 位）。
   `missing` → **`undecidable`**（不是 `fail`）；`weak` → `fail`（RFC 8301 §3.2 是 MUST）。
   `a=ed25519-sha256` → `undecidable` + 告警「本工具不支持该算法」。
5. **`failure_at` 定位**：header 失败给 `{"header": "<name>", "offset": <int>}`；
   body 失败给 `{"body_line": <int>}`（1-based，规范化后第一处不匹配的行）。
6. **五类失败 fixture**（`fixtures/dkim/`）：body 改 / header 改 / `l=` 截断 / key 缺失 / RSA-512。
   另有**正样本**（签名有效）——只有负样本的话，"永远返回 fail"也能全过。
7. **参照实现对账**（`plan/04` §2.2）：测试期用 `cryptography`（**已在 dev 环境**，实测 50.0.2）
   独立验一遍，逐条比对。参照实现**不得进运行时**（照 `test_spf.py` 那条 AST 断言做）。
8. **测试**：`tests/test_dkim.py`（五类失败、多签名不短路、无 key → undecidable、`l=` 边界、
   零依赖 RSA 与参照实现逐条一致）。
9. **`cli._cmd_audit` 接上 DKIM**：`checks[]` 多一条 `dkim.verify_signature`。
   **退出码取最严重的那个**（`exits.exit_code_for` 已实现优先级，直接复用）。

---

## 四、既定口径清单（K 编号，动了会打挂测试）

| # | 口径 | 守在哪 |
|---|---|---|
| K1 | 退出码只在 `exits.py`；优先级 `4>3>2>1>0` | `tests/test_contract.py` |
| K2 | `json.dumps` 只在 `canonical.py` | `tools/check_no_direct_json.py` |
| K3 | 网络 import 只在 `net.py` | `tools/check_no_network.py` |
| K4 | 结果枚举只在 `constants.RESULTS`；`undecidable` 不折叠成 `fail` | `test_contract` / `test_ledger` / `test_spf` |
| K5 | `evidence_ref` 缺失 → 构造期降级 `undecidable` | `ledger.check_entry` + `test_ledger` |
| K6 | `schema_version` 单点定义；未知版本 → exit 3 | `constants` + `tests/test_inputs.py` |
| K7 | 零系统时钟；**唯一豁免 `net.py::utc_now_z`**（函数级） | `tools/check_no_clock.py` + `test_determinism` |
| K8 | 比率 = 6 位定点字符串；账本内无裸浮点 | `canonical.fixed6` + `dumps` 拒浮点 |
| K9 | 账本内无绝对路径 | `render._assert_no_absolute_path` |
| K10 | `--strict-evidence` 禁词表 | `render.STRICT_FORBIDDEN` + `check_forbidden_terms` |
| K11 | fixture 只用保留域 / 文档 IP 段；上游原样件逐条登记豁免 | `tools/check_fixture_hygiene.py` |
| K12 | 判定节点 id 稳定（`n0`, `n0.1`），**只由路径决定**，不依赖遍历顺序 | `test_spf.py::test_tree_root_and_child_ids_are_stable` |
| **K13** | **`found=False`（快照没查过）不得当成"没有记录"**；判 `undecidable` 并带 `data_gap` | `test_spf.py::test_data_gap_is_not_treated_as_no_record` |

---

## 五、本机环境坑（全部实测）

| 坑 | 实测 | 处置 |
|---|---|---|
| `python` 是商店占位符 | — | 一律 `py -3.12` |
| 无 Python 3.11 | `py -0p` → 3.8.8-64 / 3.12.10-64 | 3.11 行为以 CI 为准 |
| Git Bash `/tmp` 与 Python 路径认知不一致 | `py -3.12` 看不到 `/tmp/x` | 用 `cygpath -w` 转换，或直接用 `$TEMP`（M2 踩过两次） |
| `codeload.github.com/spf-tools/pyspf` **404** | 实测 404（仓库已迁走） | 参照实现走 PyPI：`py -3.12 -m pip download pyspf --no-deps --no-binary :all:` → 解包得 `spf.py` + `test/testspf.py` |
| `spf.py` 顶层 `import DNS` / `import dns` 会炸 | 无 pydns/dnspython | 在 `sys.modules` 里塞一个 `types.ModuleType('DNS')` 桩（`DiscoverNameServers` / `Type.typemap` / `Lib.RRunpacker.getTXTdata` 三个属性） |
| 上游 driver 的 `timeout` 是**局部标志** | 不是"整域超时" | `StubResolver._collect` 已照此实现；整域判超时会让 `spftimeout` 假失败 |
| 布局门变异靶子随进度失效 | M06/M07 曾写死 M1/M2 | 变异脚本**探测当前待办里程碑**；靶子找不到就断言失败 |
| fixture 卫生门会扫 `fixtures/*/README.md` | 引用上游真实 IP 会自己变红 | 文档里描述上游件时**不要写字面 IP**，用文字转述 |
| `argparse` 缺参 `SystemExit(2)` | 与 `undecidable` 撞语义 | 入口已转 3；`test_contract` 锁定 |
| `ModuleNotReady` 继承 `InputError` | 措辞会打印成"输入错误" | `cli.main` 单独捕获，打印"尚未实现" |
| pyflakes 会抓 `%` 字符串里的 `%{` | `"%{p} ..." % x` 报 unsupported format char | 该转义就写 `%%{p}`；M2 在 `test_spf.py` 踩过 |

---

## 六、DoD 逐项 checklist（本棒，全部已实测）

- [x] `check_host()` 确定性求值，`result` 七值全覆盖（+ `undecidable` 一等结果）
- [x] 预算账本逐格可读（`used`/`limit`/`ref` + `budget_entries` 明细带 `(kind, node_id, ref)`）
- [x] 超限**不抛异常**：`Budget.consume()` 返回布尔 + 置 `limit_hit`；后果逐格不同
- [x] term 第 11 个 → `permerror`；恰好 10 个不算超限（边界两侧都断言）
- [x] MX 超 10 条 → `permerror`；PTR 超 10 条 → **截断**（不是 permerror，已登记更正）
- [x] void 超限 → `undecidable` + 告警；**同记录若另踩 MUST 则报 MUST**
- [x] include 树**完整展开**：13 个 include 全进树，第 11 个起标 `receiver_would_stop_here`
- [x] 节点 id 只由路径决定（根 `n0` / `n<i>` / `n<i>.<j>`），与遍历顺序无关
- [x] 树**不进判定**（独立 shadow 上下文，独立预算与缓存）
- [x] 宏：`s`/`l`/`o`/`d`/`i`/`p`/`h`/`v` 全覆盖 + 变换（数字/r/分隔符集）+ 大写 URL 转义
- [x] `%{p}` 缺 PTR → `undecidable`，**不默认 fail**（灰区 4）；只做诊断的 `%{p}` 不降级
- [x] 宏语法错（`%(`, `%.`, `%{x}`）→ `permerror`；`c`/`r`/`t` 在 exp 之外 → `permerror`
- [x] 先全量校验、后求值（`detect-errors-anywhere` 用例锁这条）
- [x] 数据缺口（`found=False`）→ `undecidable` + `data_gap`，**绝不落到 none**（K13）
- [x] RFC 7208 **202/203 = 99.5%**；1 条失败逐条登记（四要素）
- [x] 失败登记表由三条测试断言盯着（缺条目 / 僵尸条目 / 没写通过率）
- [x] `mailvault audit` 接上 SPF，断网下 exit `0`
- [x] `tools/offline_smoke.py` 断言收紧为固定码（缺输入→3、完整输入→0）
- [x] 两次运行 `verdict.json` sha256 一致 + `verdict.md` 一致
- [x] `pytest` 230 passed；九条门全绿；变异 11/11 + 6/6
- [x] 4 处状态副本 + `plan/06` 缺口表同步；`plan/04` §3.1 记三条口径更正
- [x] `data/rfc7208-failures.md` 进 MANIFEST（发布件要带）

**DoD 未达成项（如实登记）**：

- CI 实跑：**未接远端，未跑过**。首推后需回填 run id。
- Python 3.11 行为：**本机验不了**，以 CI 矩阵为准。
- `exp=` 文本里的 `%{t}`：**不展开**（需要系统时钟，K7 禁）。登记为 `plan/06` G7。
  若要支持，必须改成"时间只取自快照"，届时同时改 `spf.py::_expand_macro`、测试与本节。
- SPF 与上游的 1 条口径差异（void 超限）：**有意为之**，见 `plan/06` G8。

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
py -3.12 -m pip install -e ".[dev]"      # 开发期需要 pytest + pyyaml
PYTHONUTF8=1 py -3.12 -m pytest
PYTHONUTF8=1 py -3.12 -m pytest tests/test_spf.py -k pass_rate -q   # 只跑通过率
py -3.12 -m mailvault --version
py -3.12 -m mailvault audit --snapshot nope.json --eml nope.eml --query nope.json; echo "exit=$?"

# 4) 端到端 audit（断网可跑；用 Windows 路径，Git Bash 的 /tmp 见不到）
OUT="$TEMP/mv"; mkdir -p "$OUT"
py -3.12 -m mailvault audit --snapshot "$OUT/snap.json" --eml "$OUT/m.eml" \
    --query "$OUT/query.json" --out-dir "$OUT"; echo "exit=$?"

# 5) 参照实现核对（仅开发期；运行时不许 import）
py -3.12 -m pip download pyspf --no-deps --no-binary :all: -d "$TEMP/pyspfdl"
#   解包后 spf.py / test/testspf.py；顶层 import DNS 需在 sys.modules 里塞桩

# 6) 只读检查：本棒交付面
git status --short
git ls-files
```