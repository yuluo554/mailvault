# HANDOFF-M1（M0 收尾 → M1 开工）

> 用法（用户侧启动命令）：`/goal 读取 "<项目绝对路径>\plan\HANDOFF-M1.md" 继续完成任务`
> **第一动作 = 跑布局门**：`py -3.12 tools/check_sprint_layout.py`（必须全绿，红了先修布局）。
> 本文件内一律相对路径。

---

## 一、当前进度 + 证据

**已完成：M0（方法论装订 + 计划套件 + 可运行骨架）**，2026-10-21。

| 交付 | 证据（实测命令 + 结果） |
|---|---|
| 装订三件 | `AGENTS.md` 在位；`tools/check_sprint_layout.py` 可跑；`plan/00` 顶部装订行 |
| 计划套件 | `plan/00–06` 齐全，`LAYOUT.SECTIONS` PASS |
| 布局门 | `py -3.12 tools/check_sprint_layout.py` → **全绿**（9 PASS / 0 FAIL / 1 SKIP=RELEASE 未适用） |
| 布局门变异 | `py -3.12 tools/verify_layout_gate.py` → **11/11 全部如期变红** |
| AST 守门 | `check_no_network` 8 文件全绿；`check_no_direct_json` 8 文件全绿；`check_no_clock` 9 文件全绿 |
| AST 变异 | `py -3.12 tools/verify_ast_gates.py` → **5/5 全部如期变红** |
| 断网冒烟 | `py -3.12 tools/offline_smoke.py` → audit 返回 2、socket 尝试 0 |
| 测试 | `py -3.12 -m pytest` → **56 passed** |
| CLI | `py -3.12 -m mailvault --version` → `mailvault 0.1.0.dev0`；`audit` 缺参 → exit 3；未实现 → exit 2 |
| workflow | `.github/workflows/ci.yml` 本地 `yaml.safe_load` 通过：2 jobs（test 14 steps / offline 3 steps） |

**未做**：远端仓库、CI 实跑、M1–M6 全部实现。

---

## 二、当前事实·状态不变量（**动手前必须知道，否则一定踩**）

1. **`mailvault/__init__.py::__version__` 是版本唯一真源**。`pyproject.toml` 用 `dynamic = ["version"]` + `attr` 引用它，**不许在此写第二份**。定版时只改这一处。
2. **`mailvault/constants.py` 是全部数值口径的唯一出处**。SPF 上限、RSA 最小位数、schema 版本、结果枚举都在这里；其它地方（含测试、docs）只准引用常量名。改数值 → 只改这一处。
3. **`canonical.py` 是全仓唯一 JSON 出口**（K2）。任何新模块要序列化必须 `from .canonical import dumps`；`tools/check_no_direct_json.py` 会红。
4. **网络 import 只准出现在 `mailvault/net.py`**（K3）。M1 实现 `snapshot fetch` 时，**只改 `net.py`**；任何其它模块出现 `import socket` 都会让 `check_no_network` 红。
5. **判定不许读系统时钟**（K7）。快照的 `fetched_at` 是唯一时间来源；`tools/check_no_clock.py` 扫 AST。
6. **状态副本 = 4 处**（`plan/00` 里程碑表 / `plan/05` 状态表 / `README.md` 状态行 / `plan/00` 承诺-证据台账）。翻某个里程碑的状态时**四处一起改**，否则 `LAYOUT.STATUS` / `LAYOUT.LEDGER` 红。
7. **`plan/05` 与 `plan/06` 的表格首列不要用 `| M<n> |` 形态**做非状态用途——布局门按"表格行 + 首列里程碑号"识别状态行，会误判（本棒实测踩过：变异表 `| M01 |` 被读成 M1–M10 全完成）。非状态表用 `V01` / `SPF（M1）` 这类标签。
8. **未实现的能力必须 fail-closed 到 2**，不得返回 0 或空结果。M1 实现 `snapshot fetch` 后要把 `tools/offline_smoke.py` 的断言从 `code == 2` 改成 `code in (0,1,2)` 且仍零 socket。
9. **`requires-python = ">=3.11"`，本机无 3.11**（只有 3.8.8 / 3.12.10）。本机一律 `py -3.12`；3.11 行为**只能靠 CI**，别把"本机能跑"当 3.11 证据。
10. **本仓库无远端**。DoD 里不许写"CI 绿"，只能写"本地等价校验（未接远端，CI 待首推验证）"。

---

## 三、下一棒待办（M1 数据先行）

按 `plan/05` §2 的 M1 DoD 执行，顺序建议：

1. **`snap.json` schema 定稿**：按 `plan/03` §3.1 的结构实现 `mailvault/snapshot.py`
   （`queries` 有序列表、`resolve()` 返回首个命中并记下标、`rcode` 非 NOERROR 时 `answer` 必须为空、
   缺 `psl_version`/`psl_date` → `InputError`、未知 `schema_version` → `InputError`）。
2. **`query.json` 解析**（`mailvault/query.py`）：`mail_from` / `client_ip` / `helo` / `trusted_authserv_ids`。
3. **`.eml` 解析**（`mailvault/eml.py`）：headers（保序、保留重复头）/ body / 多 `DKIM-Signature`。
4. **`snapshot fetch` 实现**（只改 `mailvault/net.py` + `cli._cmd_snapshot_fetch`）：
   DNS 查询、`psl.meta.json` 写入、`fetched_at` 用真实时间（**这是唯一允许读时钟的地方**——
   若实现里要读时钟，**必须把豁免写进 `tools/check_no_clock.py`** 并在此处记一笔）。
5. **RFC 7208 测试集入仓**：`fixtures/spf/rfc7208-tests.yml` + `rfc7208-tests.LICENSE`
   （pyspf 的 BSD 式许可，原样保留），`.gitattributes` 已标 `-text`。
6. **PSL 冻结件**：`mailvault/data/public_suffix_list.dat` + `mailvault/data/psl.meta.json`
   （版本 / 日期 / 来源 URL / sha256），`.gitattributes` 已标 `-text`。
7. **`mailvault/psl.py`**：读冻结件、算 Organizational Domain、输出带版本与日期。
8. **测试**：`tests/test_inputs.py`（schema 拒绝、坏输入、缺字段）+ `tests/test_psl.py`。
9. **fixture 卫生**：M1 有 fixture 后 `check_fixture_hygiene` 从 SKIP 转真判定，必须绿。

---

## 四、既定口径清单（K 编号，动了会打挂测试）

完整定义见 `plan/03` §1。下表是浓缩版：

| # | 口径 | 守在哪 |
|---|---|---|
| K1 | 退出码只在 `exits.py`；优先级 `4>3>2>1>0` | `tests/test_contract.py` |
| K2 | `json.dumps` 只在 `canonical.py` | `tools/check_no_direct_json.py` |
| K3 | 网络 import 只在 `net.py` | `tools/check_no_network.py` |
| K4 | 结果枚举只在 `constants.RESULTS`；`undecidable` 不折叠成 `fail` | `test_contract` / `test_ledger` |
| K5 | `evidence_ref` 缺失 → 构造期降级 `undecidable` | `ledger.check_entry` + `test_ledger` |
| K6 | `schema_version` 单点定义；未知版本 → exit 3 | `constants` + 待写的 `test_inputs` |
| K7 | 零系统时钟；时间只来自快照 | `tools/check_no_clock.py` |
| K8 | 比率 = 6 位定点字符串；账本内无裸浮点 | `canonical.fixed6` + `dumps` 拒浮点 |
| K9 | 账本内无绝对路径 | `render._assert_no_absolute_path` |
| K10 | `--strict-evidence` 禁词表 | `render.STRICT_FORBIDDEN` + `check_forbidden_terms` |
| K11 | fixture 只用保留域 / 文档 IP 段 | `tools/check_fixture_hygiene.py` |
| K12 | 判定节点 id 稳定（`n0`, `n0.1`），不依赖遍历顺序 | 各模块测试 |

---

## 五、本机环境坑（全部实测，2026-10-21）

| 坑 | 实测 | 处置 |
|---|---|---|
| `python` 是商店占位符 | — | 一律 `py -3.12` |
| 无 Python 3.11 | `py -0p` → 3.8.8-64 / 3.12.10-64 | 3.11 行为以 CI 为准 |
| Node 在但不用 | `node v24.15.0` | 本项目零 Node 依赖 |
| Git Bash 控制台中文可能乱码 | 测过 `py -3.12` 输出正常 | 读文件优先用 Read 工具而非 `cat` |
| 布局门把 `| M01 |` 当状态行 | 本棒实测（`plan/05` 变异表） | 非状态表用 `V01` / `SPF（M1）` 标签 |
| `argparse` 对缺参 `SystemExit(2)` | 与 `undecidable` 撞语义 | 入口已转成 3；`test_contract` 锁定 |
| `ModuleNotReady` 继承 `InputError` | 措辞会打印成"输入错误" | 已在 `cli.main` 单独捕获，打印"尚未实现" |
| 变异靶子随项目进度失效 | M07/M08 一开始找不到 `HANDOFF-M1.md` | 变异脚本里先 `_write_handoff` 构造，再破坏 |

---

## 六、DoD 逐项 checklist（本棒，全部已实测）

- [x] `AGENTS.md` + 布局门 + `plan/00` 装订行（三件齐）
- [x] `plan/00–06` 齐全且各含必需小节
- [x] `pyproject.toml`：`>=3.11`、零运行时依赖、`dynamic` 版本
- [x] `mailvault/`：`constants` / `exits` / `canonical` / `ledger` / `render` / `cli` / `__main__` / `net`
- [x] 四条子命令已注册；未实现 → exit 2（fail-closed）
- [x] `mailvault --version` 可跑
- [x] AST 守门三条 + 断网冒烟 + fixture 卫生 + 禁词（后两条 SKIP 并打印扫描数）
- [x] 布局门变异 11/11 变红；AST 门变异 5/5 变红
- [x] `pytest` 56 passed
- [x] `.gitattributes` / `MANIFEST.in` / `LICENSE` / `.github/workflows/ci.yml`
- [x] 工作流 YAML 本地 `yaml.safe_load` 通过（2 jobs）
- [x] 本文件（HANDOFF-M1）七节齐

**DoD 未达成项（如实登记）**：
- CI 实跑：**未接远端，未跑过**。本地等价校验已列全；首推后需回填 run id。
- Python 3.11 行为：**本机验不了**，以 CI 矩阵为准。

---

## 七、关键命令速查

```bash
# 0) 第一动作：布局门
py -3.12 tools/check_sprint_layout.py

# 1) 门的变异验证（改门/改文档后必跑）
py -3.12 tools/verify_layout_gate.py     # 11/11 必须红
py -3.12 tools/verify_ast_gates.py       # 5/5 必须红

# 2) 各守门
py -3.12 tools/check_no_network.py
py -3.12 tools/check_no_direct_json.py
py -3.12 tools/check_no_clock.py
py -3.12 tools/check_fixture_hygiene.py
py -3.12 tools/check_forbidden_terms.py
py -3.12 tools/offline_smoke.py

# 3) 测试与 CLI
PYTHONUTF8=1 py -3.12 -m pytest
py -3.12 -m mailvault --version
py -3.12 -m mailvault audit --snapshot nope.json --eml nope.eml --query nope.json; echo "exit=$?"

# 4) 只读检查：本棒交付面
git status --short
git ls-files
```
