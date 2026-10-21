# HANDOFF-M2（M1 收尾 → M2 开工）

> 用法（用户侧启动命令）：`/goal 读取 "<项目绝对路径>\plan\HANDOFF-M2.md" 继续完成任务`
> **第一动作 = 跑布局门**：`py -3.12 tools/check_sprint_layout.py`（必须全绿，红了先修布局）。
> 本文件内一律相对路径。

---

## 一、当前进度 + 证据

**已完成：M0（方法论装订 + 骨架）+ M1（数据先行）**，均 2026-10-21。

| 交付 | 证据（实测命令 + 结果） |
|---|---|
| 布局门 | `py -3.12 tools/check_sprint_layout.py` → **全绿**（9 PASS / 0 FAIL / 1 SKIP=RELEASE） |
| 布局门变异 | `py -3.12 tools/verify_layout_gate.py` → **11/11 全部如期变红** |
| AST 守门 | `check_no_network` 12 文件全绿；`check_no_direct_json` 12 文件全绿；`check_no_clock` 13 文件全绿 |
| AST 变异 | `py -3.12 tools/verify_ast_gates.py` → **6/6 全部如期变红**（新增 A06：豁免文件里越界读时钟） |
| fixture 卫生 | `py -3.12 tools/check_fixture_hygiene.py` → PASS 5 份 + EXEMPT 2 份（上游原样件，理由打印） |
| 禁词门 | `py -3.12 tools/check_forbidden_terms.py` → SKIP 0 份（M6 才转真判定） |
| 断网冒烟 | `py -3.12 tools/offline_smoke.py` → 返回值 2、socket 尝试 0、**M1 数据面零 socket** |
| 测试 | `PYTHONUTF8=1 py -3.12 -m pytest` → **178 passed** |
| CLI | `py -3.12 -m mailvault --version` → `mailvault 0.1.0.dev0` |
| **真实抓取** | `snapshot fetch` 对 8.8.8.8 实抓 `example.com` → 3 条查询落盘，可被 `load_snapshot()` 回读 |

**M1 交付面**（新增/改动的代码）：

| 模块 | 内容 |
|---|---|
| `mailvault/snapshot.py` | `snap.json` schema 校验 + `Snapshot.resolve()`（有序列表、首个命中、下标进 trace） |
| `mailvault/query.py` | `query.json` 解析（mail_from / client_ip / helo / trusted_authserv_ids） |
| `mailvault/eml.py` | `.eml` 解析（保序、保留重复头、多 DKIM-Signature、body 原字节） |
| `mailvault/psl.py` | PSL 冻结件读取 + Organizational Domain（普通/通配/例外/默认四规则） |
| `mailvault/net.py` | DNS 客户端（UDP→TCP 回退）+ `fetch_snapshot()` + `utc_now_z()` 时钟豁免 |
| `mailvault/data/` | `public_suffix_list.dat`（338010 B）+ `psl.meta.json`（版本/日期/来源/sha256） |
| `fixtures/spf/` | `rfc7208-tests.yml`（203 用例 / 16 分组）+ `rfc7208-tests.LICENSE` |
| `tests/rfc7208_suite.py` | 测试集 loader + `StubResolver`（离线 DNS 桩）+ `to_snapshot()` |
| `tests/test_inputs.py` / `test_psl.py` / `test_fetch.py` / `test_rfc7208_suite.py` | M1 测试面 |

**未做**：远端仓库、CI 实跑、M2–M6。

---

## 二、当前事实·状态不变量（**动手前必须知道**）

1. **`mailvault/__init__.py::__version__` 是版本唯一真源**。`pyproject.toml` 用 `dynamic`。定版只改这一处。
2. **`mailvault/constants.py` 是全部数值口径的唯一出处**。M1 新增：`DNS_PORT` / `DNS_TIMEOUT_SECONDS` /
   `DNS_MAX_CNAME_HOPS` / `DNS_DEFAULT_RESOLVER` / `DNS_TYPE_BY_NAME` / `DNS_RCODE_BY_VALUE` /
   `DNS_RCODE_TIMEOUT`。M2 的预算常量已在（`SPF_MAX_TERMS` / `SPF_MAX_MX` / `SPF_MAX_PTR` / `SPF_MAX_VOID`）。
3. **`canonical.py` 是全仓唯一 JSON 出口**（K2）。`snapshot fetch` 落盘走 `dump_file`。
4. **网络 import 只在 `net.py`**（K3）。M2 不得碰网络。
5. **时钟豁免精确到函数**（K7 的 M1 修订）：`net.py::utc_now_z` 是**唯一**允许读时钟的位置。
   `tools/check_no_clock.py` 按 AST 的**函数行区间**放行，同文件别处读时钟仍报红（变异 A06 锁定）。
   `tests/test_determinism.py::test_source_has_no_system_clock` 用同一口径。
6. **状态副本 = 4 处**（`plan/00` 里程碑表 / `plan/05` 状态表 / `README.md` 状态行 / `plan/00` 承诺-证据台账）。
   翻状态**四处一起改**。
7. **`plan/05` 与 `plan/06` 的表格首列不要用 `| M<n> |` 形态**做非状态用途——布局门会误判。
8. **未实现的能力必须 fail-closed 到 2**。`audit` 目前仍是 `ModuleNotReady` → 2。
9. **`requires-python = ">=3.11"`，本机无 3.11**（只有 3.8.8 / 3.12.10）。一律 `py -3.12`。
10. **本仓库无远端**。DoD 里不许写"CI 绿"。
11. **运行时零第三方依赖**：`pyyaml` 只在 `dev` extra，**只给 `tests/rfc7208_suite.py` 用**。
    `mailvault/` 包内零 `import yaml`，由 `test_runtime_has_no_third_party_imports` 扫描断言（新增）。
    **M2 写 `modules/spf.py` 时不得 import yaml。**
12. **"没查过" ≠ "没有"**（`plan/04` §2.3）：`Resolved.found=False` 表示快照里没有这条查询，
    `found=True, rcode="NXDOMAIN"` 才是"查过、不存在"。M2 求值时撞上 `found=False` 必须记数据缺口，
    **不得**当成"没有 SPF 记录 → none"。

---

## 三、下一棒待办（M2：SPF 求值器）

按 `plan/05` §2 的 M2 DoD 与 `plan/03` §3.2：

1. **`mailvault/modules/spf.py`**：`check_host(snap, ip, domain, helo, *, budget, trace) -> SpfResult`
   - `result` 七值全覆盖（`none/neutral/pass/fail/softfail/temperror/permerror`）+ `undecidable` 语义；
   - 机制：`all` / `include` / `a` / `mx` / `ptr` / `ip4` / `ip6` / `exists`；
   - 修饰符：`redirect=` / `exp=`；
   - 宏展开（RFC 7208 §7）：`%{s}` `%{l}` `%{o}` `%{d}` `%{i}` `%{p}` `%{v}` `%{h}`；
     **`%{p}` 缺 PTR 必须 `undecidable`，不得默认 fail**（灰区 4）。
2. **`Budget`**（可变对象）：每消费一格记 `(kind, node_id, ref)`；超限**不抛异常**，
   在结果上标 `limit_hit`。term/MX/PTR 超限 → permerror（MUST）；void 超限 → `undecidable` + 告警（SHOULD）。
3. **include 树完整展开**：不因第 11 个截断；每节点带 `consumes_term` / `receiver_would_stop_here`
   （第 11 个起 true）。节点 id：根 `n0`，第 i 个 include `n<i>`，嵌套 `n<i>.<j>`（K12）。
4. **RFC 7208 测试集 runner**：用 `tests/rfc7208_suite.py` 的 `Case` / `to_snapshot()`；
   203 条逐条跑，通过率 ≥ 95%；失败逐条登记 `data/rfc7208-failures.md`（用例 id / 期望 / 实际 / 原因 / 是否口径差异）。
   **注意**：`to_snapshot()` 目前只把 TXT 与 include/redirect 目标落进快照。
   M2 若需要 A/MX/AAAA/PTR 查询，**要给 `to_snapshot()` 增加这些 qtype**（按用例 `zonedata` 里实际出现的类型），
   而不是在求值器里"没查到就当作无记录"。
5. **两次运行字节级一致**：`verdict.json` sha256 比对（`ledger.assemble` 已支持）。
6. **断网环境 `mailvault audit` 成功**：把 `cli._cmd_audit` 接上 SPF，返回真实退出码；
   同时把 `tools/offline_smoke.py` 的断言收紧（现在允许 0/1/2/3，M2 起应能固定断言某个真实码）。
7. **测试**：`tests/test_spf.py`（runner 通过率、预算逐格、include 树切点、宏、`%{p}` 缺 PTR → undecidable）。

---

## 四、既定口径清单（K 编号，动了会打挂测试）

| # | 口径 | 守在哪 |
|---|---|---|
| K1 | 退出码只在 `exits.py`；优先级 `4>3>2>1>0` | `tests/test_contract.py` |
| K2 | `json.dumps` 只在 `canonical.py` | `tools/check_no_direct_json.py` |
| K3 | 网络 import 只在 `net.py` | `tools/check_no_network.py` |
| K4 | 结果枚举只在 `constants.RESULTS`；`undecidable` 不折叠成 `fail` | `test_contract` / `test_ledger` |
| K5 | `evidence_ref` 缺失 → 构造期降级 `undecidable` | `ledger.check_entry` + `test_ledger` |
| K6 | `schema_version` 单点定义；未知版本 → exit 3 | `constants` + `tests/test_inputs.py`（M1 已落） |
| K7 | 零系统时钟；**唯一豁免 `net.py::utc_now_z`**（函数级） | `tools/check_no_clock.py` + `test_determinism` |
| K8 | 比率 = 6 位定点字符串；账本内无裸浮点 | `canonical.fixed6` + `dumps` 拒浮点 |
| K9 | 账本内无绝对路径 | `render._assert_no_absolute_path` |
| K10 | `--strict-evidence` 禁词表 | `render.STRICT_FORBIDDEN` + `check_forbidden_terms` |
| K11 | fixture 只用保留域 / 文档 IP 段；上游原样件逐条登记豁免 | `tools/check_fixture_hygiene.py`（M1 已落地） |
| K12 | 判定节点 id 稳定（`n0`, `n0.1`），不依赖遍历顺序 | 各模块测试 |

---

## 五、本机环境坑（全部实测）

| 坑 | 实测 | 处置 |
|---|---|---|
| `python` 是商店占位符 | — | 一律 `py -3.12` |
| 无 Python 3.11 | `py -0p` → 3.8.8-64 / 3.12.10-64 | 3.11 行为以 CI 为准 |
| `raw.githubusercontent.com` **被重置**（WinError 10054 / curl 35） | 实测拿不到 pyspf 单文件 | 用 `codeload.github.com/.../zip/refs/heads/master` 取整个仓库再解包 |
| `publicsuffix.org` 可直连 | `curl` http=200，338010 B | 直接取 |
| Git Bash `/tmp` 与 Python 的路径认知不一致 | `py -3.12` 看不到 `/tmp/x` | 用 `cygpath -w` 转换，或直接用 `$TEMP` |
| 布局门变异靶子随进度失效（M06 曾写死 M1） | M1 变 ✅ 后"M1 翻成完成"是无操作 | 变异脚本改为**探测当前待办里程碑**；靶子找不到就断言失败 |
| fixture 卫生门会扫 `fixtures/*/README.md` | 我在 README 里引用上游真实 IP 导致自己变红 | 文档里描述上游件时**不要写字面 IP**，用文字转述 |
| `argparse` 缺参 `SystemExit(2)` | 与 `undecidable` 撞语义 | 入口已转 3；`test_contract` 锁定 |
| `ModuleNotReady` 继承 `InputError` | 措辞会打印成"输入错误" | `cli.main` 单独捕获，打印"尚未实现" |

---

## 六、DoD 逐项 checklist（本棒，全部已实测）

- [x] `snap.json` schema 定稿，`SNAPSHOT_SCHEMA_VERSION` 单点定义（`constants.py`）
- [x] `queries` 有序列表；`resolve()` 首个命中 + 下标进 trace；同键多次查询可见
- [x] `rcode` 非 NOERROR 带 answer → `InputError`
- [x] 缺 `psl_version` / `psl_date` → `InputError`；未知 `schema_version` → `InputError`（列支持版本）
- [x] `query.json` 解析（未知字段拒绝；空发件人合法；IP 校验）
- [x] `.eml` 解析（保序、重复头、多 DKIM-Signature、body 原字节）
- [x] `snapshot fetch` 实现（UDP→TCP 回退、CNAME 指针、TXT 分段拼接、MX/PTR/AAAA）
- [x] `snapshot fetch` **实抓验证**：对 8.8.8.8 抓 `example.com`，3 条查询落盘并可回读
- [x] 时钟豁免写进 `tools/check_no_clock.py`（函数级）+ `test_determinism` 同口径 + 变异 A06
- [x] RFC 7208 测试集入仓（203 用例 / 16 分组）+ LICENSE（版权声明在）
- [x] 本地 runner 能读（`tests/rfc7208_suite.py`），`StubResolver` 与 pyspf driver 语义对齐
- [x] 断网下测试集能跑（桩是纯内存查表；`offline_smoke` 断言 M1 数据面零 socket）
- [x] PSL 冻结件入仓（`.dat` + meta：版本/日期/来源/sha256），每次加载复核 sha256
- [x] `mailvault/psl.py`：四规则（普通/通配/例外/默认）+ Organizational Domain
- [x] fixture 卫生门从 SKIP 转真判定，能跑红；上游原样件逐条豁免并打印理由
- [x] 运行时零第三方依赖（新增扫描断言；pyyaml 只在 dev extra）
- [x] `pytest` 178 passed
- [x] 布局门全绿；布局变异 11/11；AST 变异 6/6

**DoD 未达成项（如实登记）**：
- CI 实跑：**未接远端，未跑过**。首推后需回填 run id。
- Python 3.11 行为：**本机验不了**，以 CI 矩阵为准。
- RFC 7208 **通过率**：M2 才实现求值器，本轮**未跑**（只证明"能读、能转快照、桩语义对"）。
- `snapshot fetch` 的 **DoH 通道**：未实现（只有 UDP/TCP 53）。README 未承诺 DoH。

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
py -3.12 -m mailvault --version
py -3.12 -m mailvault audit --snapshot nope.json --eml nope.eml --query nope.json; echo "exit=$?"

# 4) 真实抓取（唯一联网动作；需要网络）
py -3.12 -m mailvault snapshot fetch --eml m.eml --query q.json -o snap.json

# 5) 只读检查：本棒交付面
git status --short
git ls-files
```
