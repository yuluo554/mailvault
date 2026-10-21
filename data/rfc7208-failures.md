# RFC 7208 测试集失败与口径差异登记（M2）

> **纪律**（`plan/04` §2.1）：**不得为了"让用例通过"而改写上游期望值**。
> 口径差异逐条登记在这里，每条带四要素：用例 id / 期望 / 实际 / 原因，并标明是否口径差异。

---

## 1 本次实跑

| 项 | 值 |
|---|---|
| 测试集 | `fixtures/spf/rfc7208-tests.yml`（openspf.org release 2014.04，pyspf 原样副本） |
| 用例数 | **203**（16 分组） |
| 通过 | **202** |
| 失败 | **1**（已登记口径差异，见 §3） |
| 通过率 | **99.5%**（DoD 门槛 95%） |
| 复跑命令 | `PYTHONUTF8=1 py -3.12 -m pytest tests/test_spf.py -k pass_rate` |
| 参照实现 | pyspf 2.0.14 的 `check_host`，**仅开发期核对语义**，运行时零依赖（由 `test_runtime_does_not_import_reference_implementation` 断言） |

**参照实现自身的对照结果**：同一份测试集用 pyspf 2.0.14 跑，203/203 全通过。
这说明本项目的 1 条失败**不是夹具不全或桩语义错**，而是刻意的口径选择。

---

## 2 三条语义更正（本棒实测后改口径）

以下三条在 `plan/04` §3 的早期表格里写法不准确，本棒以 RFC 7208 原文为准更正，
并把依据写进代码注释与测试断言。它们**不产生失败用例**，但属于"口径变了"，
所以一并登记——否则下次读表的人会以为代码写错了。

### 2.1 PTR 超限：截断，不是 permerror

| 项 | 内容 |
|---|---|
| 早期写法 | `plan/04` §3 表格：PTR 机制单次上限 10 条，超限 → `permerror`（MUST） |
| RFC 7208 §4.6.4 原文 | 每条 PTR 记录"MUST NOT result in querying more than 10 address records"；"If this limit is exceeded, **all records other than the first 10 MUST be ignored**" |
| §5.5 补充 | 反向查询超过上限时，`ptr` 机制按**未匹配**处理 |
| 本项目实现 | **截断到前 10 条** + 在 `warnings` 写明截断了几条；不判 permerror |
| 佐证 | 上游用例 `Processing limits/ptr-limit` 期望 `neutral` / `pass`——若是 permerror，这条用例的期望值就该是 permerror |
| 为什么 MX 与 PTR 不同 | RFC 明说：MX 数据归**发布方**控制（所以可以要求发布方修），PTR 数据归**连接 IP 的所有者**控制（所以只能截断，不能因别人的数据判你坏） |

### 2.2 void 超限：SHOULD 级限制，本项目判 `undecidable`

见 §3.1（它产生了本次唯一的失败用例）。

### 2.3 `%{p}` 缺 PTR：展开成 `unknown`，不判 fail

| 项 | 内容 |
|---|---|
| RFC 7208 §7.3 | 没有可验证的 PTR 名时，`p` 宏展开为字符串 `unknown`；DNS 出错时同样 |
| 题面 §2.5 灰区 4 | `%{p}` 依赖 PTR，缺 PTR 必须 `undecidable`，不得默认 fail |
| 本项目实现 | 展开仍按 §7.3 走（`unknown`）；若**最终结果由含 `%{p}` 的机制匹配决定**，则降级为 `undecidable` 并写明原因 |
| 边界 | 只做诊断的 `%{p}`（`exp=` 文本里、或未匹配的机制）**不**触发降级——否则一个纯展示用的宏会把整条判定拖成不可判定 |

---

## 3 失败用例逐条登记

### 3.1 `Processing limits/void-over-limit`

| 项 | 内容 |
|---|---|
| 用例 id | `Processing limits/void-over-limit` |
| spec | `4.6.4/7` |
| 输入 | `mailfrom: foo@e11.example.com`，`host: 1.2.3.4`，记录 `v=spf1 a:err.example.com a:err1.example.com a:err2.example.com ?all` |
| **期望** | `permerror` |
| **实际** | `undecidable` |
| **是否口径差异** | **是**（有意为之，非缺陷） |
| **原因** | RFC 7208 §4.6.4 关于 void 的原文是 "SPF implementations **SHOULD** limit 'void lookups' to two"，是 SHOULD 而非 MUST。题面 §2.5 灰区 2 明确要求"void 超限不得硬判 fail/错"，本项目据此判 `undecidable` + 告警。 |
| 为什么不跟上游走 | 若判 `permerror`，等于把一个 **SHOULD 级**实现选择冒充成**协议结论**：记录作者看到 permerror 会以为自己写错了，而实际上只是本实现选了更严格的限额。`undecidable` + "void 超限（SHOULD）"的告警，才是"我判不了"而不是"你错了"。 |
| 用户会看到什么 | `result: undecidable`；`gray_areas` 里一条"void lookup 超过 2 次（RFC 7208 §4.6.4 的**限制**是 SHOULD，不是 MUST）；本项目按题面 §2.5 灰区 2 判 undecidable 而非 permerror。超限处：err2.example.com/A" |
| 若将来要改口径 | 把 `check_host` 里 `void_exceeded` 的分支从 `undecidable` 改成 `permerror`，并同步改 `tests/test_spf.py::test_void_limit_exceeded_is_undecidable_not_permerror` 与本表。**不要**只改代码。 |

**同族用例的处理（全部通过）**：

| 用例 | 期望 | 实际 | 说明 |
|---|---|---|---|
| `Processing limits/void-at-limit` | `neutral` | `neutral` | 恰好 2 次 void 不算超限 |
| `Processing limits/mech-over-limit` | `permerror` | `permerror` | 同时踩了 term（MUST）与 void（SHOULD）→ **MUST 优先** |

> `mech-over-limit` 这条是本棒特意核对的边界：它同时踩两条限制。若实现"一撞 void 就返回
> undecidable"，这条会假失败。正确做法是 **MUST 级结论优先**——那条记录无论实现怎么选
> 都是坏的，报 permerror 更站得住。代码里的 `void_exceeded` 因此只置位、不提前返回。

---

## 4 未列入失败、但值得记录的边界

| 现象 | 处理 | 依据 |
|---|---|---|
| `Initial processing/spftimeout`（TXT 有记录、SPF 查询超时） | 返回 `fail`（按 TXT 结果），**不是** temperror | 上游 driver 的 `timeout` 局部标志语义：一旦拿到同类型值就不再算超时。`tests/rfc7208_suite.py::StubResolver._collect` 照此实现 |
| `A mechanism syntax/a-colon-domain`（domain-spec 含冒号/斜杠） | 正常查（能查到就 pass） | 名字合法性只判"标签非空且 ≤63 字节"，**不**限制字符集。按字符集拦会把这条判错 |
| `Record evaluation/detect-errors-anywhere` | `permerror`（即使前面有机制匹配） | §4.6：先全量校验、后求值。求值器分两遍走就是为了这条 |
| `Macro expansion rules/invalid-hello-macro` | `fail`（不是 `undecidable`） | 宏展开出的非法域名按"查不到"处理，是**协议结论**，不是数据缺口 |
| `Test cases from implementation bugs/cname-aliasing` | `fail` | 同一个 TXT 经两条 CNAME 别名被看到两次 → 多条记录 → permerror 分支；上游期望 fail（见 `multispf1` 的多值口径） |

---

## 5 复算方式

```bash
# 只看通过率（DoD 门槛 95%）
PYTHONUTF8=1 py -3.12 -m pytest tests/test_spf.py -k pass_rate -q

# 看全部 SPF 测试
PYTHONUTF8=1 py -3.12 -m pytest tests/test_spf.py -q

# 打印逐条失败（不经 pytest 的断言过滤）
PYTHONUTF8=1 py -3.12 -c "
import sys; sys.path[:0] = ['tests', '.']
import rfc7208_suite as S
from mailvault.modules.spf import check_host
suite = S.load_suite()
for case in suite.cases:
    local, _, domain = case.mailfrom.partition('@')
    result = S.run_case(case, lambda snap: check_host(
        snap, case.host, domain or case.helo, case.helo,
        local=local or None, sender=case.mailfrom or None))
    if not case.accepts(result.result):
        print(case.case_id, '期望', case.acceptable, '实得', result.result)
"
```

**登记表的自检**：`tests/test_spf.py` 里三条断言盯着这份文件——

1. `test_failures_doc_lists_every_divergence`：`KNOWN_DIVERGENCES` 里每一条都必须在本文件出现，且本文件必须有"期望/实际/原因/口径差异"四类字段；
2. `test_every_known_divergence_actually_happens`：登记了差异但实际已一致 → 测试失败（防"僵尸条目"）；
3. `test_failures_doc_records_pass_rate`：本文件必须写清 203 / 202 / 99.5% 这组数，否则读者无法判断它是哪一版的快照。
