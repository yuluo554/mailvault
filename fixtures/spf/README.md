# fixtures/spf —— SPF 判定样本

本组证两件事：**RFC 7208 测试集能跑**，以及**预算账本能逐格读**。

## 内容

| 文件 | 作用 | 状态 |
|---|---|---|
| `rfc7208-tests.yml` | pyspf 上游测试集（**203 个 `spec:` 用例 / 16 分组**），原样入仓 | ✅ M1 |
| `rfc7208-tests.LICENSE` | 上游 BSD 式许可，**必须保留** | ✅ M1 |
| `../../data/rfc7208-failures.md` | 实跑结果 + 失败/口径差异逐条登记（M2 产出） | ✅ M2 |

读取与离线跑：`tests/rfc7208_suite.py`（`load_suite()` / `StubResolver` / `to_snapshot()` / `run_case()`）。

## M2 实跑结果

| 项 | 值 |
|---|---|
| 用例数 | 203 |
| 通过 | 202 |
| 通过率 | **99.5%**（DoD 门槛 95%） |
| 失败 | 1 条，已登记为口径差异（`Processing limits/void-over-limit`） |
| 复跑 | `PYTHONUTF8=1 py -3.12 -m pytest tests/test_spf.py -k pass_rate` |

`run_case()` 为什么**迭代**：宏展开后的查询名（`%{i}.%{l2r-}.user.%{d2}` 之类）事先算不出来，
静态清单必然漏。求值器撞上没查过的键时会如实报 `data_gap`（`plan/04` §2.3 要求"没查过"
不许当成"没有"），`run_case()` 把它补进快照再重跑，直到收敛。**补进去的每一项都是桩真实
答复过的**，不是猜的——所以通过率不会因为夹具"自动补全"而虚高。

## 上游件的豁免登记（K11）

`rfc7208-tests.yml` 与 `rfc7208-tests.LICENSE` **原样保留**，因此
`tools/check_fixture_hygiene.py` 对它们登记了 `EXEMPT_FILES` 豁免。理由逐条：

| 文件 | 为什么不能改 |
|---|---|
| `rfc7208-tests.yml` | 上游 `rfc7208-tests.CHANGES` 明确承认早期用例里用了真实全球 IP（作者自述 "that is a real global IP"）——这是历史遗留。改写会把 203 条用例的输入与期望一起改掉，测试集就不再是"上游那一版"。 |
| `rfc7208-tests.LICENSE` | 许可第 1 条要求"保留原始版权声明"，声明里含作者域名（`bmsi.com` / `mehnle.net` / `kitterman.com`）。改写即违约。 |

**豁免只到这两份文件本身**。其它任何 fixture 引用真实域名 / 非文档 IP 段依然报红。
门的输出里会打印"豁免了哪几份、为什么"——不是静默跳过。

## 纪律

- 测试集里的域名与 IP **只作为 DNS 桩数据**，不发起任何查询（`StubResolver` 是纯内存查表）。
- 所有 `snap.json` 的 `resolver` 必须是 `synthetic`，`fetched_at` 为合成时间。
- **不得为了"让用例通过"而改写上游期望值**；口径差异逐条登记到 `data/rfc7208-failures.md`。
- 上游有 4 条用例的 `result` 是**多值**（如 `[fail, permerror]`）——两种结果都算通过，不得折叠成一个。
- 上游有一条 `strict: 2`（`bytes-bug`）：非 strict 语义要保留，`Case.strict` 存原值、
  `Case.is_strict` 给布尔判断。
- 上游 `zonedata` 里 `SPF` 记录在"该名字没有 TXT"时会**合成**一条同名 TXT
  （pyspf driver 行为，测试集有分组依赖它）；`NONE` 哨兵表示"查了但没有"（不是 NXDOMAIN）。
- **驱动的 `timeout` 是逐次查询的局部标志**（上游 `testspf.DNSLookup` 同名变量）：
  一旦本次查询拿到同类型的值就不再算超时。整域一律判超时会让 `spftimeout` 那条假失败。
