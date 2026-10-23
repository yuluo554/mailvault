# plan/RELEASE-M6 —— `v1.0.0` 发布留档

> **两栏口径**（`plan/05` §4.3）：第一栏写**tag 树内可以自洽**的事实；tag 之后才知道的
> 字面值（tag 的 OID、源码包 sha256、CI run id、Release 页 URL）写进第二栏。
> **自指的东西不许写进 tag 树**——写一次、tag 一次就失效一次。
>
> 本文件由布局门的 `LAYOUT.RELEASE` 逐条断言：两栏 + `覆盖对账` 小节 + 三态行 ≥3。

---

## 一、tag 前事实

### 1.1 版本（三处一致）

| 处 | 值 |
|---|---|
| `mailvault/__init__.py::__version__`（唯一真源） | `1.0.0` |
| `pyproject.toml` | `dynamic = ["version"]` + `attr = "mailvault.__version__"`（不写第二份） |
| `README.md` 状态行 | 版本 `v1.0.0` |

一条测试同时断言三处：`tests/test_version_consistency.py`（4 条）。

### 1.2 归档样例（原 `SKIP` 的禁词门在此转为真判定）

`examples/` 放 4 个用例、10 份真产物，**全部用真 CLI 跑真 fixture 生成**并带
`--strict-evidence`（`tools/gen_examples.py`，`--check` 逐字节幂等）：

| 目录 | 命令 | 展示 | 退出码 |
|---|---|---|---|
| `reconcile-r2-gateway-body/` | `audit` | 矛盾 → `cross_check` undecidable + 每条 ≥2 解释与各自 verify | `2` |
| `dmarc-b41/` | `audit` | 干净 pass（RFC 9989 B.4.1 的 tree walk 复现例） | `0` |
| `whatif-spf-tighten/` | `whatif` | 差分：`?all` → `-all` 让退出码 0 翻成 1 | `1` |
| `diff-p-reject/` | `diff` | 两份真账本的结构差分（附 baseline / candidate） | `0` |

### 1.3 fixture 清单（五组）

| 组 | 内容 | 计数 |
|---|---|---|
| `fixtures/spf/` | RFC 7208 上游测试集（原样件，含 LICENSE）+ 豁免登记 | 203 用例（1 文件 + 1 许可） |
| `fixtures/dkim/` | 正样本 + 五类失败 + 多签名 / 未签名 / 缺标签 / `l=` 超长 + 测试密钥 | 12 目录 |
| `fixtures/dmarc/` | B.4.1 / B.4.2 / B.4.3 + `psd=n` + `np` + `pct` | 6 目录 |
| `fixtures/reconcile/` | 一致 / 矛盾 / 无法判定（三分类都有样本） | 3 目录 |
| `fixtures/whatif/` | `spf-tighten` / `p-reject` + `rua.json` + `changes.json` | 2 目录 |

### 1.4 随包冻结件

| 项 | 值 |
|---|---|
| PSL 版本 | `2026-10-20_08-40-56_UTC` |
| PSL 日期 | `2026-10-20` |
| PSL sha256 | `8228e4bdac6024c058a1e67859157e468a2613b826b53de0e5cae298e1b70755` |
| 来源 | publicsuffix.org 列表（MPL 2.0）；运行时只读本文件，**禁止联网更新** |

### 1.5 脱敏四步（`plan/05` §4）

| 步 | 判据 | 实测 |
|---|---|---|
| ① 产物扫描（禁词门） | `tools/check_forbidden_terms.py` | **PASS 11 份**（含 `examples/README.md`）；不再是 `SKIP` |
| ② `fixtures/` + `examples/` 无真实域名/私有路径 | `tools/check_fixture_hygiene.py` | **PASS 108 份**（另 2 份上游原样件逐条豁免并打印理由） |
| ③ 账本无绝对路径（K9） | `render._assert_no_absolute_path` + `tests/test_examples.py` 直扫样例产物 | PASS（无盘符 / 家目录形态） |
| ④ 样例产物版本绑定 | `tests/test_examples.py::test_examples_carry_the_current_tool_version` | PASS（每份账本 `tool_version == 1.0.0`） |

M6 为第②步把卫生门的扫描面从 `fixtures/` 扩到 `fixtures/ + examples/`，并新增两条
**结构性剥离**（标识符命名空间 + RFC 引用）——都是"剥前缀后剩余部分照旧被扫"，
不是放宽判据（阳性对照见 `tests/test_hygiene.py`）。

### 1.6 tag 前门结果

| 门 | 结果 |
|---|---|
| 布局门 `check_sprint_layout.py` | **8 PASS / 0 FAIL / 1 SKIP**（`LAYOUT.RELEASE` 因 M6 尚未 ✅ 报 SKIP，属预期） |
| 布局门变异 `verify_layout_gate.py` | **11/11** 如期变红 |
| AST 变异 `verify_ast_gates.py` | **6/6** 如期变红 |
| 语义变异 `verify_module_mutations.py` | **11/11** 如期变红 |
| AST 守门（网络 / 裸 JSON / 时钟） | 21 / 21 / 22 源文件全绿 |
| 卫生门 / 禁词门 / 断网冒烟 | 全绿（禁词门真判定） |
| `pytest` | **470 passed** |
| 生成器幂等 `--check` | 四个 fixture 生成器 + `gen_examples.py` 全部逐字节一致 |

### 1.7 干净环境验证（tag 前，本地）

口径与 M5 的 bare 仓库 round-trip 相同：把**已提交的树**导到一个临时目录（`git archive`
口径，`export-ignore` 与 `.gitattributes` 一并生效），再在那个目录里直跑测试与全部门。
它验的是"**交付树自足**"——不依赖工作区里没入仓的文件、不依赖 `.git` 元数据。

| 项 | 结果 |
|---|---|
| 导出方式 ① | `git archive HEAD \| tar -x` 到临时目录（**无 `.git`**，`.gitattributes` 与 `-text` 规则一并生效） |
| 导出方式 ② | 本地 `git clone --bare` → `git clone` round-trip（走完整索引/属性链） |
| `.eml` 字节 | 两种形态都保住 CRLF（`r2-gateway-body` 25/25、`p-reject` 10/10、`b41` 16/16） |
| `mailvault --version` | `mailvault 1.0.0` |
| `pytest` | **470 passed**（两种形态一致） |
| 布局门 + 三类变异 | 全绿 / **11/11** / **8/8** / **11/11** |
| 六条守门 | 网络 · 裸 JSON · 时钟 · 卫生 · 禁词 · 断网冒烟 全部全绿 |
| 发布门 `--offline` | 全绿（7 条判据） |
| 生成器 `--check` | 5 个（dkim / dmarc / reconcile / whatif / examples）全部逐字节一致 |
| 汇总 | **18/18 项通过**（两种形态各跑一遍） |

> 这一步证明的是"**交付树自足**"：不依赖工作区里没入仓的文件、不依赖 `.git` 元数据。
> 它**不替代** V6 的"发布件真下载 + 解包"复核——那一步要等 tag 与 Release 在远端。

---

## 二、tag 后追加

> 本节在 `v1.0.0` 打出**之后**填写。tag 树内的留档**不含**这些字面值（自指）。

### 2.1 首推 CI 实录与一处**只在远端才显形**的缺陷

首推 `main`（run **39526291036**）的结果是「**四个测试矩阵全绿 + 一个 job 红**」：

| job | 结果 |
|---|---|
| `py3.11 · ubuntu-latest` | ✅ 全步骤 success（含发布门 `--offline`） |
| `py3.11 · windows-latest` | ✅ |
| `py3.13 · ubuntu-latest` | ✅ |
| `py3.13 · windows-latest` | ✅ |
| `offline no-network job` | ❌ 挂在 `Initialize containers`（**没有跑到任何一条判据**） |

**根因**（日志原文）：

```
docker: conflicting options: cannot attach both user-defined and non-user-defined
network-modes
Exit code 125 returned from process: file name '/usr/bin/docker'
```

Actions 创建 **job 容器**时总是先建一个 user-defined network，再叠加
`container.options: --network none` 就成了互斥选项。**这个缺陷在本机永远看不出来**
（本机没有 docker，也不走 Actions 的容器模型），是 V1「CI 实跑」这一条的第一个真实产出。

**修法**（`ci.yml` 的 `offline` job 重写）：不把 job 放进容器，改用普通 runner +
`docker run --network none` 起**嵌套**容器（`--network none` 只在 `docker run` 这一层合法）；
镜像由新增的 `.github/offline.Dockerfile` 构建。运行期完全无网络，正是要证明的那件事。
另加一条"零第三方 import（无任何安装步骤）"的断言，让"运行时零依赖"在无网络容器里再证一次。

### 2.2 回填

| 项 | 值 |
|---|---|
| CI run id（`main` 首推，**红**） | `39526291036` |
| CI run id（tag `v1.0.0` 首推，**红**） | `39526365982` |
| CI run id（修复后 `main`） | `39526981564` |
| CI run id（修复后 tag `v1.0.0` 重指） | `39527171060` |
| CI run id（收尾提交 `d76829c`） | `39528967472` |
| CI run id（计数更新提交 `858f944`） | `39529331411` |
| push 数 = run 数 | `6 = 6` |
| 计数截至提交 | `858f944`（此后只改文档；「每次 push 恰好一条 run」这个不变量由 `--online` 断言，不再靠改数字维持） |
| 远端 | `git@github.com:yuluo554/mailvault.git`（公开） |
| GitHub Release | https://github.com/yuluo554/mailvault/releases/tag/v1.0.0 |
| tag OID（annotated tag 对象） | `fbbd25fc10375e3affcb8ca995e020a98c9fe0ba` |
| tag 提交 OID | `c84b0c85376aabbcecbdc646d02c6002b3430400` |
| 源码包 sha256（`mailvault-1.0.0.tar.gz`） | `4140fcf97e2c36a9b1498745371424ab99dd988cf8128a445b7c37a5928df524`（497 992 字节） |

**tag 重指说明**：`v1.0.0` 首次指向 `195b68d`（CI 一红），按用户决定修完 `ci.yml` 后
`git push --force` 重指到 `c84b0c8`。重指前该 tag **没有** Release、无人消费；
重指后 tag run `39527171060` 五个 job 全绿。**交付面（`mailvault/` 与 `pyproject.toml`）
在两次 tag 之间零差异**——改的只有 `.github/` 与 `plan/`。

### 2.3 CI 实录（修复后）

| run | 事件 | 提交 | 结果 |
|---|---|---|---|
| `39526981564` | push `main` | `c84b0c8` | ✅ 5/5 job（四矩阵 + offline 嵌套容器） |
| `39527171060` | push `v1.0.0` | `c84b0c8` | ✅ 5/5 job |
| `39528967472` | push `main`（收尾提交，只动非交付面） | `d76829c` | ✅ 5/5 job |

每个 job 内**发布门 `--offline`** 与 `pytest`（470 passed）均为 success；
offline job 在 `docker run --network none` 里跑 `offline_smoke` + 发布门 + 零第三方 import 断言。
收尾提交 `d76829c` 相对 tag **只动** `plan/` `README` `tools/`（`POST_TAG_SCOPE`）；
`mailvault/`（源码）相对 `v1.0.0` **零差异**（`DELIVERABLE_UNCHANGED`）。
`pyproject.toml` 在其后的 `bb19d9e` 有 4 行改动（PEP 639：`setuptools>=68`→`>=77`、
`license={text}`→SPDX 表达式、删 `License::` classifier、加 `license-files`）——
**不影响运行行为**（`mailvault/` 零差异），属于跨仓统一的技术债修复。
这一处偏差**不隐藏**：`tools/check_release.py` 的「交付面未被改动」判据把它逐条比对，
只放行**这一处已登记**的 hunk（见 §2.6）。

### 2.4 发布件复核（V6：真下载 + 解包）

| 步 | 实测 |
|---|---|
| `gh release download v1.0.0` | 497 992 字节 |
| sha256 | `4140fcf9…8df524`，与本地 `git archive` 逐字节相同；GitHub 记录的 asset digest 也相同 |
| 解包后跑 18 项 | **18/18 全绿**（`pytest` 470 passed、三类变异、六条守门、发布门 `--offline`、五个生成器 `--check`） |
| `.eml` 字节 | 解包后 CRLF 仍在（`r2` 25/25、`p-reject` 10/10） |

### 2.5 发布门三态实测

| 模式 | 跑在 | 实测 |
|---|---|---|
| `--offline` | CI 两个 job + 本机 | **全绿**（**9** 条判据；不碰网络，`--network none` 容器里也全绿） |
| `--pre-tag` | tag **之前**（本机） | tag 前全绿（**11** 条）；**tag 之后必然红**（`tag 尚未创建` 已不成立）——这正是三态分开的意义 |
| `--online` | 推送 / Release **之后**（本机） | **全绿**（**21** 条判据） |

> 判据条数是 **2026-10-23 实测**（补上 §2.6 的两条交付面判据之后）。tag 当时的条数是
> `--offline` 7 / `--pre-tag` 9 / `--online` 19 —— 那三个数字保留在 §1.6 与 §2.4 的历史记录里。

`--online` 的关键判据（不是"所有历史 run 都绿"——历史不可变，那样写只会得到一条永远红、
然后被人删掉的假门）：

| 判据 | 实测 |
|---|---|
| **认证发布树的 run 全绿** | tag 提交 `c84b0c8` 上的 run `39526981564` / `39527171060` **均 success** |
| **历史失败逐条登记** | 首推的 2 条红 run（`39526291036` / `39526365982`）**都在留档里**；漏记即红 |
| **每次 push 恰好一条 run** | 6 次 push 各一条（按「提交 + ref」去重：同一提交既作 `main` HEAD 又作 tag 指向，就该有两条 run） |
| **计数锚在可核对的提交上** | `计数截至提交` = `858f944`，仓库里真实存在 |

**一处自指陷阱（值得记）**：`push 数 = run 数` 写成绝对数字后，**每改一次文档就会让它 +1**，
于是每推一次就要再改一次数字、再推一次——这正是"tag 树内不写自指字面值"那条纪律在计数上的翻版。
处置：判据改落在**不变量**上（每次 push 恰好一条 run、两个数字彼此相等、计数锚在一个可核对的提交上），
绝对数字只作为**截至某提交的快照**保留。

### 2.6 交付面偏差登记（`DELIVERABLE_UNCHANGED` 的机器判据与它放行的那一处）

`AGENTS.md` 硬性纪律第 1 条把「在 tag 之后改交付面（`mailvault/`、`pyproject.toml`）」列为禁止项。
此前**没有任何机器判据**盯着它：`check_release.py --offline` 在仓库 HEAD 与 tag 导出树里都报全绿，
于是 §2.3 那句「`pyproject.toml` 零差异」过期后无人发现（`bb19d9e`）。

**2026-10-23 补上的判据**（`tools/check_release.py::deliverable_checks`，三档共用）：

| 判据 | 判什么 | 怎么才算红 |
|---|---|---|
| **交付面未被改动** | `git diff --name-only <最近tag>..HEAD -- mailvault pyproject.toml` 必须为空，除非该文件在 `REGISTERED_DEVIATIONS` 里 | 出现未登记的文件；或已登记文件的**工作区 blob OID 与登记值不等**（再改一个字节就红） |
| **登记偏差无僵尸条目** | 每条登记都必须**仍然存在** | 登记路径相对 tag 已无差异（例如下次发版把它正规化进了 tag）→ 登记行须一并删除 |
| 无 `.git` 工作树（sdist 解包树） | 显式 **SKIP** | 不适用 ≠ 通过：输出里单列 SKIP 行，且「这轮跑了 N 条判据」不计它 |
| 浅克隆（`--is-shallow-repository` = true） | **FAIL** | 历史被截断会让判据**空验成绿**；修法是 `actions/checkout` 的 `fetch-depth: 0` + `fetch-tags: true`（CI 已加） |

**为什么登记的是 blob OID 而不是路径**：路径级白名单会把整份文件永久放行，之后对该文件的任何改动
都看不见——那正是本判据要防的事。登记 `c756dfc4…`（`pyproject.toml` 当前工作区 blob）之后，
只放行**这一处已知偏差**；再改一个字 hash 就变、判据立刻红（实测阳性对照，见 `update/03-执行记录.md`）。

**放行的那一处偏差**：

| 路径 | tag 上的 blob | 放行的 blob | 内容 | 为什么接受 |
|---|---|---|---|---|
| `pyproject.toml` | `67efb292…` | `c756dfc4…` | `bb19d9e` 的 PEP 639 迁移：`license={text}`→SPDX 字符串、`setuptools>=68`→`>=77`、删 `License::` classifier、加 `license-files` | `mailvault/`（源码）**零差异**，**不改运行行为**；属跨仓统一的技术债修复（同批 certledger / extract-oracle 同样迁移，PEP 639 硬期限 2027-02-18） |

**这不是放宽判据，是如实登记**：偏差若消失（下次发版正常化），「登记偏差无僵尸条目」会报红要求删登记；
偏差若扩大（多改一行），「交付面未被改动」会报红。两条判据互为反向约束，中间没有"永久绿"的位置。

**对应变异**：`tools/verify_ast_gates.py` 的 **A09** —— 临时副本先被造成**带 tag 的真仓库**，
植入前做**阳性对照**（两条交付面判据必须都是 PASS、且输出里没有本次植入的串），
然后往 `mailvault/__init__.py` 追加一行并**提交**，断言 `check_release.py --offline` exit 1
且「交付面未被改动」那条判据本身是 FAIL（不是只看整份输出里出现过某个词）。

---

## 覆盖对账

本表对 M6 的 DoD 与 `plan/05` §5 的未验证项逐条给出**三态**：`实现` / `不适用`（本条不适用
的情形已写明） / `待首推`（要等远端与 CI）。

| # | 条目 | 证据 | 三态 |
|---|---|---|---|
| 1 | 脱敏四步 + 产物扫描 | 禁词门 PASS 11 份；卫生门 PASS 108 份；样例绝对路径直扫 PASS | 实现 |
| 2 | 干净环境验证（`git archive` 目录 / 本地 bare clone / 发布件解包） | 见 §1.7 与 §2.4，三种形态各 **18/18** | 实现 |
| 3 | 发布件**真下载 + 解包**复核（V6） | §2.4：sha256 与 asset digest 一致，解包后 18/18 | 实现 |
| 4 | 建仓 `gh repo create` + 首推 + CI run id 入库（V1、G4） | §2.1–§2.3：push 数 = run 数 = 6；run id 已回填 | 实现 |
| 5 | `git tag v1.0.0` + GitHub Release 三件套 | §2.2：Release 页在位，附源码包 + 示例产物 + fixture 清单 + PSL 版本 | 实现 |
| 6 | Python 3.11 行为（V2、G5） | CI 矩阵 `py3.11 · ubuntu` 与 `py3.11 · windows` 两个 job 全步骤 success；**本机不适用**（只有 3.8.8 / 3.12.10） | 不适用（已由 CI 覆盖） |
| 7 | CI 跨平台实跑（ubuntu / windows × 3.11 / 3.13） | §2.3：run `39526981564` 与 `39527171060` 各 5/5 job success | 实现 |
| 8 | 真实收件方 `Authentication-Results` 与真实 RUA 报告的方言覆盖（V8、V9） | 本仓全部 AR/RUA 都是自建最小形态；**发布后收反馈**才能验 | 不适用 |
| 9 | 发布门三态 `--pre-tag` / `--offline` / `--online` 可复跑 | `tools/check_release.py`（三模式）；§2.5 实测 | 实现 |

> **口径**：`待首推` 已全部转为 `实现`（#3/#4/#5/#7）；两条 `不适用` 是**真的不适用**
> 而不是没做——#6 由 CI 矩阵覆盖（本机无 3.11 通道），#8 只能等真实用户反馈。
> 未验证项**不得**用"计划里写了"代替"已发生"（`plan/05` §5 口径）。

### 2.7 tag 后追加的收尾（2026-10-23，未发新 tag）

tag `v1.0.0` 与 Release **均未移动**。以下改动全部落在非交付面（`tools/` `tests/` `plan/` `.github/`）：

| 项 | 内容 | 根因 / 判据 |
|---|---|---|
| §2.3 自述过期 | 原文"`mailvault/` 与 `pyproject.toml` 零差异"已不成立（`bb19d9e` 动了 `pyproject.toml`） | 改写为"源码零差异 + `pyproject.toml` 有 PEP 639 迁移、不影响运行行为"，见 §2.6 |
| 新增发布门判据 | `交付面未被改动` + `登记偏差无僵尸条目`（`--offline` 档 7 → 9 条判据） | D2：本仓此前对 `AGENTS.md` 硬性纪律第 1 条**没有任何机器判据** |
| 新增变异 A09 | 临时仓库先造成带 tag 的真仓库，**分两段**打靶（不提交 / 提交）+ **阳性对照** | 本仓方法论：每条判据都要被打靶；A 系列 8/8 → **9/9** |
| CI 前置条件 | `actions/checkout` 加 `fetch-depth: 0` + `fetch-tags: true` | 新判据读 git 历史；默认浅克隆会让它**空验成绿**（判据本身把浅克隆判 FAIL，不是 SKIP） |
| `verdict.md` 散落产物 | 仓库根 5,519 B 那份**不是手放的**：`tests/test_whatif.py::test_rua_is_not_part_of_the_exit_code` 调 CLI 时没给 `--md`，CLI 按契约写进 CWD（= 仓库根），**每次 pytest 都重生成** | 删除文件治不住 ⇒ 改测试显式给 `--md`，并加反自证断言"CWD 不得多出产物"。**这条是本轮唯一的确定性缺陷** |

> **关于 `verdict.md` 的更正**：`00-诊断报告.md` 的 D3 把它描述为"散落产物"，方向对但归因不全——
> 它不是一次性遗留，而是**测试每次跑都会重新生成**。所以本轮不只删文件，还修了生成点。