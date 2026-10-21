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
| CI run id（修复后 `main`） | `待回填` |
| CI run id（修复后 tag `v1.0.0` 重指） | `待回填` |
| push 数 = run 数 | `待回填` |
| 远端 | `git@github.com:yuluo554/mailvault.git`（公开） |
| GitHub Release | `待回填` |
| tag OID / 源码包 sha256 | `待回填`（tag 重指后重算） |

---

## 覆盖对账

本表对 M6 的 DoD 与 `plan/05` §5 的未验证项逐条给出**三态**：`实现` / `不适用`（本条不适用
的情形已写明） / `待首推`（要等远端与 CI）。

| # | 条目 | 证据 | 三态 |
|---|---|---|---|
| 1 | 脱敏四步 + 产物扫描 | 禁词门 PASS 11 份；卫生门 PASS 108 份；样例绝对路径直扫 PASS | 实现 |
| 2 | 干净环境验证（`git archive` 目录直跑 / 本地 bare 仓库 round-trip） | 见 §1.7 | 实现 |
| 3 | 发布件**真下载 + 解包**复核（V6） | 需 tag 与 Release 先在远端 | 待首推 |
| 4 | 建仓 `gh repo create` + 首推 + CI run id 入库（V1、G4） | 需远端 | 待首推 |
| 5 | `git tag v1.0.0` + GitHub Release 三件套 | 需远端 | 待首推 |
| 6 | Python 3.11 行为（V2、G5） | 本机只有 3.8.8 / 3.12.10；**本机不适用**，以 CI 矩阵（3.11 / 3.13）为准 | 不适用 |
| 7 | CI 跨平台实跑（ubuntu / windows × 3.11 / 3.13） | 同 #4；未接远端时只能做"本地等价校验" | 待首推 |
| 8 | 真实收件方 `Authentication-Results` 与真实 RUA 报告的方言覆盖（V8、V9） | 本仓全部 AR/RUA 都是自建最小形态；**发布后收反馈**才能验 | 不适用 |
| 9 | 发布门三态 `--pre-tag` / `--offline` / `--online` 可复跑 | `tools/check_release.py`（三模式） | 实现 |

> **口径**：`待首推` 的三条（#3/#4/#5/#7）在第二栏回填后一并转为 `实现`。
> 未验证项**不得**用"计划里写了"代替"已发生"（`plan/05` §5 口径）。