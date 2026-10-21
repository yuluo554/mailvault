# AGENTS.md

本仓库遵循 **`ai-tool-project-sprint`** 方法论（装订日期：2026-10-21）。

## 任何新对话的第一件事

```bash
py -3.12 tools/check_sprint_layout.py     # 布局门（CI / 非 Windows 用 python tools/check_sprint_layout.py）
```

- 必须全绿；红了先修布局再干活。
- 续接对话：先读 `plan/HANDOFF-M<k>.md`（第 k 棒的收尾交接单），**再跑上面这条门**。
- 接手对话（无 HANDOFF）：先读 `plan/00`、`plan/05`、`plan/06`，重建"当前状态 + 既定口径清单"再动手。
- **门不存在 = 本项目没装订** → 先补装订三件（本文件 + `tools/check_sprint_layout.py` + `plan/00` 顶部装订行），再做别的。

## 强制布局（布局门逐条断言，改动前先看这里）

| 项 | 位置 | 判据 |
| --- | --- | --- |
| 计划套件 | `plan/00`–`plan/06` + `data/README.md` | 存在且各含必需小节（标题关键词） |
| 数据台账 | `data/README.md` | 含"证据清单"与"数值口径"两节 |
| 交接单 | `plan/HANDOFF-M<k>.md` | 每个 ✅ 里程碑一份（M0 已声明豁免），**七节**齐：当前进度 / 当前事实 / 待办 / 既定口径 / 环境坑 / DoD / 命令速查 |
| 里程碑状态副本 | `plan/00` 里程碑表 + `plan/05` 状态表 + `README` 状态行 + `plan/00` 承诺-证据台账 | **逐处一致**；门按"逐副本采集、任一不一致即红"判定，不以任何单一副本为真值 |
| 缺口表 | `plan/06` 的"缺口"列 | 已 ✅ 的里程碑不得再出现在缺口格里（关闭缺口时只描述、不点名文件） |
| 发布留档 | `plan/RELEASE-M6.md`（两栏）或 `plan/WRAPUP-M6.md` | 仅当发布里程碑 M6 已 ✅ 时断言；两栏 + 覆盖对账小节 + 三态行 ≥ 3 |
| 文档点名的工具 | `tools/*.py` 被文档引用 | `AGENTS.md`、`README.md`、`plan/*.md` 里出现的 `tools/*.py` 必须**真实存在**（防"文档点名的门没有实物"） |
| 装订行 | `plan/00` 顶部 | 同一行同现：方法论名 + 布局门命令 + 装订日期 |

## 变异验证（改门或改文档后必跑）

```bash
py -3.12 tools/verify_layout_gate.py
```

它会在临时目录里逐条构造"缺件 / 状态冲突 / 过期缺口 / 留档缺节"等 10 组故障，**每一组都要求布局门变红**并报出对应判据 id。任一组仍绿 = 假门，先修门再继续。

## 其他守门（都在 CI 里有一条步骤）

| 命令 | 断什么 | 能否变异变红 |
| --- | --- | --- |
| `tools/check_no_network.py` | `mailvault/` 里除 `net.py` 外零 `socket/ssl/http/urllib` import | 在 `spf.py` 加 `import socket` → 红 |
| `tools/check_no_direct_json.py` | `json.dumps/dump` 只准出现在 `canonical.py` | 在 `cli.py` 加一句 `json.dumps({})` → 红 |
| `tools/check_no_clock.py` | 源码零 `datetime.now/today/utcnow`、`time.time/monotonic`；**唯一豁免** `net.py::utc_now_z`（按函数行区间，同文件别处仍红） | 加一句 `time.time()` → 红；在 net.py 非豁免函数里写 `time.time()` → 红（A06） |
| `tools/check_fixture_hygiene.py` | `fixtures/` + `examples/` 只用保留域 / 文档 IP 段；上游原样件逐条登记豁免并打印理由 | 放一条真实域名到 `fixtures/`（A04）或 `examples/`（A07）→ 红 |
| `tools/check_forbidden_terms.py` | 样例产物在 strict 口径下无禁词（M0 无产物 → SKIP 并打印扫描数；M6 起有 `examples/` → 真判定） | 放一份含"攻击"的 verdict → 红 |
| `tools/offline_smoke.py` | `audit` 路径零 socket 尝试（进程内替换 `socket.socket` 为抛异常的桩）；**M2 起固定断言两个码**：缺三件套 → `3`，完整输入 → `0`（真实判定） | 在 audit 分支里联网 → 红 |
| `tools/check_release.py` | 发布门**三态**：`--offline`（CI 跑这档，不碰网络）/ `--pre-tag`（内容齐备 + tag 未创建 + 工作区干净）/ `--online`（远端 · tag 已推 · Release 三件套 · CI run 实录） | 把 README 换成不含版本号的正文 → `--offline` 报红（A08） |
| `tools/verify_ast_gates.py` | 上面六条门的变异验证（**8/8** 必须 red） | 自身即变异验证 |

## 环境事实与禁忌（2026-10-21 实测）

- Windows + Git Bash。`py -0p` 实测两条通道：**3.8.8-64 与 3.12.10-64**（**没有 3.11**）；`node v24.15.0` 在但本项目不依赖 Node。
- `python` 是商店占位符 → 本机一律 `py -3.12 ...`；`requires-python = ">=3.11"` 的 3.11 行为**以 CI 矩阵为准**，本机验不了。
- 运行时**零第三方依赖**；测试期依赖 `pytest` + `pyyaml`（`dev` extra）。`pyyaml` 只用于读 RFC 7208 测试集，`mailvault/` 包内零 `import yaml`（由 `tests/test_determinism.py::test_runtime_has_no_third_party_imports` 扫描断言）。
- 编码：入口按 `stream.encoding` 探针决定是否 reconfigure 到 UTF-8；CI 另设 `PYTHONUTF8=1`。
- 提交身份：`yuluo554`；远端在 M6 才建（本轮无 remote，**DoD 里不得写"CI 绿"**，只能写"本地等价校验（未接远端，CI 待首推验证）"）。
- 禁止：把"未执行"写成已完成；未实现的能力返回 `0` 或空结果（fail-closed 到退出码 `2`）；在 tag 之后改交付面（`mailvault/`、`pyproject.toml`）。
