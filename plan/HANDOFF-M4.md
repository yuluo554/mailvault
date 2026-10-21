# HANDOFF-M4（M3 收尾 → M4 开工）

> 用法（用户侧启动命令）：`/goal 读取 "<项目绝对路径>\plan\HANDOFF-M4.md" 继续完成任务`
> **第一动作 = 跑布局门**：`py -3.12 tools/check_sprint_layout.py`（必须全绿，红了先修布局）。
> 本文件内一律相对路径。

---

## 一、当前进度 + 证据

**已完成：M0（装订 + 骨架）+ M1（数据先行）+ M2（SPF 求值器）+ M3（DKIM 验签）**，均 2026-10-21。

| 交付 | 证据（实测命令 + 结果） |
|---|---|
| 布局门 | `py -3.12 tools/check_sprint_layout.py` → **全绿**（8 PASS / 0 FAIL / 1 SKIP=RELEASE） |
| 布局门变异 | `py -3.12 tools/verify_layout_gate.py` → **11/11 全部如期变红** |
| AST 守门 | `check_no_network` 18 文件全绿；`check_no_direct_json` 18 文件全绿；`check_no_clock` 19 文件全绿 |
| AST 变异 | `py -3.12 tools/verify_ast_gates.py` → **6/6 全部如期变红** |
| fixture 卫生 | `py -3.12 tools/check_fixture_hygiene.py` → PASS 50 份 + EXEMPT 2 份（理由打印） |
| 禁词门 | `py -3.12 tools/check_forbidden_terms.py` → SKIP 0 份（M6 才转真判定） |
| 断网冒烟 | `py -3.12 tools/offline_smoke.py` → **缺输入→3、完整输入→0、socket 尝试 0** |
| 测试 | `PYTHONUTF8=1 py -3.12 -m pytest` → **296 passed**（M2 时 230；DKIM 新增 66） |
| **DKIM fixtures** | 11 例全绿：正样本 1 + 五类失败 6（body/header/`l=`/key 缺失×2/RSA-512）+ 多签名/未签名/缺标签 3 |
| **规范化对表** | RFC 6376 §3.4.5 Example 1/2/3 + §3.4.3/§3.4.4 两个空正文基准哈希（原文给的字面值） |
| **零依赖 RSA 对账** | 与 `cryptography` 50.0.2 逐例一致（SPKI + 裸 PKCS#1 × SHA-256/SHA-1 + 阴性对照） |
| **dkimpy 对账** | 11 例逐条跑 dkimpy 1.1.8：**9 例一致 + 2 例按 RFC 的有意差异**（见 `plan/04` §3.2） |
| fixture 生成器幂等 | `py -3.12 tools/gen_dkim_fixtures.py --check` → **逐字节一致** |
| CLI 端到端 | 正样本 → `checks` 两条（`spf.check_host` + `dkim.verify_signature`），`tree` 键在 |
| 多签名 CLI | `d7` → 两条 `dkim.verify_signature`（`index` 0/1，`fail` / `pass`），**不短路** |

**M3 交付面**（新增/改动的代码）：

| 模块 | 内容 |
|---|---|
| `mailvault/crypto/__init__.py` | 包声明（L1：只标准库；本包存在的理由 = 不给运行时加依赖） |
| `mailvault/crypto/der.py` | DER TLV 解析；**SPKI 与裸 `RSAPublicKey` 两种编码**；严格拒绝尾随垃圾/截断/错误标签 |
| `mailvault/crypto/rsa.py` | PKCS#1 v1.5 **逐字节**比对 `EM`；DigestInfo 前缀写成可核对的字面量 |
| `mailvault/modules/dkim.py` | 规范化（simple/relaxed × 头/正文）、标签解析、密钥状态、按 RFC §6.1 三步走、多签名不短路 |
| `mailvault/eml.py` | 新增 `header_fields()`（字节级保真，`dkimpy::rfc822_parse` 同口径）与 `body_crlf` |
| `mailvault/constants.py` | 新增 `DKIM_FORBIDDEN_ALGS` / `DKIM_UNSUPPORTED_ALGS` / `DKIM_KEY_STATUSES`；收窄 `DKIM_SUPPORTED_ALGS` |
| `mailvault/cli.py` | `_cmd_audit` 接 DKIM；`checks[]` 追加 `dkim.verify_signature`（一签名一条目） |
| `tests/test_dkim.py` | **66 条**：RFC 原文向量、11 例 fixture 全量对账、参照实现对账、反自证、卫生门阳性对照 |
| `tools/gen_dkim_fixtures.py` | 生成 11 例 + 两把钥匙；`--check` 逐字节幂等 |
| `tools/check_fixture_hygiene.py` | **改判据**：JSON 只扫字符串**值**、不扫键（键是 schema 字段名） |
| `fixtures/dkim/` | 11 个用例目录 × 4 份产物 + `keys/`（私钥 + 公钥 + README） |

**未做**：远端仓库、CI 实跑、M4–M6。

---

## 二、当前事实·状态不变量（**动手前必须知道**）

1. **`mailvault/__init__.py::__version__` 是版本唯一真源**。`pyproject.toml` 用 `dynamic`。定版只改这一处。
2. **`mailvault/constants.py` 是全部数值口径的唯一出处**。M3 新增 DKIM 三个元组、收窄算法白名单。
3. **`canonical.py` 是全仓唯一 JSON 出口**（K2）。M3 没有新增序列化路径。
4. **网络 import 只在 `net.py`**（K3）。`mailvault/crypto/` 与 `mailvault/modules/` 都在此约束下。
5. **时钟豁免精确到函数**（K7）：`net.py::utc_now_z` 是**唯一**允许读时钟的位置。
   **M3 新增的后果**：DKIM 的 `x=`（过期时间）**不校验**，只出告警。
   与 SPF 的 `%{t}` 同源（`plan/06` G7 / G10）。**不要为了"校验过期"去读时钟。**
6. **状态副本 = 4 处**（`plan/00` 里程碑表 + `plan/05` 状态表 + `README.md` 状态行 +
   `plan/00` 承诺-证据台账）。翻状态**四处一起改**。`plan/06` 缺口表是第五处（只描述、不点名文件）。
7. **`plan/05` 与 `plan/06` 的表格首列不要用 `| M<n> |` 形态**做非状态用途——布局门会误判。
8. **未实现的能力必须 fail-closed 到 2**。`whatif` / `diff` 仍是 `ModuleNotReady` → 2；
   **`audit` 现在是 SPF + DKIM 两条真判定**。
9. **`requires-python = ">=3.11"`，本机无 3.11**（只有 3.8.8 / 3.12.10）。一律 `py -3.12`。
10. **本仓库无远端**。DoD 里不许写"CI 绿"。
11. **运行时零第三方依赖**：`pyyaml`（读 RFC 7208 测试集）与 `cryptography`（签 DKIM 样本 +
   参照对账）都只在 `dev` extra。`mailvault/` 包内不得 import 它们
    ——`test_dkim.py::test_runtime_does_not_import_reference_implementation` 是 DKIM 侧的守门。
12. **"没查过" ≠ "没有"**（K13）：DKIM 已落地两种形态——
    快照没查过 → `undecidable` + `data_gap`；快照答复 NXDOMAIN → `permerror`。
    M4 对 DMARC 的 `_dmarc` 查询要照同一口径（三跳全空才是 `none`；某跳没查过 → `undecidable`）。
13. **`failure_at` 只在可判定时给位置**：`bh=`/`b=` 失败给 `kind` + `basis`，**不编造**行号/头名
    （`plan/03` §3.3 的六种 `kind` 表；`plan/06` G9）。
14. **`check_entry` 的字段集对所有条目一致**：DKIM 条目 `tree` 恒为 `null`（键仍存在）。
15. **DKIM 的 `subject` 里有 `index` / `signatures_total`**：多签名时每个条目都写，
    不要靠"数条目"反推。形状见 `docs/ledger-format.md` §3.1。
16. **`eml.Message` 现在有两条读取路径**：`headers`（人读，折行展开成 `\n`）
    与 `header_fields()`（字节级保真，供规范化）。**做 DKIM/AR 类字节敏感解析必须用后者。**
17. **`.eml` 的正文归一**：`body_crlf` 按 `\r?\n` 切行（与 dkimpy 同口径）。`body` 仍是原始字节。

---

## 三、下一棒待办（M4：DMARC tree walk + 对齐 + 处置）

按 `plan/05` §2 的 M4 DoD、`plan/01` 的 M3 段、`plan/03` §3.4：

1. **`mailvault/modules/dmarc.py`**：`_dmarc` tree walk **Author → Org → PSD** 三跳，
   每跳记 `(qname, answered, record_or_reason)`，命中即停；三跳全空 → `none`（不是 `fail`）。
   某跳快照没查过 → `undecidable` + `data_gap`（K13 第 12 条）。
2. **`spf_align` / `dkim_align` 双算**：`relaxed` 与 `strict` **各出一个布尔值，不合并**
   （`constants.ALIGN_MODES`）。DKim 侧用 `d=` + `i=` 的域和 `From:` 域比对；
   SPF 侧用 MAIL FROM 域（或 HELO 域）与 `From:` 域比对。
3. **`disposition`**（`constants.DMARC_DISPOSITIONS`）：按 `p=` / `sp=` + 对齐结果 + `pct=`
   推导。`pct=` **出现即告警**"已被 RFC 9989 删除"，**不得静默忽略**（题面 M3 验收 2）。
   `psd=` / `np=` / `t=` 正常解析并进输出。
4. **PSL 版本**：输出必带 `psl_version` + `psl_date`（来自快照；`psl.py` 已有
   `organizational_domain()`，M4 第一次真正用上它）。
5. **RFC 9989 Appendix B.4.1–B.4.3 三个 tree-walk 示例逐跳复现**（`fixtures/dmarc/b41/`…`b43/`）。
   这是 M4 的主验收：**逐跳**与原文一致，不是"最终 disposition 对上了"。
6. **`psd=y` 与 `np=` 各一条独立 fixture**（题面 M3 验收 3）。
7. **测试**：`tests/test_dkim.py` 是模板（RFC 原文向量 / fixture 全量 / 参照对账 / 反自证四层）。
   DMARC 的"参照实现"是对齐域的手算（`plan/04` §2.2），不是引第三方库。
8. **`cli._cmd_audit` 接上 DMARC**：`checks[]` 多一条 `dmarc.evaluate`。
   退出码仍取最严重的那个（`exits.exit_code_for`），**不要**在 dmarc 里自己算退出码。

---

## 四、既定口径清单（K 编号，动了会打挂测试）

| # | 口径 | 守在哪 |
|---|---|---|
| K1 | 退出码只在 `exits.py`；优先级 `4>3>2>1>0` | `tests/test_contract.py` |
| K2 | `json.dumps` 只在 `canonical.py` | `tools/check_no_direct_json.py` |
| K3 | 网络 import 只在 `net.py` | `tools/check_no_network.py` |
| K4 | 结果枚举只在 `constants.RESULTS`；`undecidable` 不折叠成 `fail` | `test_contract` / `test_ledger` / `test_spf` / `test_dkim` |
| K5 | `evidence_ref` 缺失 → 构造期降级 `undecidable` | `ledger.check_entry` + `test_ledger` |
| K6 | `schema_version` 单点定义；未知版本 → exit 3 | `constants` + `tests/test_inputs.py` |
| K7 | 零系统时钟；**唯一豁免 `net.py::utc_now_z`**（函数级） | `tools/check_no_clock.py` + `test_determinism` |
| K8 | 比率 = 6 位定点字符串；账本内无裸浮点 | `canonical.fixed6` + `dumps` 拒浮点 |
| K9 | 账本内无绝对路径 | `render._assert_no_absolute_path` |
| K10 | `--strict-evidence` 禁词表 | `render.STRICT_FORBIDDEN` + `check_forbidden_terms` |
| K11 | fixture 只用保留域 / 文档 IP 段；上游原样件逐条登记豁免 | `tools/check_fixture_hygiene.py` |
| K12 | 判定节点 id 稳定（`n0`, `n0.1`），**只由路径决定** | `test_spf.py::test_tree_root_and_child_ids_are_stable` |
| **K13** | **`found=False`（快照没查过）不得当成"没有记录"**；判 `undecidable` 并带 `data_gap` | `test_spf.py` + `test_dkim.py`（两种形态各一例） |
| **K14** | **单向哈希类失败不编造定位**；给 `kind` + `basis` | `test_dkim.py::test_failure_at_for_*_does_not_invent_*` |
| **K15** | **fixture 卫生门只扫 JSON 的字符串值、不扫键**（键是 schema 字段名） | `test_dkim.py::test_fixture_hygiene_catches_domain_in_json_value`（阳性 + 阴性对照） |

---

## 五、本机环境坑（全部实测）

| 坑 | 实测 | 处置 |
|---|---|---|
| `python` 是商店占位符 | — | 一律 `py -3.12` |
| 无 Python 3.11 | `py -0p` → 3.8.8-64 / 3.12.10-64 | 3.11 行为以 CI 为准 |
| Git Bash `/tmp` 与 Python 路径认知不一致 | `py -3.12` 看不到 `/tmp/x` | **用 `cygpath -w "$TEMP"` 转成 Windows 路径**（M2 踩两次，M3 又踩一次） |
| Git Bash heredoc 里写中文/`%` 会乱码 | `py -3.12 - <<'EOF'` 直接跑含中文的脚本会炸 | **把脚本写到文件再跑**，或 `PYTHONUTF8=1` |
| Windows 控制台打印中文乱码 | 布局门输出的 PASS 行显示成乱码 | 只是显示问题；判据按 UTF-8 读文件，不影响结论。看数字看"结论:"那行 |
| `cryptography` 拒绝生成 <1024 位密钥 | `rsa.generate_private_key(512)` → `ValueError` | 用纯 Python 素数搜索（`gen_dkim_fixtures.py::_gen_small_rsa`） |
| `cryptography` 的 `sign(data, pad, hash_alg)` **会自己再哈希一遍** | 传摘要进去 → 签名对应 `SHA256(SHA256(x))`，**每条都验不过** | 必须用 `utils.Prehashed(hash_alg)`（M3 踩过，症状与真实故障无法区分） |
| dkimpy 拒绝 `t=` 在未来 | `ValidationError: t= value is in the future` | fixture 用过去的时间戳（2026-01-01） |
| dkimpy 的模块级 `verify()` 遇首个坏签名就抛异常 | 多签名时拿不到逐条结果 | 对账用 `DKIM(raw).verify(idx=i)` 逐条调 |
| dkimpy 的 `signature_fields` 是 dict 不是 list | 数签名条数用它 → 恒为 0 | 用 `len([1 for n,v in d.headers if n.lower()==b"dkim-signature"])` |
| 布局门变异靶子随进度失效 | M06/M07 曾写死 M1/M2 | 变异脚本**探测当前待办里程碑**；靶子找不到就断言失败 |
| fixture 卫生门会扫 `fixtures/*/README.md` | 引用上游真实 IP 会自己变红 | 文档里描述上游件时**不要写字面 IP**，用文字转述 |
| `argparse` 缺参 `SystemExit(2)` | 与 `undecidable` 撞语义 | 入口已转 3；`test_contract` 锁定 |
| `ModuleNotReady` 继承 `InputError` | 措辞会打印成"输入错误" | `cli.main` 单独捕获，打印"尚未实现" |
| pyflakes 会抓 `%` 字符串里的 `%{` | `"%{p} ..." % x` 报 unsupported format char | 该转义就写 `%%{p}` |
| 测试文件 docstring 里的 `\*` | 触发 `SyntaxWarning: invalid escape sequence` | 用 `raw` 字符串或改措辞 |

---

## 六、DoD 逐项 checklist（本棒，全部已实测）

- [x] 五类失败各有 fixture：body 改 / header 改 / `l=` 截断 / key 缺失 / RSA-512
- [x] **正样本存在**（`d6-valid`）——否则"永远返回 fail"也能全过（有断言盯着）
- [x] 无快照 key → `undecidable`（测试断言**不是** `fail`）；NXDOMAIN 另判 `permerror`
- [x] 多签名逐个出结果、不短路（`d7` 实测 `[fail, pass]`；顺序 = 物理顺序）
- [x] 零依赖 RSA 验签与参照实现（`cryptography` 50.0.2）逐条对账
- [x] 规范化对表 RFC 6376 §3.4.5 Example 1/2/3 与 §3.4.3/§3.4.4 空正文基准哈希
- [x] `key_status` 五值齐全（`ok`/`revoked`/`missing`/`weak`/`invalid`）+ 四值以外的 `None`（未取证）
- [x] `a=rsa-sha1` → `permerror`（RFC 8301 §3.1）；`a=ed25519-sha256` → `undecidable` + 告警
- [x] `l=` 大于规范化正文长度 → `permerror`（§3.5 MUST NOT + §6.1.1）
- [x] `l=` 边界另一侧（恰好等于、以及截断后改尾部）→ `pass` + 未受保护告警
- [x] `h=` 不含 From → `permerror`；`v≠1` → `permerror`；`i=` 越域 → `permerror`
- [x] `x=` 不校验但**必出告警**（K7）
- [x] `p=` 为空（revoked）/ `v≠DKIM1` / `k≠rsa` / `s=` 不含 email / `h=` 排除该哈希 → 全部有断言
- [x] 坏 DER → `permerror`（异常不穿透到账本）
- [x] fixture 生成器 `--check` 逐字节幂等
- [x] `audit` 接上 DKIM；`checks[]` 一签名一条目；退出码走 `exit_code_for`
- [x] `pytest` 296 passed；九条门全绿；变异 11/11 + 6/6
- [x] 4 处状态副本 + `plan/06` 缺口表同步；`plan/04` §3.2 记 2 条口径差异

**DoD 未达成项（如实登记）**：

- CI 实跑：**未接远端，未跑过**。首推后需回填 run id。
- Python 3.11 行为：**本机验不了**，以 CI 矩阵为准。
- `x=` 过期校验：**不校验**（需系统时钟，K7 禁）。登记为 `plan/06` G10。
- 单向哈希失败的精确位置（哪一行/哪个头）：**给不出**（数学上不可能）。
  登记为 `plan/06` G9；`plan/03` §3.3 的初版写法已按实装更正。
- `i=` 本地部分不做 quoted-printable 解码：登记为 `plan/06` G12。
- 与 dkimpy 的 2 条口径差异（`l=` 超长、`rsa-sha1`）：**有意为之**，见 `plan/04` §3.2 与 `plan/06` G11。

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
PYTHONUTF8=1 py -3.12 -m pytest tests/test_dkim.py -q        # 只跑 DKIM（66 条）
py -3.12 -m mailvault --version

# 4) DKIM fixture 幂等复核（改生成器后必跑）
py -3.12 tools/gen_dkim_fixtures.py --check

# 5) 端到端 audit（断网可跑；Git Bash 里必须用 cygpath 转 Windows 路径）
OUT="$(cygpath -w "$TEMP")\\mv"; mkdir -p "$(cygpath -u "$OUT")"
py -3.12 -m mailvault audit \
    --snapshot fixtures/dkim/d6-valid/snap.json \
    --eml fixtures/dkim/d6-valid/message.eml \
    --query fixtures/dkim/d6-valid/query.json --out-dir "$OUT"; echo "exit=$?"
#   注：d6 的快照只含 DKIM 密钥查询，SPF 会判 undecidable（数据缺口）→ exit 2。
#   要看 exit 0 的端到端，用 tools/offline_smoke.py 里那份三件套。

# 6) 多签名（不短路的现场验证）
py -3.12 -m mailvault audit \
    --snapshot fixtures/dkim/d7-multi-signature/snap.json \
    --eml fixtures/dkim/d7-multi-signature/message.eml \
    --query fixtures/dkim/d7-multi-signature/query.json --out-dir "$OUT"
#   期望：checks 里两条 dkim.verify_signature，index=0 fail / index=1 pass

# 7) 参照实现核对（仅开发期；运行时不许 import）
py -3.12 -m pip download dkimpy --no-deps -d "$TEMP/dkimdl"
#   解包后按 index 逐条调：dkim.DKIM(raw).verify(idx=i, dnsfunc=...)
#   模块级 dkim.verify() 遇首个坏签名会抛异常，拿不到逐条结果

# 8) 只读检查：本棒交付面
git status --short
git ls-files
```
