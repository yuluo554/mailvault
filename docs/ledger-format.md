# 判定账本格式（`verdict.json` / `verdict.md`）

本文件定义账本的字段、语义与 `evidence_ref` 约定。**这是字段名的唯一真源**；代码里的常量模块引用这里，不另行发明名字。

---

## 1 顶层结构

```json
{
  "schema_version": 1,
  "ledger_id": "<sha256 of canonical inputs>",
  "tool_version": "0.1.0",
  "snapshot": {
    "fetched_at": "<ISO8601 from snapshot, never system clock>",
    "resolver": "synthetic | <resolver string>",
    "psl_version": "<version string>",
    "psl_date": "<ISO date>",
    "query_count": 0
  },
  "query": {
    "mail_from": "<addr or empty>",
    "helo": "<name or null>",
    "client_ip": "<ip>",
    "trusted_authserv_ids": []
  },
  "checks": [],
  "reconcile": {},
  "summary": {
    "exit_code": 0,
    "counts": {"pass": 0, "fail": 0, "undecidable": 0}
  }
}
```

**确定性要求**：`ledger_id` 由规范化输入算出（键排序、无空白差异）；除 `snapshot` 带入的时间外，账本**不含任何运行时刻**。

---

## 2 `checks[]` 条目

```json
{
  "check_id": "spf.check_host",
  "module": "M2",
  "subject": {"domain": "example.invalid", "scope": "mail_from"},
  "result": "pass | fail | softfail | neutral | none | temperror | permerror | undecidable",
  "reason": "human readable, no speculation",
  "evidence_ref": ["RFC7208#5.2", "RFC7208#4.6.2"],
  "trace": [],
  "budget": null,
  "tree": null,
  "warnings": []
}
```

字段集对**所有**条目一致：没有判定树的模块（DKIM/DMARC/对账）写 `"tree": null`，
不省略键——省略会让渲染层必须判"这个键有没有"，那种分支迟早会两边不一致。

`evidence_ref` 挂的是**命中机制自己**的条款节（§5.1–§5.7）+ 限定符语义（§4.6.2），
不是笼统的一个 §4.6.4：读者要能核对"到底是哪条规则判的"。

### 2.1 `result` 枚举（唯一真源）

| 值 | 语义 |
|---|---|
| `pass` / `fail` / `softfail` / `neutral` / `none` | SPF 结果语义（RFC 7208） |
| `temperror` / `permerror` | 同上 |
| `undecidable` | **数据不足或规则本身是灰区**。禁止用 `fail` 代替 |

灰区一律 `undecidable`，并在 `reason` 中写明缺什么（缺 PTR、缺快照 key、PSL 版本影响、void 是 SHOULD 等）。

### 2.1.1 `data_gap`（SPF 专用，不在 `checks[]` 里）

求值结果对象（`modules/spf.py::SpfResult`）额外带一个字段：

```python
data_gap: tuple[str, str] | None   # (qname, qtype)
```

它**不写进** `verdict.json`（账本是结论面，不是输入清单），但调用方需要它：

- `data_gap` 非空表示"快照里没查过这条"——**待补的输入**；
- `undecidable` 表示"查过了，但数据不足或规则是灰区"——**已得的结论**。

把两者混为一谈，用户就分不清"该去补抓快照"还是"本来就判不了"（`plan/03` K13）。
`tests/rfc7208_suite.py::run_case()` 正是靠它把宏展开出来的查询名补进夹具再重跑。

### 2.2 `evidence_ref` 格式

`RFC<number>#<section>`，可选追加 `#<paragraph>` 或 `#appendix-<id>`：

- `RFC7208#4.6.4`
- `RFC9989#4.10.1`
- `RFC9989#appendix-B.4.2`
- `RFC6376#3.5`
- `RFC8301#3.2`
- `RFC8601#2.5`

**规则**：没有 `evidence_ref` 的判定不允许进入账本。引用不到条款 → 该判定降为 `undecidable` 并记 `warnings`。

---

## 3 `budget`（M2 SPF）

```json
{
  "terms":   {"used": 0, "limit": 10, "ref": "RFC7208#4.6.4"},
  "mx":      {"used": 0, "limit": 10, "ref": "RFC7208#4.6.4"},
  "ptr":     {"used": 0, "limit": 10, "ref": "RFC7208#4.6.4"},
  "void":    {"used": 0, "limit": 2,  "ref": "RFC7208#4.6.4", "limit_kind": "SHOULD"},
  "depth":   {"used": 0, "limit": 20, "ref": "RFC7208#5.2"}
}
```

超限的后果**逐格不同**，不是一句话能概括的（`plan/04` §3 / §3.1）：

| 格 | 超限后果 |
|---|---|
| `terms` / `mx` | `permerror`（RFC 7208 §4.6.4 MUST） |
| `ptr` | **截断到前 10 条**，不判错（原文："超出前 10 条 MUST 被忽略"） |
| `void` | `undecidable` + 告警（原文是 SHOULD；`limit_kind: "SHOULD"` 就是这个意思） |
| `depth` | `permerror`（本项目第二道保险） |

**MUST 优先**：同一条记录同时踩 MUST 与 SHOULD 时报 MUST。

逐格明细另有一份 `budget_entries`（结果对象上，不写进账本）：每条 `(kind, node_id, ref, used)`，
用于回答"这一格是被哪一步消耗的"。

---

## 3.1 DKIM 条目的 `subject`（M3）

一条签名一个条目，`check_id` 固定为 `dkim.verify_signature`；`module` 为 `M3`；
`tree` 恒为 `null`（DKIM 无判定树）。

```json
{
  "check_id": "dkim.verify_signature",
  "module": "M3",
  "subject": {
    "index": 0,
    "signatures_total": 2,
    "selector": "sel20261021",
    "d": "example.com",
    "a": "rsa-sha256",
    "c": "relaxed/relaxed",
    "key_status": "ok",
    "key_bits": 2048,
    "bh_matches": true,
    "failure_at": null,
    "h": ["from", "to", "subject", "date"]
  },
  "result": "pass",
  "reason": "正文哈希匹配，rsa-sha256 签名在 2048 位 RSA 公钥上验签通过",
  "evidence_ref": ["RFC6376#6.1.3", "RFC6376#3.7", "RFC6376#3.6.1"],
  "trace": [],
  "budget": null,
  "tree": null,
  "warnings": []
}
```

字段口径：

- `index` / `signatures_total`：物理顺序 + 总数。多签名时**每条都写**这两个字段，
  读者不必去数条目。
- `bh_matches` 三值：`true` / `false` / **`null`**。`null` 表示"没算到那一步"
  （例如密钥已撤销、算法不支持）——**不是**"没匹配"。
- `key_status` 五值见 `constants.DKIM_KEY_STATUSES`；`null` 同上（未取证）。
- `failure_at`：`kind` 必给；定位字段只在可判定时给，否则为 `null` + `basis`
  （见 `plan/03` §3.3 的六种 `kind` 与理由）。

**未签名的报文**：仍然产出**一条**条目，`result: "none"`、`subject.signatures_total: 0`。
不产出条目会让"这封邮件没签名"从账本里消失。

---

## 3.2 DMARC 条目的 `subject`（M4）

`check_id` 固定为 `dmarc.evaluate`；`module` 为 `M4`；`tree` 恒为 `null`（DMARC 没有
include 树；它的"树"是**走查路径**，写在 `trace` 的 `walk.<i>` 节点与 `subject.walk_queries`）。

```json
{
  "check_id": "dmarc.evaluate",
  "module": "M4",
  "subject": {
    "author_domain": "example.com",
    "organizational_domain": "example.com",
    "policy_domain": "example.com",
    "policy_source": "author",
    "policy_tag": "p",
    "policy_value": "reject",
    "disposition": "reject",
    "disposition_status": "determined",
    "psd": "u",
    "test_mode": false,
    "spf_align_relaxed": true,
    "spf_align_strict": true,
    "dkim_align_relaxed": true,
    "dkim_align_strict": false,
    "walk_queries": 2,
    "walk_hit": "_dmarc.example.com",
    "psl_version": "2026-10-20_08-40-56_UTC",
    "psl_date": "2026-10-20",
    "psl_organizational_domain": "example.com"
  },
  "result": "fail",
  "reason": "DMARC 判 fail；策略取自 example.com 的 p=reject → 处置 reject",
  "evidence_ref": ["RFC9989#4.10", "RFC9989#4.10.1", "RFC9989#4.10.2",
                   "RFC9989#4.4", "RFC9989#5.3.5", "RFC9989#4.7", "RFC9989#5.3.6"],
  "trace": [],
  "budget": null,
  "tree": null,
  "warnings": []
}
```

字段口径：

- **`organizational_domain` 只由 §4.10.2 的 tree walk 得出**，**不是** PSL 的值。
  RFC 9989 §4.10 明确用走查替换了 RFC 7489 的 PSL 做法。
- `psl_organizational_domain` 是**对照值**，由随包冻结的 PSL 算出。在 `psd=y` 场景下
  两者**不同**（B.4.3 就是这样），这个不等本身是信息，不是 bug。
- `policy_source` 三值：`author` / `organizational` / `psd`；`null` 表示没找到记录。
- `disposition_status` 三值：
  - `determined`：给了处置；
  - `not_applicable`：机制没 fail（pass/none），没有"处置"这回事；
  - `undecidable`：**缺输入导致该用哪个策略标签判不出来**。此时 `disposition` 必为
    `null`——用 `p=` 顶上会给出一个看着确定的错答案（`np=` 与 `sp=` 的歧义就是这种）。
- `spf_align_*` / `dkim_align_*`：`relaxed` 与 `strict` **各一个布尔值，不合并**
  （`constants.ALIGN_MODES`）。诊断时两者的差异本身就是信息。
- `walk_queries`：实际查询跳数（§4.10 的反滥用上限是 8）；`walk_hit` 是**第一次命中
  记录**的 `_dmarc.<domain>` 名，`null` 表示逐跳都没命中。
- `psd`：命中记录的 `psd=` 值，缺省 `u`（§4.7 默认值）；没有记录时为 `null`。
- `test_mode`：`t=y` 时为 `true`，且处置按 §4.7 降一级（`reject`→`quarantine`）。
- 逐跳明细**不写进** `subject`（键集要对所有条目一致，值必须是标量）：它写在 `trace`
  的 `walk.0` / `walk.1` … 节点里，一步一行。

**`data_gap` 与 `undecidable` 分开**（K13，与 SPF/DKIM 同一口径）：
`DmarcResult.data_gaps` 形如 `(("_dmarc.example.com", "TXT"), ...)`，表示"快照里没查过
这条"——**待补的输入**；`undecidable` 是**已得的结论**。快照明确答复 `NXDOMAIN` 既不是
前者也不是后者：那是"问过了、没有记录"，走查继续往上。

---

## 4 `tree`（M2 完整 include 展开）

```json
{
  "node_id": "n1",
  "parent": "n0",
  "domain": "example.invalid",
  "record": "v=spf1 include:_spf.example.invalid -all",
  "mechanism": "include",
  "child_result": "fail",
  "consumes_term": true,
  "terminates_parent": false,
  "receiver_would_stop_here": false,
  "children": []
}
```

- **完整展开**：不因第 10 个 term 而截断树。截断的树会把"后面还有 N 个 include"
  整件事藏起来——那正是用户想看的（checkdmarc #172 的诉求）。
- 节点 id 规则：根 `n0`，第 i 个 include `n<i>`，嵌套 `n<i>.<j>`（K12）。
  **只由从根到该节点的 include 序号路径决定**，与遍历顺序、与树是否被截断都无关。
- `receiver_would_stop_here: true` 标出"真实收件方会在此 permerror 停下"的切点
  （第 11 个 DNS 查询类 term 起）。**标记但不停止展开**——切点之后仍然进树。
- `terminates_parent` 只对被 include 域自身的机制生效；子域的 `-all` 不终止父域处理
  （RFC 7208 §5.2）。只有子域结果 `pass` 才让父域的 `include` 命中。
- 没有 SPF 记录或成环的目标也进树，带 `note` 说明原因（"目标域没有 SPF 记录" /
  "include 成环…停止展开"）。

**树不进判定**：画树用独立的 shadow 上下文（独立预算、独立缓存），
所以树里那些查询不改变 `result` / `budget` / `trace`。这是"树可以随便展开"的前提。

---

## 5 `reconcile`（M5）

```json
{
  "entries": [
    {
      "class": "consistent | contradiction | undecidable",
      "claimed": {"source": "Authentication-Results", "authserv_id": "mx.example.invalid",
                  "authserv_version": null, "method": "spf", "result": "pass",
                  "reason": null, "properties": [["smtp.mailfrom", "alice@example.com"]],
                  "parsed": true, "parse_note": null},
      "recomputed": {"result": "fail", "ref": "RFC7208#4.6.4"},
      "explanations": [
        {"hypothesis": "转发导致信封发件人被改写", "verify": "比对 Received 链中是否存在转发跳，检查 mail_from 与 From 域是否一致"},
        {"hypothesis": "快照与接收方当时解析到的 DNS 不同", "verify": "取接收时刻前后两个快照重跑，看结果是否翻转"}
      ],
      "strict_evidence_ok": true,
      "warnings": []
    }
  ],
  "received_chain": {
    "monotonic": true,
    "clock_regressions": [],
    "hop_count": 0,
    "unparsed_dates": 0,
    "dates": [],
    "notes": []
  },
  "authserv_ids": ["mx.example.invalid"],
  "trusted_authserv_ids": ["mx.example.invalid"],
  "notes": [],
  "strict_evidence_ok": true
}
```

**硬约束**：

- `class: contradiction` 时 `explanations` **≥ 2**（`RECONCILE_MIN_EXPLANATIONS`），
  且每条带非空 `hypothesis` + `verify`。少于 2 条 → 模块内部 `InternalError`。
- `authserv_id` 不在 `trusted_authserv_ids` 里、**或不可解析** → `class: undecidable`
  （fail-closed，参照 authres_status #86）。**空的可信列表 ≠ 全部可信**：空列表时任何 AR
  都判 `undecidable`。
- 在 `--strict-evidence` 下，全文禁止出现"攻击"、"伪造"、"被黑"等定性词；`strict_evidence_ok`
  为**自检位**（装配期算出来、逐条 + 汇总各一个），false 时 `audit`/`whatif` 直接
  **exit 3**（渲染期还有第二道闸）。禁词表唯一出处是 `constants.STRICT_FORBIDDEN`。
- `received_chain.monotonic` 三值：`true` / `false` / **`null`**。`null` = 有 `Received`
  头的时间戳解析不出（或没有时区偏移，跨跳不可比）→ **判不了就说判不了**。
  `clock_regressions[]` 每项含 `from_index` / `to_index` / `from` / `to` / `note`。
- **时间只取报文头里的字面值，只做相互比较**——从不与系统时钟比较（K7）。

**汇总条目** `reconcile.cross_check`（进 `checks[]`，所以对账的灰区会让退出码变 2）：

| 情形 | `result` |
|---|---|
| 至少一条 AR，全部 `consistent` | `pass` |
| 出现 `contradiction` **或** `undecidable` | `undecidable` |
| 一条 AR 都没有 | `none` |

**矛盾不进 `fail`**：矛盾的意思是"报文头与重算不一致，哪一侧描述的是现实本工具不知道"
——那正是 `undecidable` 的语义；报成 `fail` 会被读成"你被黑了"（题面风险 ③）。

---

## 5.1 `whatif`（M5）

`whatif` 的产物是**一份账本**（结构与 `audit` 一致，`checks[]` + `reconcile` + `summary`
描述的是**候选**），外加一个 `whatif` 块：

```json
{
  "whatif": {
    "changes": [
      {"key": "p", "value": "reject", "record": "_dmarc.example.com",
       "path": "queries[0].answer[0]",
       "from": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
       "to": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"}
    ],
    "diff": {
      "schema_version": 1,
      "ops": [{"op": "set", "path": "/checks/2/subject/disposition",
               "from": "none", "to": "reject"}],
      "op_count": 1,
      "changed_checks": [{"index": 2, "check_id": "dmarc.evaluate",
                          "changed_fields": ["reason", "subject", "trace"],
                          "result": {"from": "fail", "to": "fail"}}],
      "summary": {"exit_code": {"from": 1, "to": 1},
                  "counts": {"from": {}, "to": {}}}
    },
    "rua": {"status": "complete | undecidable", "...": "见 §5.2"},
    "baseline": {"ledger_id": "<sha256>", "summary": {}},
    "note": "差分只重跑 M2–M4；报文与 query.json 是既成事实，whatif 只改配置"
  }
}
```

- `whatif` 块是**报告信封**：它描述的是两份账本，所以**不参与差分、不参与 `ledger_id`**
  （否则自指）。账本 `ledger_id` 覆盖的是账本本体。
- **差分可复算**：把 `diff.ops` 施加到基线账本得到候选账本体；
  把 ops 反转（`add`↔`remove`、`set` 的 `from`/`to` 互换）施加到候选得到基线。
  **两个方向都必须成立**（`tests/test_whatif.py` 用两份独立的 CLI 产物断言，
  且逐字节比对——含 `ledger_id`）。
- `path` 是 JSON Pointer 形态（RFC 6901 的 `~0` / `~1` 转义）。
- 列表只在"等长且元素都是对象"时按下标递归；**长度不同就整表当一个值**——
  按下标对不等长列表做增删时重建顺序无法唯一定义。
- `changed_checks` 是**人读用**的摘要，不参与可逆性。

---

## 5.2 `rua` 关联（`whatif.rua`）

```json
{
  "status": "complete | undecidable",
  "policy_under_test": "reject",
  "org_name": "Example Receiver Co",
  "report_period": {"begin": 1767225600, "end": 1767312000},
  "period_note": "RUA 是聚合报告：它只覆盖报告期内的投递，且结论依赖报告方的观测口径……",
  "records": 3,
  "affected": [{"source_ip": "198.51.100.9", "header_from": "example.com", "count": 7,
                "spf": "fail", "dkim": "fail", "reported_disposition": "none",
                "would_be": "reject", "reason": "……"}],
  "affected_total": 1,
  "clusters": [{"header_from": "example.com", "source_ips": ["192.0.2.10"]}],
  "notes": []
}
```

- `affected` 的筛选口径是"**SPF 与 DKIM 都没有通过对齐**"（任一通过即对齐成立，
  不会被 `p=reject` 打断）。写成"任一不过就算"会把计数抬高，`rua.json` 里有一条
  "SPF fail 但 DKIM pass" 的记录专门用来把这条口径钉住。
- `period_note` 必须出现：**只覆盖报告期内，且依赖报告方的观测口径**——这与"本次审计
  这一时刻"不是一回事。
- `status: "undecidable"` 时 `affected` 为空并给出 `required_inputs[]`（缺什么列什么），
  **不猜**。**`--rua` 缺省不影响退出码**（退出码只由 `checks[]` 决定）：可选输入缺省若
  也算 undecidable，"不带 `--rua` 就永远非零"，那条功能就成了噪声。

---

## 5.3 `diff` 子命令的产物（`diff.json` / `diff.md`）

```json
{
  "schema_version": 1,
  "tool_version": "0.1.0.dev0",
  "baseline_ledger_id": "<sha256>",
  "candidate_ledger_id": "<sha256>",
  "diff": {"ops": [], "op_count": 0, "changed_checks": [], "summary": {}}
}
```

- `diff` 的 `schema_version` 是 `DIFF_SCHEMA_VERSION`，**不复用账本版本号**：
  它没有 `ledger_id`、也没有"退出码"的判定含义，混用会让两套时间线互相假装。
- `diff` 的**退出码恒为 0**：它是比较命令，"有差异"是正常输出，不是失败。
  映射成 `1` 会与"`1` = 存在 fail"撞语义。
- 未指定 `--json` / `--md` 时写 `diff.json` / `diff.md`（**不覆盖** `verdict.*`）——
  让 `diff` 盖掉 `verdict.json` 会让用户丢掉基线账本。

---

## 6 `verdict.md` / `diff.md`

人读版由 `verdict.json` 单向渲染，**不含 JSON 里没有的信息**。每节结构：

1. 结论摘要（exit code + 计数）。
2. 快照口径（`fetched_at` / `resolver` / `psl_version` / `psl_date`）。
3. 逐检查条目：结果 → 条款 → 轨迹摘要 → 告警。
4. 对账节：一致 / 矛盾（双解释）/ 无法判定 + **Received 链**（跳数、单调性、时钟回退）。
5. 反事实差分节（**仅 `whatif` 产物**）：施加的变更 → 与基线的差分 → RUA 关联。
6. 灰区声明：本次哪些结论属于不可判定及原因。

`diff.md` 的结构不同（它不是账本）：概要（两份 `ledger_id` + 退出码变化 + 计数变化）→
逐检查条目变化 → **结构差分表**（op / path / from / to，"把表施加到基线得到候选、
反转施加到候选得到基线"）。

渲染可复算：同一 `verdict.json` 两次渲染字节级一致。
`--strict-evidence` 下渲染结果仍会扫一遍禁词（第二道闸），命中即 exit 3。

---

## 7 版本与兼容

- `schema_version` 只在常量模块定义一次。加字段需升版本；删/改字段必须写迁移说明并在 `docs/backlog.md` 记录。
- 快照 schema 与账本 schema 各自独立版本号，互不复用。
- `DIFF_SCHEMA_VERSION` 管 `diff.json`，与上述两套**各自独立**（它既不是快照也不是账本）。
