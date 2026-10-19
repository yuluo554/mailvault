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
  "module": "M1",
  "subject": {"domain": "example.invalid", "scope": "mail_from"},
  "result": "pass | fail | softfail | neutral | none | temperror | permerror | undecidable",
  "reason": "human readable, no speculation",
  "evidence_ref": ["RFC7208#4.6.4", "RFC7208#5.2"],
  "trace": [],
  "budget": null,
  "warnings": []
}
```

### 2.1 `result` 枚举（唯一真源）

| 值 | 语义 |
|---|---|
| `pass` / `fail` / `softfail` / `neutral` / `none` | SPF 结果语义（RFC 7208） |
| `temperror` / `permerror` | 同上 |
| `undecidable` | **数据不足或规则本身是灰区**。禁止用 `fail` 代替 |

灰区一律 `undecidable`，并在 `reason` 中写明缺什么（缺 PTR、缺快照 key、PSL 版本影响、void 是 SHOULD 等）。

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

## 3 `budget`（M1 专用）

```json
{
  "terms":   {"used": 0, "limit": 10, "ref": "RFC7208#4.6.4"},
  "mx":      {"used": 0, "limit": 10, "ref": "RFC7208#4.6.4"},
  "ptr":     {"used": 0, "limit": 10, "ref": "RFC7208#4.6.4"},
  "void":    {"used": 0, "limit": 2,  "ref": "RFC7208#4.6.4", "limit_kind": "SHOULD"},
  "depth":   {"used": 0, "limit": null, "ref": "RFC7208#5.2"}
}
```

`limit_kind: "SHOULD"` 表示超限**不硬判 fail**，按 `undecidable` 处理并给告警。

---

## 4 `tree`（M1 完整 include 展开）

```json
{
  "node_id": "n0",
  "parent": null,
  "domain": "example.invalid",
  "record": "v=spf1 include:_spf.example.invalid -all",
  "mechanism": "include",
  "child_result": "pass",
  "consumes_term": true,
  "terminates_parent": false,
  "receiver_would_stop_here": false
}
```

- **完整展开**：不因第 10 个 term 而截断树。
- `receiver_would_stop_here: true` 标出"真实收件方会在此 permerror 停下"的切点（第 11 个 term 起）。
- `terminates_parent` 只对被 include 域自身的机制生效；子域的 `-all` 不终止父域处理（RFC 7208 §5.2）。

---

## 5 `reconcile`（M4）

```json
{
  "entries": [
    {
      "class": "consistent | contradiction | undecidable",
      "claimed": {"source": "Authentication-Results", "authserv_id": "mx.example.invalid", "method": "spf", "result": "pass"},
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
    "hop_count": 0
  }
}
```

**硬约束**：

- `class: contradiction` 时 `explanations` **必须 ≥ 2**，且每条带 `verify`。
- 在 `--strict-evidence` 下，全文禁止出现"攻击"、"伪造"、"被黑"等定性词；`strict_evidence_ok` 为自检位，false 直接非零退出。
- `authserv_id` 不可解析 → `class: undecidable`（fail-closed，参照 authres_status #86）。

---

## 6 `verdict.md`

人读版由 `verdict.json` 单向渲染，**不含 JSON 里没有的信息**。每节结构：

1. 结论摘要（exit code + 计数）。
2. 快照口径（`fetched_at` / `resolver` / `psl_version` / `psl_date`）。
3. 逐检查条目：结果 → 条款 → 轨迹摘要 → 告警。
4. 对账节：一致 / 矛盾（双解释）/ 无法判定。
5. 灰区声明：本次哪些结论属于不可判定及原因。

渲染可复算：同一 `verdict.json` 两次渲染字节级一致。

---

## 7 版本与兼容

- `schema_version` 只在常量模块定义一次。加字段需升版本；删/改字段必须写迁移说明并在 `docs/backlog.md` 记录。
- 快照 schema 与账本 schema 各自独立版本号，互不复用。
