# mailvault 账本差分

## 1 概要

| 项 | 值 |
| --- | --- |
| 基线账本 id | `83267db736c20d90ac9995bcf18190c412ea7a2e2caa25b410d7b70b8fe2ed2b` |
| 候选账本 id | `fed022e2442d0aff6b1f21c087558351c11bc6b78722bd36c59240e230459d0f` |
| 结构差分条目 | 6 |
| 退出码 | `1` → `1` |
| pass | 0 → 0 |
| fail | 2 → 2 |
| undecidable | 0 → 0 |

## 2 逐检查条目变化

| # | 检查项 | 结果 | 变化字段 |
| --- | --- | --- | --- |
| 2 | `dmarc.evaluate` | `fail` → `fail` | reason、subject、trace |

## 3 结构差分（可复算）

把下表施加到基线得到候选；把 `op` 反转（`add`↔`remove`、`set` 的 from/to 互换）
施加到候选则得到基线——**两个方向都能反推**。

| op | 路径 | from | to |
| --- | --- | --- | --- |
| `set` | `/checks/2/reason` | `DMARC 判 fail；Author Domain 的 p=none → 处置 none` | `DMARC 判 fail；Author Domain 的 p=reject → 处置 reject` |
| `set` | `/checks/2/subject/disposition` | `none` | `reject` |
| `set` | `/checks/2/subject/policy_value` | `none` | `reject` |
| `set` | `/checks/2/trace/5/note` | `_dmarc.example.com → 记录 `v=DMARC1; p=none; rua=mailto:dmarc@example.com`（psd=u）` | `_dmarc.example.com → 记录 `v=DMARC1; p=reject; rua=mailto:dmarc@example.com`（ps...` |
| `set` | `/ledger_id` | `83267db736c20d90ac9995bcf18190c412ea7a2e2caa25b410d7b70b8fe2ed2b` | `fed022e2442d0aff6b1f21c087558351c11bc6b78722bd36c59240e230459d0f` |
| `add` | `/whatif` | `（无）` | `{'baseline': {'ledger_id': '83267db736c20d90ac9995bcf18190c412ea7a2e2caa25b41...` |
