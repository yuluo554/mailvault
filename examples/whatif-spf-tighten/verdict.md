# mailvault 判定账本

## 1 结论摘要

| 项 | 值 |
| --- | --- |
| 退出码 | `1` |
| pass | 0 |
| fail | 1 |
| undecidable | 0 |
| 账本 id | `646d3ab028ef6eba198828fe69892ac626604e9c18309dcab1888cd8f1c2d2ac` |

## 2 快照口径

| 项 | 值 |
| --- | --- |
| fetched_at（来自快照，非本机时钟） | `2026-10-19T18:35:00Z` |
| resolver | `synthetic` |
| PSL 版本 | `2026-10-20_08-40-56_UTC` |
| PSL 日期 | `2026-10-20` |

## 3 逐检查条目

### `spf.check_host`

- 结果：`fail`
- 理由：example.com：机制 -all 匹配，限定符为 -（RFC 7208 §4.6.2）
- 条款：`RFC7208#5.1`、`RFC7208#4.6.2`
- 对象：client_ip=`198.51.100.9`，dkim_signatures=`0`，domain=`example.com`，helo=`mail.example.com`，message_headers=`6`，scope=`mail_from`
- 求值轨迹：
  - `n0` example.com/TXT → rcode=NOERROR answer=1 条（queries[0]）
  - `n0` 选中记录：v=spf1 ip4:192.0.2.0/24 -all
- 预算账本：

  | 项 | 已用 | 上限 | 条款 |
  | --- | --- | --- | --- |
  | depth | 0 | 20 | `RFC7208#5.2` |
  | mx | 0 | 10 | `RFC7208#4.6.4` |
  | ptr | 0 | 10 | `RFC7208#4.6.4` |
  | terms | 0 | 10 | `RFC7208#4.6.4` |
  | void | 0 | 2 | `RFC7208#4.6.4` |

- include 树（完整展开；第 11 个起的 DNS 查询类 term 标为切点）：

  - `n0` 根记录（example.com） 记录 `v=spf1 ip4:192.0.2.0/24 -all`

### `dkim.verify_signature`

- 结果：`none`
- 理由：报文里没有 DKIM-Signature 头字段，本项判 none（不是 fail）
- 条款：`RFC6376#6.1`
- 对象：signatures_total=`0`
- 求值轨迹：
  - `n0` example.com/TXT → rcode=NOERROR answer=1 条（queries[0]）
  - `n0` 选中记录：v=spf1 ip4:192.0.2.0/24 -all
  - `dkim.extract` 报文头 6 个，其中 DKIM-Signature 0 条（逐条独立求值，不短路）
- 告警：
  - 报文未签名：dkim 判 none

### `dmarc.evaluate`

- 结果：`none`
- 理由：tree walk 逐跳都没有有效 DMARC Policy Record（2 跳：_dmarc.example.com=nxdomain、_dmarc.com=nxdomain）；§4.10.1：Mail Receivers MUST NOT apply the DMARC mechanism → none
- 条款：`RFC9989#4.10`、`RFC9989#4.10.1`
- 对象：author_domain=`example.com`，disposition=`None`，disposition_status=`not_applicable`，dkim_align_relaxed=`False`，dkim_align_strict=`False`，organizational_domain=`None`，policy_domain=`None`，policy_source=`None`，policy_tag=`None`，policy_value=`None`，psd=`None`，psl_date=`2026-10-20`，psl_organizational_domain=`example.com`，psl_version=`2026-10-20_08-40-56_UTC`，spf_align_relaxed=`False`，spf_align_strict=`False`，test_mode=`False`，walk_hit=`None`，walk_queries=`2`
- 求值轨迹：
  - `n0` example.com/TXT → rcode=NOERROR answer=1 条（queries[0]）
  - `n0` 选中记录：v=spf1 ip4:192.0.2.0/24 -all
  - `dkim.extract` 报文头 6 个，其中 DKIM-Signature 0 条（逐条独立求值，不短路）
  - `dmarc.author` RFC5322.From 提取到 1 个域：example.com
  - `snap.resolve` _dmarc.example.com/TXT → rcode=NXDOMAIN answer=0 条（queries[1]）
  - `walk.example.com.0` _dmarc.example.com → NXDOMAIN（问过了，没有这个域）
  - `snap.resolve` _dmarc.com/TXT → rcode=NXDOMAIN answer=0 条（queries[2]）
  - `walk.example.com.1` _dmarc.com → NXDOMAIN（问过了，没有这个域）
  - `dmarc.org` Author Domain example.com 的 Organizational Domain：（走查无命中）

### `reconcile.cross_check`

- 结果：`none`
- 理由：报文里没有可对账的 Authentication-Results 头；本项不构成判定（不是通过，也不是失败）
- 条款：`RFC8601#2.5`、`RFC8601#5`、`RFC5321#4.4`、`RFC5322#3.6.7`、`RFC8601#7.1`
- 对象：consistent=`0`，contradiction=`0`，entries=`0`，received_hops=`1`，received_monotonic=`True`，trusted_authserv_ids=`1`，undecidable=`0`
- 求值轨迹：
  - `received.0` Thu, 1 Jan 2026 00:00:00 +0000
- 告警：
  - 报文里没有 Authentication-Results 头，本次没有可对账的声称值

## 4 对账

（本次未做对账，或输入不含 `Authentication-Results`）

### Received 链

- 跳数：1
- 沿链单调（时间不递增）：是
- 时钟回退：无

> 时间只取报文头里的字面值，只做相互比较——**从不与系统时钟比较**（K7）。

对账说明：
- 报文里没有 Authentication-Results 头，本次没有可对账的声称值

## 5 反事实差分

### 施加的变更

- `all=-all` → 改 `example.com` 的 `queries[0].answer[0]`
  - `v=spf1 ip4:192.0.2.0/24 ?all`
  - → `v=spf1 ip4:192.0.2.0/24 -all`

### 与基线的差分

- 退出码：`0` → `1`
- 结构差分条目：9 处

| # | 检查项 | 结果 | 变化字段 |
| --- | --- | --- | --- |
| 0 | `spf.check_host` | `neutral` → `fail` | reason、result、trace、tree |
| 1 | `dkim.verify_signature` | `none` → `none` | trace |
| 2 | `dmarc.evaluate` | `none` → `none` | trace |

### RUA 关联

- 状态：`undecidable`
- 报告期：`None` → `None`
- 口径：RUA 是聚合报告：它只覆盖报告期内的投递，且结论依赖报告方的观测口径（source_ip 取样点、对齐判定实现）。这与『本次审计这一时刻』不是一回事——报告期内没出现，不等于以后不出现；报告期外发生的事，本报告看不见。
- 所需输入：
  - RUA 聚合报告（parsedmarc 导出的 JSON），含 report_metadata.date_range 与 records[]
  - 每条记录的 source_ip 与 count（用于聚类『会打断谁』）
  - 每条记录的 identifiers.header_from（被评估的 Author 域）
  - 每条记录的 policy_evaluated.dkim / .spf / .disposition（决定该条在 p=reject 下的后果）
  - 报告期（date_range.begin / end）——用于标注『只覆盖报告期内』

## 6 灰区声明

以下结论属于**不可判定**，不表示通过也不表示失败：

（本次无不可判定项）
