# mailvault 判定账本

## 1 结论摘要

| 项 | 值 |
| --- | --- |
| 退出码 | `0` |
| pass | 3 |
| fail | 0 |
| undecidable | 0 |
| 账本 id | `bb13a4487a3693f90f71191b252b59b6a90abab127c14ac1ad18659c2633225c` |

## 2 快照口径

| 项 | 值 |
| --- | --- |
| fetched_at（来自快照，非本机时钟） | `2026-10-19T18:35:00Z` |
| resolver | `synthetic` |
| PSL 版本 | `2026-10-20_08-40-56_UTC` |
| PSL 日期 | `2026-10-20` |

## 3 逐检查条目

### `spf.check_host`

- 结果：`pass`
- 理由：example.com：机制 ip4:192.0.2.0/24 匹配（RFC 7208 §5）
- 条款：`RFC7208#5.6`、`RFC7208#4.6.2`
- 对象：client_ip=`192.0.2.10`，dkim_signatures=`1`，domain=`example.com`，helo=`mail.example.com`，message_headers=`6`，scope=`mail_from`
- 求值轨迹：
  - `n0` example.com/TXT → rcode=NOERROR answer=1 条（queries[3]）
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

- 结果：`pass`
- 理由：正文哈希匹配，rsa-sha256 签名在 2048 位 RSA 公钥上验签通过
- 条款：`RFC6376#6.1.3`、`RFC6376#3.7`、`RFC6376#3.6.1`
- 对象：a=`rsa-sha256`，bh_matches=`True`，c=`relaxed/relaxed`，d=`signing.example.com`，failure_at=`None`，h=`['from', 'to', 'subject', 'date']`，index=`0`，key_bits=`2048`，key_status=`ok`，selector=`sel`，signatures_total=`1`
- 求值轨迹：
  - `dkim.sig` #0 位于报文第 2 个头字段
  - `dkim.h=` from to subject date
  - `dkim.t` t=1767225600（仅记录，不参与判定）
  - `snap.resolve` sel._domainkey.signing.example.com/TXT → rcode=NOERROR answer=1 条（queries[5]）
  - `dkim.key` signing.example.com 的选择器 sel → 查询 sel._domainkey.signing.example.com
  - `dkim.key_status` ok：RSA 2048 位（spki 编码）
  - `dkim.key_encoding` p= 编码为 spki
  - `dkim.bh` 正文规范化（relaxed）45 字节；覆盖 45 字节；bh 匹配
  - `dkim.headers` 已签名 4 个头字段（relaxed 规范化）+ 签名头自身（b= 置空）
- 告警：
  - 规范化 relaxed/relaxed：与默认值不同，已按 c= 声明求值

### `dmarc.evaluate`

- 结果：`pass`
- 理由：至少一个 Authenticated Identifier 与 Author Domain 对齐（SPF 侧 relaxed 模式=true / DKIM 侧 relaxed 模式=true）；§5.3.5 判 pass，不施加处置策略
- 条款：`RFC9989#4.10`、`RFC9989#4.10.1`、`RFC9989#4.10.2`、`RFC9989#4.4`、`RFC9989#5.3.5`
- 对象：author_domain=`example.com`，disposition=`None`，disposition_status=`not_applicable`，dkim_align_relaxed=`True`，dkim_align_strict=`False`，organizational_domain=`example.com`，policy_domain=`example.com`，policy_source=`author`，policy_tag=`None`，policy_value=`None`，psd=`u`，psl_date=`2026-10-20`，psl_organizational_domain=`example.com`，psl_version=`2026-10-20_08-40-56_UTC`，spf_align_relaxed=`True`，spf_align_strict=`True`，test_mode=`False`，walk_hit=`_dmarc.example.com`，walk_queries=`2`
- 求值轨迹：
  - `n0` example.com/TXT → rcode=NOERROR answer=1 条（queries[3]）
  - `n0` 选中记录：v=spf1 ip4:192.0.2.0/24 -all
  - `dkim.extract` 报文头 6 个，其中 DKIM-Signature 1 条（逐条独立求值，不短路）
  - `dkim.sig` #0 位于报文第 2 个头字段
  - `dkim.h=` from to subject date
  - `dkim.t` t=1767225600（仅记录，不参与判定）
  - `snap.resolve` sel._domainkey.signing.example.com/TXT → rcode=NOERROR answer=1 条（queries[5]）
  - `dkim.key` signing.example.com 的选择器 sel → 查询 sel._domainkey.signing.example.com
  - `dkim.key_status` ok：RSA 2048 位（spki 编码）
  - `dkim.key_encoding` p= 编码为 spki
  - `dkim.bh` 正文规范化（relaxed）45 字节；覆盖 45 字节；bh 匹配
  - `dkim.headers` 已签名 4 个头字段（relaxed 规范化）+ 签名头自身（b= 置空）
  - `dmarc.author` RFC5322.From 提取到 1 个域：example.com
  - `snap.resolve` _dmarc.example.com/TXT → rcode=NOERROR answer=1 条（queries[0]）
  - `walk.example.com.0` _dmarc.example.com → 记录 `v=DMARC1; p=reject; rua=mailto:dmarc@example.com`（psd=u）
  - `snap.resolve` _dmarc.com/TXT → rcode=NXDOMAIN answer=0 条（queries[2]）
  - `walk.example.com.1` _dmarc.com → NXDOMAIN（问过了，没有这个域）
  - `dmarc.org` Author Domain example.com 的 Organizational Domain：example.com
  - `align.spf` spf：example.com vs example.com → relaxed=true / strict=true（Organizational Domain：example.com / example.com）
  - `snap.resolve` _dmarc.signing.example.com/TXT → rcode=NOERROR answer=1 条（queries[1]）
  - `walk.signing.example.com.0` _dmarc.signing.example.com → 记录 `v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com`（psd=u）
  - `snap.resolve` _dmarc.example.com/TXT → rcode=NOERROR answer=1 条（queries[0]）
  - `walk.signing.example.com.1` _dmarc.example.com → 记录 `v=DMARC1; p=reject; rua=mailto:dmarc@example.com`（psd=u）
  - `snap.resolve` _dmarc.com/TXT → rcode=NXDOMAIN answer=0 条（queries[2]）
  - `walk.signing.example.com.2` _dmarc.com → NXDOMAIN（问过了，没有这个域）
  - `align.dkim` dkim：example.com vs signing.example.com → relaxed=true / strict=false（Organizational Domain：example.com / example.com）
  - `dmarc.verdict` aspf=relaxed / adkim=relaxed；SPF 在本侧模式下对齐=true、DKIM 在对齐模式下对齐=true → pass

### `reconcile.cross_check`

- 结果：`none`
- 理由：报文里没有可对账的 Authentication-Results 头；本项不构成判定（不是通过，也不是失败）
- 条款：`RFC8601#2.5`、`RFC8601#5`、`RFC5321#4.4`、`RFC5322#3.6.7`、`RFC8601#7.1`
- 对象：consistent=`0`，contradiction=`0`，entries=`0`，received_hops=`0`，received_monotonic=`True`，trusted_authserv_ids=`1`，undecidable=`0`
- 告警：
  - 报文里没有 Authentication-Results 头，本次没有可对账的声称值

## 4 对账

（本次未做对账，或输入不含 `Authentication-Results`）

### Received 链

- 跳数：0
- 沿链单调（时间不递增）：是
- 时钟回退：无

> 时间只取报文头里的字面值，只做相互比较——**从不与系统时钟比较**（K7）。

对账说明：
- 报文里没有 Authentication-Results 头，本次没有可对账的声称值

## 5 灰区声明

以下结论属于**不可判定**，不表示通过也不表示失败：

（本次无不可判定项）
