# mailvault 判定账本

## 1 结论摘要

| 项 | 值 |
| --- | --- |
| 退出码 | `2` |
| pass | 2 |
| fail | 1 |
| undecidable | 1 |
| 账本 id | `6eb949be6761ab6310dc7f2ed765b0c676b86be90a1571ed3263287c9335827a` |

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
- 对象：client_ip=`192.0.2.10`，dkim_signatures=`1`，domain=`example.com`，helo=`mail.example.com`，message_headers=`9`，scope=`mail_from`
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

- 结果：`fail`
- 理由：正文哈希与 bh= 不符（RFC 6376 §6.1.3 第 3 步：body hash did not verify）
- 条款：`RFC6376#6.1.3`、`RFC6376#3.7`
- 对象：a=`rsa-sha256`，bh_matches=`False`，c=`relaxed/relaxed`，d=`example.com`，failure_at=`{'kind': 'body_hash', 'body_line': None, 'basis': 'bh= 是单向摘要，没有原文无法反推是哪一行被改；本工具不猜行号', 'l': None, 'canonical_length': 122}`，h=`['from', 'to', 'subject', 'date']`，index=`0`，key_bits=`2048`，key_status=`ok`，selector=`selrec`，signatures_total=`1`
- 求值轨迹：
  - `dkim.sig` #0 位于报文第 2 个头字段
  - `dkim.h=` from to subject date
  - `dkim.t` t=1767225600（仅记录，不参与判定）
  - `snap.resolve` selrec._domainkey.example.com/TXT → rcode=NOERROR answer=1 条（queries[2]）
  - `dkim.key` example.com 的选择器 selrec → 查询 selrec._domainkey.example.com
  - `dkim.key_status` ok：RSA 2048 位（spki 编码）
  - `dkim.key_encoding` p= 编码为 spki
  - `dkim.bh` 正文规范化（relaxed）122 字节；覆盖 122 字节；bh 不匹配
- 告警：
  - 规范化 relaxed/relaxed：与默认值不同，已按 c= 声明求值

### `dmarc.evaluate`

- 结果：`pass`
- 理由：至少一个 Authenticated Identifier 与 Author Domain 对齐（SPF 侧 relaxed 模式=true / DKIM 侧 relaxed 模式=false）；§5.3.5 判 pass，不施加处置策略
- 条款：`RFC9989#4.10`、`RFC9989#4.10.1`、`RFC9989#4.10.2`、`RFC9989#4.4`、`RFC9989#5.3.5`
- 对象：author_domain=`example.com`，disposition=`None`，disposition_status=`not_applicable`，dkim_align_relaxed=`False`，dkim_align_strict=`False`，organizational_domain=`example.com`，policy_domain=`example.com`，policy_source=`author`，policy_tag=`None`，policy_value=`None`，psd=`u`，psl_date=`2026-10-20`，psl_organizational_domain=`example.com`，psl_version=`2026-10-20_08-40-56_UTC`，spf_align_relaxed=`True`，spf_align_strict=`True`，test_mode=`False`，walk_hit=`_dmarc.example.com`，walk_queries=`2`
- 求值轨迹：
  - `n0` example.com/TXT → rcode=NOERROR answer=1 条（queries[0]）
  - `n0` 选中记录：v=spf1 ip4:192.0.2.0/24 -all
  - `dkim.extract` 报文头 9 个，其中 DKIM-Signature 1 条（逐条独立求值，不短路）
  - `dkim.sig` #0 位于报文第 2 个头字段
  - `dkim.h=` from to subject date
  - `dkim.t` t=1767225600（仅记录，不参与判定）
  - `snap.resolve` selrec._domainkey.example.com/TXT → rcode=NOERROR answer=1 条（queries[2]）
  - `dkim.key` example.com 的选择器 selrec → 查询 selrec._domainkey.example.com
  - `dkim.key_status` ok：RSA 2048 位（spki 编码）
  - `dkim.key_encoding` p= 编码为 spki
  - `dkim.bh` 正文规范化（relaxed）122 字节；覆盖 122 字节；bh 不匹配
  - `dmarc.author` RFC5322.From 提取到 1 个域：example.com
  - `snap.resolve` _dmarc.example.com/TXT → rcode=NOERROR answer=1 条（queries[3]）
  - `walk.example.com.0` _dmarc.example.com → 记录 `v=DMARC1; p=none; rua=mailto:dmarc@example.com`（psd=u）
  - `snap.resolve` _dmarc.com/TXT → rcode=NXDOMAIN answer=0 条（queries[4]）
  - `walk.example.com.1` _dmarc.com → NXDOMAIN（问过了，没有这个域）
  - `dmarc.org` Author Domain example.com 的 Organizational Domain：example.com
  - `align.spf` spf：example.com vs example.com → relaxed=true / strict=true（Organizational Domain：example.com / example.com）
  - `dmarc.verdict` aspf=relaxed / adkim=relaxed；SPF 在本侧模式下对齐=true、DKIM 在对齐模式下对齐=false → pass
- 告警：
  - 没有结论为 pass 的 DKIM 签名：不构成 DKIM-Authenticated Identifier（§4.4.1），两侧对齐均为 false

### `reconcile.cross_check`

- 结果：`undecidable`
- 理由：对账 1 条：一致 0、矛盾 1、无法判定 0——存在矛盾或无法判定即判 undecidable，不折成 fail
- 条款：`RFC8601#2.5`、`RFC8601#5`、`RFC5321#4.4`、`RFC5322#3.6.7`、`RFC8601#7.1`
- 对象：consistent=`0`，contradiction=`1`，entries=`1`，received_hops=`2`，received_monotonic=`True`，trusted_authserv_ids=`1`，undecidable=`0`
- 求值轨迹：
  - `received.0` Thu, 1 Jan 2026 00:00:03 +0000
  - `received.1` Thu, 1 Jan 2026 00:00:01 +0000

## 4 对账

### `contradiction`

- 报文声称：`dkim` = `pass`（来源 `Authentication-Results`，authserv-id `mx.example.com`）
- 本工具重算：`fail`
- 可能解释与验证方法：
  1. **内容网关在验签之后重写了正文（追加页脚、清洗 HTML、重排空白）** → 验证：把正文与签名者留存的原件比对；检查正文尾部是否多出网关声明或页脚，并看 dkim 条目的 failure_at.kind 是否为 body_hash
  2. **报文在归档或转发途中被改（不是签名者改的）** → 验证：用签名者留存的原件重算 bh=；若原件能过而这份过不了，说明改动发生在传输/归档环节
  3. **报文头声称的签名与报文里现存的签名不是同一条** → 验证：比对 claimed 的 header.d / header.s 与报文里每条签名的 d= / s=；本工具看到的签名域是 example.com

### Received 链

- 跳数：2
- 沿链单调（时间不递增）：是
- 时钟回退：无

> 时间只取报文头里的字面值，只做相互比较——**从不与系统时钟比较**（K7）。

## 5 灰区声明

以下结论属于**不可判定**，不表示通过也不表示失败：

- `reconcile.cross_check`：对账 1 条：一致 0、矛盾 1、无法判定 0——存在矛盾或无法判定即判 undecidable，不折成 fail
