# fixtures/dkim —— DKIM 验签样本

本组证五类失败各有一条可复现样本（题面 M2 验收 1），外加正样本与几条结构性样本。

**每个子目录 = 一个完整用例**：`message.eml` + `snap.json` + `query.json` + `expected.json`。
`expected.json` 的形状遵 `plan/04` §2.1（`case_id` / `input` / `expect` / `why`）。
全部由 `tools/gen_dkim_fixtures.py` 生成，`--check` 可逐字节复核幂等性。

| 编号 | 目录 | 形态 | 期望 |
|---|---|---|---|
| 正样本 | `d6-valid/` | relaxed/relaxed，2048 位密钥，SPKI 编码 | `pass`，`key_status=ok`，`key_bits=2048` |
| D1 | `d1-body-modified/` | 签名后改动正文 | `fail`，`bh_matches=false`，`failure_at.kind=body_hash` |
| D2 | `d2-header-modified/` | 签名后改动已签名头（Subject） | `fail`，`bh_matches=true`，`failure_at.kind=header_hash` |
| D3 | `d3-length-truncated/` | `l=` 只覆盖正文前 N 字节，改被排除的尾部 | `pass` + 告警「第 N 行起未受保护」 |
| D3b | `d3b-length-exceeds-body/` | `l=` 大于规范化正文长度 | `permerror`，`failure_at.kind=length_exceeds_body` |
| D4a | `d4a-key-not-queried/` | 快照里**没有查过**该选择器（空 queries） | `undecidable` + `data_gap`（**不是 fail**） |
| D4b | `d4b-key-nxdomain/` | 快照明确答复 NXDOMAIN | `permerror`（真的没有密钥），无 `data_gap` |
| D5 | `d5-key-weak-512/` | RSA-512（< 1024 位），裸 `RSAPublicKey` 编码 | `fail`，`key_status=weak`，`key_bits=512` |
| D7 | `d7-multi-signature/` | 两条签名：第 1 条针对另一份正文 | `[fail, pass]` —— **逐条求值、不短路** |
| D8 | `d8-unsigned/` | 无 `DKIM-Signature` | `none`（**不是 fail**） |
| D9 | `d9-missing-tag/` | 签名头缺 `d=` | `permerror`，`failure_at.kind=missing_tag` |

**D5 的 1024 位对照说明**：`< 1024` 是 RFC 8301 §3.2 的判据边界；恰好 1024 位**合格**，
不另设 1024 位样本（正样本 2048 位已覆盖"合格"一侧），边界两侧由
`tests/test_dkim.py::test_weak_key_is_fail_not_undecidable` 与正样本分别断言。

**为什么必须有正样本**：只有负样本的 fixture 集会让"永远返回 fail"的实现全部通过。
`tests/test_dkim.py::test_fixture_set_contains_a_positive_sample` 把这一点写成断言。

**为什么 D4a 与 D4b 是两条**："快照里没查过"与"查过了没有"是两件事（K13）。
前者是**待补的输入**（`undecidable` + `data_gap`），后者是**已得的结论**（`permerror`）。
只有一条 fixture 的话，把两者混为一谈的实现照样全绿。

**关于 `failure_at` 的行号/头名**：`bh=` 与 `b=` 都是单向哈希，验签器拿不到"哪一行/哪个头
不同"。本组因此给 `kind` + `basis` 而不编造位置——理由见 `plan/03` §3.3 与 `plan/06` G9。

## 密钥纪律

`keys/` 下的私钥**仅 fixture 使用，不得用于生产**，每个文件头写一行说明。

| 文件 | 内容 | 用途 |
|---|---|---|
| `keys/rsa2048-main.pem` | RSA-2048 私钥（PKCS#1 PEM） | 正样本、D1/D2/D3/D7 的签名 |
| `keys/rsa512-weak.txt` | RSA-512 的 `n`/`e`/`d` 三个十进制整数（**不是 PEM**：没有标准容器承载缺 p/q 的私钥，用 `.txt` 免得有人拿 `openssl` 去开） | D5（`cryptography` 拒绝生成 <1024 位，由生成器用纯 Python 素数搜索产出） |
| `keys/README.md` | 两把钥匙的公钥（`n` / `e` 十进制） | 人工核对 `p=` 与 PEM 是同一把钥匙 |

签名侧的独立性问题：样本由 `cryptography`（dev 期依赖）签，验签侧走
`mailvault/modules/dkim.py` 的零依赖实现——两侧不共享代码路径。
另用 dkimpy 1.1.8 逐条对账，结果与 2 条按 RFC 的有意差异见 `plan/04` §3.2。
