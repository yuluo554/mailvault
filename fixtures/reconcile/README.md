# fixtures/reconcile —— 三方对账样本

本组证三分类与"双解释"（题面 §3 的 M4 验收）。**由 `tools/gen_reconcile_fixtures.py`
生成**（`--check` 逐字节幂等），不要手改——生成器把"报文头声称什么"与"期望分类"
放在同一处，手改会让两者漂移。

| 编号 | 形态 | 期望 |
|---|---|---|
| `r1-forwarded` | 列表转发器改写信封发件人；`spf=fail` 但 `dkim=pass`，头里写的也是这两个值 | 2 条 `consistent`（**一致也要有样本**：只测矛盾会放过一个"永远判 contradiction"的实现） |
| `r2-gateway-body` | 网关在验签之后重写了正文；头里声称 `dkim=pass`，本工具重算 `fail`（`failure_at.kind=body_hash`） | 1 条 `contradiction`，≥2 条解释且每条带 `verify` |
| `r3-untrusted-ar` | `Authentication-Results` 的 authserv-id 是 `relay.example.org`，不在 `trusted_authserv_ids` 里 | 2 条 `undecidable`（fail-closed） |

每个目录 4 份产物：`message.eml` / `snap.json` / `query.json` / `expected.json`。

## 硬约束

- 每条 `contradiction` 必须有 **≥ 2 条解释**（`constants.RECONCILE_MIN_EXPLANATIONS`），
  每条带**具体的验证方法**（查什么、怎么看）。
- `--strict-evidence` 下全文不得出现定性词；对账模块在**装配期**就扫一遍自己生成的串
  （`strict_evidence_ok` 自检位），渲染期还有第二道闸。
- 报文、IP、域名全部合成（保留域 / 文档 IP 段）。
- `r2` 的 DKIM 签名是**真实签名**（复用 `tools/gen_dkim_fixtures.py` 的签名器）：
  对**原始正文**签名，再把正文换成网关改写后的版本。手写签名头只会得到
  `header_syntax`，`bh` 不匹配这条路径永远走不到。
- `r1` 的 `why` 里写明"一致"样本存在的理由；三分类都有样本由
  `tests/test_reconcile.py::test_fixture_shapes_are_the_three_required_scenarios` 断言。

## 卫生门的一处判据改动（M5）

报文头里的 `smtp.mailfrom=` 是 RFC 8601 §2.2 的 **ptype 关键字**，形态却与两级域名
无法区分（`smtp.mailfrom` 的"TLD"是 8 个字母）。`tools/check_fixture_hygiene.py`
因此新增一条：剥掉 `ptype.property=` 前缀后再扫。**这不是放宽判据**——
`=` 右边真正的域名照旧被扫到；把同一个属性值换成某个真实域名，门会照样报红
（负样本见 `tests/test_reconcile.py::
test_hygiene_gate_strips_ar_ptype_but_still_catches_a_real_domain`，
那里用的是测试临时目录，不在本组 fixture 里）。
