# fixtures/dmarc —— DMARC tree walk 与对齐样本（M4）

本组证四件事（题面 M3 验收 + `plan/05` M4 DoD）：

| 目录 | 形态 | 期望结果 | 证明什么 |
|---|---|---|---|
| `b41` | RFC 9989 Appendix B.4.1 的简单示例 | `pass` | 逐跳与附录一致（2 跳） |
| `b42` | Appendix B.4.2 的**深树走**（13 标签 Author） | `pass` | **8 标签跳步**：第 2 跳直接落到 7 标签处，全程 8 次查询 |
| `b43` | Appendix B.4.3 的 `psd=y` 示例 | `pass` | `psd=y` 让 Org 域变成记录**下面一层**；DKIM 侧不对齐 |
| `psd-n` | `psd=n` 让子域自成 Org 域 | `pass` | §4.10.2 步骤 1：走查就地停，**不再**看父域 |
| `np` | Author 域不存在（NXDOMAIN） | `fail` / `quarantine` | `np=` 与 `sp=` 取值不同，选错立刻可见 |
| `pct` | 旧标签 `pct=` / `rf=` / `ri=` | `fail` / `reject` | 三个标签各出一条"已被 RFC 9989 删除"告警，且不被采纳 |

每例四份产物：`snap.json` / `query.json` / `message.eml` / `expected.json`。
生成器 `tools/gen_dmarc_fixtures.py`（`--check` 逐字节幂等）。

## 纪律

**Organizational Domain 只看 tree walk，不看 PSL。** RFC 9989 §4.10 明确用走查替换了
RFC 7489 的 PSL 做法。所以：

- 判定用的 `organizational_domain` 由 §4.10.2 的走查得出；
- PSL 冻结件算出的值另存为 `psl_organizational_domain`，**仅作对照**；
- `psl_version` / `psl_date` 来自 `snap.json`（跨 PSL 版本的结果差异不是 bug，
  但必须能在输出里看到版本号——题面 §2.5 灰区 3）。

在 `psd=y` 的形态下两者**必然不同**（`b43` 就是这样），这个不等是信息，不是缺陷。

## 域映射

RFC 9989 的示例域用裸保留 TLD（B.4.3 的 `giant.bank.<example>`）。卫生门
（`tools/check_fixture_hygiene.py`）只认 `example.com` / `.net` / `.org` / `.invalid`
及其子域，所以示例整体落到 `.example.com` 下。**不放宽卫生门**——每放宽一次，
"fixture 引用了真实域名"这条红线就少一道护栏。每份 `expected.json` 的 `why` 里写明映射。
