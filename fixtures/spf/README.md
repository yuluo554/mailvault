# fixtures/spf —— SPF 判定样本

本组证两件事：**RFC 7208 测试集能跑**，以及**预算账本能逐格读**。

## 内容（M1–M2 填充）

| 文件 | 作用 |
|---|---|
| `rfc7208-tests.yml` | pyspf 上游测试集（203 个 `spec:` 用例 / 16 分组），原样入仓 |
| `rfc7208-tests.LICENSE` | 上游 BSD 式许可，**必须保留** |
| `expected.json` | 本项目对测试集的结构化期望（见 `plan/04` §2.1） |

## 纪律

- 测试集里的域名由上游给出；若含非保留域，本组的 `README.md` 需注明"仅作 DNS 桩数据，不发起查询"，
  并在 `plan/04` §4 登记豁免。
- 所有 `snap.json` 的 `resolver` 必须是 `synthetic`，`fetched_at` 为合成时间。
- 不得为了"让用例通过"而改写上游期望值；口径差异逐条登记到 `data/rfc7208-failures.md`。
