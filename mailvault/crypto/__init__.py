"""L1 密码学原语：DER 解析 + RSA PKCS#1 v1.5 验签。

分层（`plan/03` §0）：本包只许 import 标准库与 L1 同级模块。**不得 import 网络层**
（`tools/check_no_network.py` 扫 `mailvault/**`），**不得 import 第三方**——这正是
本包存在的原因：DKIM 验签不能把 `cryptography` 拖进运行时依赖（`plan/02` §4）。

两个模块的分工：

- :mod:`mailvault.crypto.der`：字节 → ``n`` / ``e``（只读 TLV，不解释语义）
- :mod:`mailvault.crypto.rsa`：``n`` / ``e`` + 签名 + 摘要 → 通过 / 不通过（严格填充比对）
"""
