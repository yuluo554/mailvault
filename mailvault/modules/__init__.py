"""L3 判定模块：把快照 + 输入变成带条款与轨迹的判定。

分层（`plan/03` §0）：本包只允许 import L1（`constants` / `exits` / `canonical`）与
L2（`snapshot` / `query` / `eml` / `psl`）。**不得 import 网络层**——审计阶段零网络
由 `tools/check_no_network.py` 扫 `mailvault/**/*.py` 保证（含本包）。
"""
