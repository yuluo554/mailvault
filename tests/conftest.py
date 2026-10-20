"""测试夹具：把仓库根加入 sys.path，使 `mailvault` 可直接 import（无需安装）。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
