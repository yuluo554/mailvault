"""口径常量：**所有会漂移的数值只在这里定义一次**。

其它模块（含文档里的代码块、测试断言）只能引用常量名，不得复制字面量。
理由：同一数字写在两处，改一处必然漏另一处，而漏掉的那处不会报错、只会静默给错答案。

禁止把星数 / 下载量 / issue 数 / 检索总数写进本文件（题面 §5 扣分红线）。
那些数字只存在于 `data/README.md` 的"检索窗口快照"里。
"""

from __future__ import annotations

# ── SPF（RFC 7208 §4.6.4） ───────────────────────────────────────────────
SPF_MAX_TERMS = 10
"""term 限制。第 11 个 → permerror（MUST）。"""

SPF_MAX_MX = 10
"""MX 机制单次最多查 10 条。超限 → permerror（MUST）。"""

SPF_MAX_PTR = 10
"""PTR 机制单次最多查 10 条。超限 → permerror（MUST）。"""

SPF_MAX_VOID = 2
"""void lookup 上限是 **SHOULD**（RFC 7208 §4.6.4 原文 "SHOULD"）。

超限**不得硬判 fail**：判 ``undecidable`` 并给告警。这条是题面 §2.5 灰区 2 的直接落地。
"""

SPF_MAX_VOID_LIMIT_KIND = "SHOULD"

# ── DKIM（RFC 8301 §3.2） ────────────────────────────────────────────────
DKIM_MIN_KEY_BITS = 1024
"""低于此位数的 RSA 密钥 **必须**判无效（RFC 8301 §3.2）。"""

DKIM_SUPPORTED_ALGS = ("rsa-sha256", "rsa-sha1")
"""本工具能独立验签的算法。

``ed25519-sha256`` 不在其中（标准库无 Ed25519）→ 该签名的判定为 ``undecidable``，
并在 ``warnings`` 写明"本工具不支持该算法"，**不判 fail**。
"""

# ── Schema 版本（两套独立时间线，互不复用） ──────────────────────────────
SNAPSHOT_SCHEMA_VERSION = 1
"""`snap.json` 的 schema 版本。变更必须升版本并写迁移说明。"""

LEDGER_SCHEMA_VERSION = 1
"""`verdict.json` 的 schema 版本。与快照版本各自独立。"""

# ── 判定结果枚举（RFC 7208 七值 + 本项目的 undecidable） ─────────────────
RESULTS = (
    "none",
    "neutral",
    "pass",
    "fail",
    "softfail",
    "temperror",
    "permerror",
    "undecidable",
)
"""唯一结果枚举。``undecidable`` 是**一等结果**，不得被折叠成 ``fail``。

分组：
- SPF 语义（RFC 7208 §2.6）：none / neutral / pass / fail / softfail / temperror / permerror
- 本项目语义：undecidable（数据不足或规则本身是灰区）
"""

SPF_RESULTS = frozenset(RESULTS) - {"undecidable"}

RECONCILE_CLASSES = ("consistent", "contradiction", "undecidable")
"""M4 三方对账的三分类。"""

DMARC_DISPOSITIONS = ("none", "quarantine", "reject")

# ── 对齐模式 ─────────────────────────────────────────────────────────────
ALIGN_MODES = ("relaxed", "strict")
"""DMARC 对齐必须**双算**：两种模式各出一个结果，不合并。"""

# ── 表格：结果 → 是否属于 fail 类（退出码 1 的判定依据） ─────────────────
FAIL_RESULTS = frozenset({"fail", "permerror", "softfail"})
"""哪些结果算"存在 fail"。

``softfail`` 计入：它是发送方明确声明的"不通过"。``temperror`` 不算 fail（是临时故障），
按 undecidable 处理更贴近题面"灰区不虚高"的口径。
"""

# ── 文件形态 ─────────────────────────────────────────────────────────────
SNAPSHOT_FILENAME = "snap.json"
VERDICT_JSON_FILENAME = "verdict.json"
VERDICT_MD_FILENAME = "verdict.md"
