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

SPF_MAX_DEPTH = 20
"""``include`` / ``redirect`` 嵌套深度上限。

RFC 7208 §4.6.4 的 10 term 限制已能间接封顶深度（每层至少消费 1 term），
这个上限是**第二道**保险：用于挡住"记录里 include 成环但每层都不计 term"这类病态输入，
避免求值器把递归栈跑穿。超限按 ``permerror`` 处理。
"""

SPF_TREE_MAX_NODES = 256
"""``tree`` 输出里最多展开多少个节点。

树本身**不参与判定**（用独立 shadow 上下文），所以这个上限只影响诊断输出，
不影响任何判定结果。存在的理由是防止"成环的 include 图"把内存跑满。
"""

# ── DKIM（RFC 6376 / RFC 8301） ──────────────────────────────────────────
DKIM_MIN_KEY_BITS = 1024
"""低于此位数的 RSA 密钥 **必须**判无效（RFC 8301 §3.2 "MUST NOT consider ... valid"）。"""

DKIM_SUPPORTED_ALGS = ("rsa-sha256",)
"""本工具**接受**的算法（会给出 pass/fail 判定）。

划分依据是 RFC 8301 §3.1（它更新了 RFC 6376 的算法矩阵）：

- ``rsa-sha256``：Signers MUST sign / Verifiers MUST verify → 本工具接受。
- ``rsa-sha1``：原文 "rsa-sha1 MUST NOT be used for signing or verifying"，且
  §3 收尾说这类签名 "have permanently failed evaluation" → 归 :data:`DKIM_FORBIDDEN_ALGS`，
  本工具**会**算出密码学结果（诊断用）但不据此判 pass。
- ``ed25519-sha256``：标准库没有 Ed25519 → 归 :data:`DKIM_UNSUPPORTED_ALGS`，
  判 ``undecidable`` 并写明"本工具不支持该算法"，**不判 fail**（`plan/02` §4）。
"""

DKIM_FORBIDDEN_ALGS = ("rsa-sha1",)
"""RFC 8301 §3.1 明令不得用于签名或验签的算法。命中即 ``permerror``（永久失败）。"""

DKIM_UNSUPPORTED_ALGS = ("ed25519-sha256",)
"""本工具**无能力**判定（不是"签名坏了"）的算法 → ``undecidable`` + 告警。"""

DKIM_KEY_STATUSES = ("ok", "revoked", "missing", "weak", "invalid")
"""``key_status`` 的取值集合（`plan/03` §3.3）。

- ``ok``：记录存在、可解析、未撤销、位数达标。
- ``revoked``：``p=`` 为空（RFC 6376 §3.6.1 "An empty value means that this public key
  has been revoked"）。
- ``missing``：快照里没有这条查询（数据缺口）**或**快照明确答复了 NXDOMAIN / 空答复。
  两者结果不同（前者 ``undecidable``、后者 ``permerror``），但键状态同为 ``missing``
  ——"这条选择器名下没有可用密钥"。
- ``weak``：RSA 位数 < :data:`DKIM_MIN_KEY_BITS`（RFC 8301 §3.2）。
- ``invalid``：记录存在但不可用（语法错、``k=`` 非 rsa、``h=`` 排除该哈希、``s=`` 不含 email）。

``None`` 表示**没有取证**（签名本身在取密钥之前就被判死了，例如算法不支持）。
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
"""M5 三方对账的三分类。"""

RECONCILE_SOURCES = ("Authentication-Results", "Received-SPF")
"""对账的"报文声称"一侧读哪些头。

``Received-SPF`` 只作**补充证据**（`plan/01` §3 的 M4 对象三种）；判定用的
authserv-id 只认 ``Authentication-Results``（RFC 8601 §2.5）。
"""

RECONCILE_MIN_EXPLANATIONS = 2
"""每条 ``contradiction`` 至少要给几条解释（题面 M4 硬性要求：两种可能解释 + 各自验证方法）。

写进常量而不是散在代码里：这是**验收断言**，不是实现偏好；测试与实现同引一个名字。
"""

STRICT_FORBIDDEN = (
    "攻击",
    "伪造",
    "被黑",
    "黑客",
    "hacked",
    "forged",
    "attack",
    "compromised",
)
"""``--strict-evidence`` 的禁词表（K10）。

**唯一出处**：`render.py` 与 `modules/reconcile.py` 都从这里取——
对账模块要在**装配期**自检"我生成的解释里有没有定性词"，而渲染期只是最后一道闸。
两处各写一份禁词表必然漂移：改了渲染忘了对账，strict 模式就会"渲染通过、
解释里却写着'伪造'"。题面 §5 扣分红线明令禁止。
"""

#: what-if 允许的变更键（`plan/01` §3 的 M5 候选变更 + `plan/03` §3.6）。
#: 未知键 → ``InputError``（exit 3），**不静默忽略**（`plan/03` §2 第 3 条）。
WHATIF_CHANGE_KEYS = ("p", "sp", "np", "t", "all", "include")
"""``--change KEY=VALUE`` 的合法键。

- ``p`` / ``sp`` / ``np``：改 ``_dmarc`` 记录里的策略标签（值 ∈ :data:`DMARC_DISPOSITIONS`）。
- ``t``：改 ``t=`` 测试模式（``y`` / ``n``）。
- ``all``：改 SPF 记录的末尾限定符（``+all`` / ``-all`` / ``~all`` / ``?all``）。
- ``include``：往 SPF 记录里插一条 ``include:<domain>``（值就是域名）。
"""

WHATIF_SPF_ALL_VALUES = ("+all", "-all", "~all", "?all")
"""``--change all=`` 的合法取值（RFC 7208 §5.1 的四个限定符 + ``all`` 机制）。"""

#: diff 产物的 schema 版本（与账本各自独立，`plan/04` §3.4 的两套时间线不混）。
DIFF_SCHEMA_VERSION = 1

DMARC_DISPOSITIONS = ("none", "quarantine", "reject")
"""``disposition`` 的取值集合（RFC 9989 §4.7 的 ``dmarc-request``）。

同时是 ``p=`` / ``sp=`` / ``np=`` 三个标签的**合法值集合**——ABNF 里三者共用
``dmarc-request``，写两处必然漂移。
"""

# ── DMARC（RFC 9989） ───────────────────────────────────────────────────
DMARC_RECORD_LABEL = "_dmarc"
"""记录发布位置的前缀标签（§4.5：``_dmarc.<domain>`` 的 TXT）。"""

DMARC_VERSION = "DMARC1"
"""``v=`` 的唯一合法值，**大小写敏感**（§4.7："the only possible value is 'DMARC1'"）。"""

DMARC_MAX_LABELS = 8
"""tree walk 的查询上限所对应的标签数（§4.10 的反滥用捷径）。

原文："Author Domains with more than eight labels do not result in more than eight DNS queries"。
超限时走"保留 7 个标签"的跳步，而不是逐级爬。
"""

DMARC_TREE_KEEP_LABELS = 7
"""超限跳步后保留的最右标签数（§4.10 步骤 4："until 7 labels remain"）。"""

DMARC_DEFAULT_ALIGN = "r"
"""``adkim=`` / ``aspf=`` 的默认值（§4.7："default is 'r'"）。"""

DMARC_ALIGN_VALUES = ("r", "s")
"""对齐模式取值：``r`` = relaxed，``s`` = strict（§4.7）。"""

DMARC_PSD_VALUES = ("y", "n", "u")
"""``psd=`` 的取值（§4.7）。``u`` 是默认值："use the mechanism described in Section 4.10"。"""

DMARC_DEFAULT_PSD = "u"

DMARC_REMOVED_TAGS = ("pct", "rf", "ri")
"""RFC 9989 **已删除**的标签（Appendix C.5.2）。出现即告警，**不得静默忽略**。

``pct`` 另见 Appendix A.6（题面 M3 验收 2 点名）。这三个标签本工具**不解释语义**
（RFC 9989 已无定义），但也不假装没看见——静默忽略会让读者以为"pct=0 被尊重了"。
"""

DMARC_TEST_MODE_DOWNGRADE = {"none": "none", "quarantine": "none", "reject": "quarantine"}
"""``t=y`` 的降级表（§4.7）：``quarantine``→``none``，``reject``→``quarantine``，``none`` 不变。"""

DMARC_DISPOSITION_STATUSES = ("determined", "undecidable", "not_applicable")
"""``disposition`` 能否给出。

- ``determined``：机制判 fail，且策略可确定（``disposition`` 非 null）。
- ``not_applicable``：机制未 fail（pass/none），没有"处置"这回事。
- ``undecidable``：缺输入导致"该用哪个策略标签"判不出来（K13）。此时**不猜**
  ——用 ``p=`` 顶上会让账本给出一个看着确定的错答案。
"""

DMARC_DNS_ERROR_RCODES = ("SERVFAIL", "TIMEOUT", "REFUSED", "FORMERR", "NOTIMP")
"""DNS 错误（区别于"问过了没有"）。§5.3.6：此时报文"不能算 pass 也不能算 fail"。"""

DMARC_WALK_STATUSES = (
    "record",
    "no_record",
    "nxdomain",
    "multiple_records",
    "invalid_record",
    "dns_error",
    "not_queried",
)
"""tree walk 每跳的状态。``not_queried`` 是数据缺口（K13），**不是** ``no_record``。"""

# ── 对齐模式 ─────────────────────────────────────────────────────────────
ALIGN_MODES = ("relaxed", "strict")
"""DMARC 对齐必须**双算**：两种模式各出一个结果，不合并。"""

# ── 表格：结果 → 是否属于 fail 类（退出码 1 的判定依据） ─────────────────
FAIL_RESULTS = frozenset({"fail", "permerror", "softfail"})
"""哪些结果算"存在 fail"。

``softfail`` 计入：它是发送方明确声明的"不通过"。``temperror`` 不算 fail（是临时故障），
按 undecidable 处理更贴近题面"灰区不虚高"的口径。
"""

# ── 快照抓取（`snapshot fetch`，唯一联网动作） ───────────────────────────
DNS_PORT = 53
"""DNS 服务端口。UDP 优先，响应截断（TC=1）时退化为 TCP。"""

DNS_TIMEOUT_SECONDS = 5
"""单次查询超时（秒）。超时**不是**"没有记录"：落盘为 ``rcode="TIMEOUT"``。"""

DNS_MAX_CNAME_HOPS = 8
"""CNAME 链最多跟几跳。超过按 ``temperror`` 语义记录，不无限递归。"""

DNS_DEFAULT_RESOLVER = "8.8.8.8"
"""未给 ``--resolver`` 时使用的解析器。

刻意写死一个**公共**解析器而不是读系统配置：本机 ``/etc/resolv.conf`` 在 Windows 上不存在，
"默认跟随系统"会让同一命令在不同机器上抓出不同快照。
要跟随本地解析器请显式传 ``--resolver``。
"""

DNS_QCLASS_IN = 1

DNS_TYPE_BY_NAME = {
    "A": 1,
    "CNAME": 5,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}
"""本工具会写入快照的记录类型（`plan/01` §4 的五字段查询）。"""

DNS_RCODE_BY_VALUE = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

DNS_RCODE_TIMEOUT = "TIMEOUT"
"""伪 rcode：查询超时。**不允许**与 NXDOMAIN 混同——前者是"没问到"，后者是"问过了没有"。"""

# ── 文件形态 ─────────────────────────────────────────────────────────────
SNAPSHOT_FILENAME = "snap.json"
VERDICT_JSON_FILENAME = "verdict.json"
VERDICT_MD_FILENAME = "verdict.md"

#: `diff` 子命令未指定 `--json` / `--md` 时的默认文件名。
#: 与 `verdict.*` **分开**：三条命令落在同一目录时不会互相覆盖——
#: "diff 把 verdict.json 盖掉"会让用户丢掉基线账本。
DIFF_JSON_FILENAME = "diff.json"
DIFF_MD_FILENAME = "diff.md"
