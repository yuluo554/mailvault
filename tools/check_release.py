#!/usr/bin/env python3
"""发布门（M6）：发布**三态**各自可复跑。

发布棒要回答的不是"代码能不能跑"（那是别的门的事），而是
**"这个仓库现在处在发布的哪一态，那一态该有的东西齐不齐"**。所以本门有三种模式：

| 模式 | 什么时候跑 | 判什么 |
|---|---|---|
| `--offline` | 随时（**不碰网络**，CI 也跑这一档） | 发布内容齐备：版本三处一致、样例产物齐且干净、发布留档两栏齐、**交付面未被改动** |
| `--pre-tag` | `git tag` **之前**（本机） | `--offline` 的全部 + **tag 尚未创建** + **工作区干净** |
| `--online` | 推送与 Release **之后**（本机） | `--offline` 的全部 + 远端存在 + tag 已推 + Release 在 + CI run 实录 |

**为什么必须分开**：`tag` 之后 `--pre-tag` 就该红（那一态已经过去了），
而在 CI 里跑 `--pre-tag` 会在 tag 推送那一刻变成假红——所以 CI 只跑 `--offline`。
把三态分开，每条判据在它**确实成立的那一态**才是判据。

**为什么清单式的判据要落在这里而不是测试里**：这三条都不是"代码行为"，
而是"发布现场"——`git`/`gh`/网络。测试拿不到这些，也没法在 CI 的四矩阵里跑。

**为什么"交付面未被改动"落在 `--offline` 档**：`--offline` 的前提是"不碰网络"，
**不是"不碰 git"**；把这条只放进 `--pre-tag`，等于只有本机手工跑才查得到，
而 D1 的漂移正是这么漏掉的（`--offline` 在仓库 HEAD 与 tag 导出树里都报全绿）。
无 `.git`（sdist 解包树、浅克隆）时**显式 SKIP —— 不是 PASS**。

用法：

    py -3.12 tools/check_release.py --offline
    py -3.12 tools/check_release.py --pre-tag
    py -3.12 tools/check_release.py --online

退出码：0 全绿 / 1 有 FAIL / 2 用法错误。
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FINAL_MILESTONE = 6
VERSION_TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+)$")

#: 归档样例：用例 → 必须存在的产物。
EXAMPLE_CASES = {
    "reconcile-r2-gateway-body": ["verdict.json", "verdict.md"],
    "dmarc-b41": ["verdict.json", "verdict.md"],
    "whatif-spf-tighten": ["verdict.json", "verdict.md"],
    "diff-p-reject": ["baseline.json", "candidate.json", "diff.json", "diff.md"],
}

RELEASE_DOC = "plan/RELEASE-M%d.md" % FINAL_MILESTONE
#: 发布留档必须有两栏；`--online` 还要求第二栏已回填。
COLUMN_ONE = re.compile(r"^##\s*一、tag 前事实", re.M)
COLUMN_TWO = re.compile(r"^##\s*二、tag 后", re.M)
COVERAGE = re.compile(r"^#{2,3}.*覆盖对账", re.M)

#: 第二栏里的**机器可读两行**（本门与 `plan/RELEASE-M6.md` 的契约）。
RUN_ID_ROW = re.compile(r"^\|\s*CI run id[^|]*\|\s*`?(\d+)`?\s*\|", re.M)
PUSH_RUN_ROW = re.compile(r"^\|\s*push 数 = run 数\s*\|\s*`?(\d+)\s*=\s*(\d+)`?\s*\|", re.M)
#: 「这个计数截至哪个提交」——绝对数字必须锚在一个可核对的提交上，否则无法对账。
#: 单元格里 sha 之后允许跟说明文字（留档要解释为什么锚在这里）。
SNAPSHOT_ROW = re.compile(r"^\|\s*计数截至提交\s*\|\s*`?([0-9a-f]{7,40})`?", re.M)

#: Release 说明必须点到的三件套要素（`plan/05` §4.1）。
RELEASE_KEYWORDS = ("verdict.json", "verdict.md", "fixture", "PSL")

#: 交付面 = 打 tag 之后**不许再动**的面（`AGENTS.md` 硬性纪律第 1 条）。
DELIVERABLE_PATHS = ("mailvault", "pyproject.toml")

#: 已登记的「交付面偏差」：相对路径 → (允许的工作区 blob OID, 理由)。
#:
#: 为什么登记 **blob OID** 而不是「允许这个路径漂移」：路径级白名单会把整份文件永久放行，
#: 于是登记之后对该文件的任何改动都看不见——那正是本判据要防的事。登记 blob 之后，
#: **只放行这一处已知偏差**，再改一个字 hash 就变、判据立刻红。
#:
#: 为什么还要「僵尸检测」：偏差消失（例如下次发版把 `pyproject.toml` 正规化进 tag）之后，
#: 这条登记必须一起删掉，否则它变成一条永远不被执行的白名单——本仓对登记表的一贯口径是
#: 「登记表不能有僵尸条目」（`test_every_known_divergence_actually_happens` 是同一手法）。
REGISTERED_DEVIATIONS: dict[str, tuple[str, str]] = {
    "pyproject.toml": (
        "c756dfc4ba55eaab446748b5b78f7a9518693e29",
        "bb19d9e 的 PEP 639 迁移：`license` 表→SPDX 字符串 + `setuptools>=68`→`>=77` + "
        "删 `License::` classifier + 加 `license-files`（mailvault/ 源码零差异，不改运行行为）",
    ),
}


class Report:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.rows: list[tuple[str, str, str]] = []

    def check(self, label: str, ok: bool, detail: str = "") -> bool:
        self.rows.append((label, "PASS" if ok else "FAIL", detail))
        return bool(ok)

    def skip(self, label: str, detail: str = "") -> None:
        """不适用 ≠ 通过。SKIP 不进 FAIL 计数，但必须在输出里看得见。"""
        self.rows.append((label, "SKIP", detail))

    def render(self) -> int:
        print("发布门 · 模式 %s" % self.mode)
        print("=" * 72)
        for label, status, detail in self.rows:
            print("%-4s  %-34s %s" % (status, label, detail))
        failed = [row for row in self.rows if row[1] == "FAIL"]
        skipped = [row for row in self.rows if row[1] == "SKIP"]
        print("=" * 72)
        print("这轮跑了 %d 条判据" % (len(self.rows) - len(skipped)))
        if skipped:
            print("其中 %d 条 SKIP（不适用，**不计为通过**）：%s"
                  % (len(skipped), "、".join(row[0] for row in skipped)))
        print("结论: %s" % ("全绿" if not failed else "%d 项 FAIL" % len(failed)))
        return 1 if failed else 0


# ── 内容齐备（三种模式共用） ────────────────────────────────────────────


def _version() -> str:
    import mailvault

    return mailvault.__version__


def content_checks(report: Report) -> None:
    import tomllib

    version = _version()

    # 1. 版本"三处一致"（`plan/05` §4.2；同样的事实由 tests/test_version_consistency.py 断言）
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    attr = pyproject["tool"]["setuptools"]["dynamic"]["version"]["attr"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    report.check(
        "版本三处一致",
        attr == "mailvault.__version__" and ("v" + version) in readme
        and re.fullmatch(r"\d+\.\d+\.\d+", version) is not None,
        "version=%s attr=%s README含v%s=%s" % (version, attr, version, ("v" + version) in readme),
    )

    # 2. 归档样例齐备（`--strict-evidence` 产出的真产物）
    missing: list[str] = []
    for case, names in EXAMPLE_CASES.items():
        for name in names:
            if not (ROOT / "examples" / case / name).is_file():
                missing.append("examples/%s/%s" % (case, name))
    report.check("归档样例齐备", not missing,
                 "缺 %s" % ", ".join(missing) if missing
                 else "%d 个用例 / %d 份产物" % (len(EXAMPLE_CASES),
                                                sum(len(v) for v in EXAMPLE_CASES.values())))

    # 3. 样例的 tool_version 与当前版本绑定（定版后不许留旧版样例）
    stale: list[str] = []
    import json

    for path in sorted((ROOT / "examples").rglob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if "tool_version" in payload and payload["tool_version"] != version:
            stale.append("%s=%s" % (path.name, payload["tool_version"]))
    report.check("样例版本已定版", not stale, "旧版本样例: %s" % ", ".join(stale) if stale
                 else "全部 =%s" % version)

    # 4. 禁词门（`examples/` 产物面）
    from check_forbidden_terms import scan as forbidden_scan

    forbidden, scanned = forbidden_scan(ROOT)
    report.check("样例产物无禁词", not forbidden and scanned > 0,
                 "违规 %s" % forbidden if forbidden else "扫了 %d 份" % scanned)

    # 5. 卫生门（`fixtures/` + `examples/`）
    from check_fixture_hygiene import scan as hygiene_scan

    hygiene, hygiene_scanned, _exempt = hygiene_scan(ROOT)
    report.check("只用保留域/文档 IP", not hygiene and hygiene_scanned > 0,
                 "违规 %s" % hygiene[:3] if hygiene else "扫了 %d 份" % hygiene_scanned)

    # 6. 发布留档：两栏 + 覆盖对账（`LAYOUT.RELEASE` 同一判据，这里独立复核一遍）
    doc = (ROOT / RELEASE_DOC)
    text = doc.read_text(encoding="utf-8") if doc.is_file() else ""
    report.check("发布留档（tag 前栏）", bool(COLUMN_ONE.search(text)),
                 "缺 %s 的『一、tag 前事实』" % RELEASE_DOC if not COLUMN_ONE.search(text)
                 else RELEASE_DOC)
    report.check("发布留档（覆盖对账）", bool(COVERAGE.search(text)),
                 "缺『覆盖对账』小节" if not COVERAGE.search(text) else "在位")


# ── 交付面未被改动（三种模式共用） ──────────────────────────────────────


def _blob_oid(rel: str) -> str | None:
    """工作区文件按 git 口径算 blob OID（可直接与 `git rev-parse <rev>:<path>` 比较）。"""
    code, out = _git("-c", "core.quotePath=false", "hash-object", "--", rel)
    return out if code == 0 and len(out) == 40 else None


def deliverable_checks(report: Report) -> None:
    """交付面（`mailvault/` + `pyproject.toml`）相对最近 tag 未被改动。

    `AGENTS.md` 硬性纪律第 1 条把"在 tag 之后改交付面"列为禁止项，但此前**没有任何机器
    判据**盯着它——于是 `plan/RELEASE-M6.md` §2.3 那句"`pyproject.toml` 零差异"过期后
    在仓库 HEAD 与 tag 导出树里都报全绿，无人发现。

    **比较的是 `<tag>` 与「工作区」**（`git diff <tag>`），不是只比提交：只比提交会漏掉
    "改了还没提交"这一态——而那正是 `--offline` 最常被跑的时候。未跟踪的新文件另算
    （`git diff` 看不见它们，但它们同样改动了交付面）。

    「无 `.git`」「无 tag」显式 SKIP；「浅克隆」判 FAIL（历史被截断会让判据空验成绿）。
    """
    code, out = _git("rev-parse", "--is-inside-work-tree")
    if code == 127:
        # 环境里**没有 git 可执行文件**（离线镜像，实测 CI offline job）：不适用，不是失败。
        report.skip("交付面未被改动",
                    "环境里没有 git（离线镜像）——不适用，**不计为通过**")
        report.skip("登记偏差无僵尸条目",
                    "环境里没有 git（离线镜像）——不适用，**不计为通过**")
        return
    if code != 0 or out.strip() != "true":
        report.skip("交付面未被改动", "无 .git 工作树（sdist 解包树）——不适用，**不计为通过**")
        report.skip("登记偏差无僵尸条目", "无 .git 工作树——不适用，**不计为通过**")
        return

    # 浅克隆是**最危险**的一态：`.git` 在、命令也跑得动，但历史被截断，
    # `git describe` 可能取到真值、`diff` 却看不见被截掉的那段 —— 判据会**空验成绿**。
    # 所以这里判 FAIL 而不是 SKIP：修法是 `actions/checkout` 加 `fetch-depth: 0`。
    code, shallow = _git("rev-parse", "--is-shallow-repository")
    if code == 0 and shallow.strip() == "true":
        detail = ("浅克隆仓库：历史被截断，本判据会空验 —— "
                  "`actions/checkout` 需 `fetch-depth: 0`（+ `fetch-tags: true`）")
        report.check("交付面未被改动", False, detail)
        report.check("登记偏差无僵尸条目", False, detail)
        return

    code, tag_out = _git("describe", "--tags", "--abbrev=0")
    tag = tag_out.strip()
    if code != 0 or not tag:
        report.skip("交付面未被改动", "仓库里没有 tag——无从比较，**不计为通过**")
        report.skip("登记偏差无僵尸条目", "仓库里没有 tag——无从比较，**不计为通过**")
        return

    # ① 已提交的漂移（`<tag>..HEAD`）与 ② 工作区里未提交的漂移（`git diff <tag>`），
    # 后者是前者的超集；两者都要，因为报告里要说清"是提交里的还是工作区里的"。
    #
    # `-c core.quotePath=false`：否则非 ASCII 路径会被 git 转义成 `"plan/\346..."`，
    # 于是它既对不上 `REGISTERED_DEVIATIONS` 的 key，也会在报告里显示成乱码
    # （本仓 `plan/` 下本来就有中文文件名）。
    quoted = ("-c", "core.quotePath=false")
    code, committed_out = _git(*quoted, "diff", "--name-only",
                               "%s..HEAD" % tag, "--", *DELIVERABLE_PATHS)
    code2, worktree_out = _git(*quoted, "diff", "--name-only", tag, "--", *DELIVERABLE_PATHS)
    if code != 0 or code2 != 0:
        report.check("交付面未被改动", False,
                     "`git diff %s` 跑失败：%s" % (tag, (committed_out or worktree_out)[:120]))
        report.check("登记偏差无僵尸条目", False, "同上：列不出交付面改动")
        return

    committed = [line.strip() for line in committed_out.splitlines() if line.strip()]
    tracked = [line.strip() for line in worktree_out.splitlines() if line.strip()]

    # ③ 未跟踪的新文件：`git diff` 看不见，但它们同样进了交付面。
    code3, status_out = _git(*quoted, "status", "--porcelain", "--untracked-files=all",
                             "--", *DELIVERABLE_PATHS)
    untracked = [line[3:].strip() for line in status_out.splitlines()
                 if line.startswith("??")] if code3 == 0 else []

    unregistered = [rel for rel in tracked if rel not in REGISTERED_DEVIATIONS]
    uncommitted = [rel for rel in tracked if rel not in committed]

    # 登记的是 **blob OID**，所以"登记了就放行"不成立：再改一个字 hash 就变、判据立刻红。
    bad_blob = []
    for rel in tracked:
        if rel not in REGISTERED_DEVIATIONS:  # 未登记的在上面已经算过，这里不重复报
            continue
        expected = REGISTERED_DEVIATIONS[rel][0]
        actual = _blob_oid(rel)
        if actual != expected:
            bad_blob.append("%s（工作区 %s ≠ 登记 %s）"
                            % (rel, (actual or "?")[:12], expected[:12]))

    reasons = []
    if unregistered:
        reasons.append("%s 之后改了未登记的交付面文件：%s" % (tag, ", ".join(unregistered)))
    if untracked:
        reasons.append("交付面新增未跟踪文件：%s" % ", ".join(untracked))
    if bad_blob:
        reasons.append("已登记偏差的字节对不上：%s" % "；".join(bad_blob))
    if not reasons:
        extra = ("（其中 %s 尚未提交）" % ", ".join(uncommitted)) if uncommitted else ""
        detail = ("%s 之后交付面零差异" % tag if not tracked
                  else "%s 之后仅已登记偏差：%s%s" % (tag, ", ".join(tracked), extra))
    else:
        detail = "；".join(reasons)
    report.check("交付面未被改动", not reasons, detail)

    # 僵尸登记：偏差已经不存在了（例如下次发版把它正规化进了 tag），登记行必须一起删。
    # 判的是**已提交历史**（`<tag>..HEAD`）：登记表描述的是"发布之后我动了什么"，
    # 工作区里临时还原某文件不代表这条登记该删。
    # HEAD 恰好就是 tag 时这一态没有"相对 tag 的偏差"可言（tag 推送那一刻会走到这里，
    # 与 `--pre-tag` 在 tag 后必然红是同一类态问题），所以 SKIP 而不是 FAIL。
    code, head = _git("rev-parse", "HEAD")
    code2, tag_commit = _git("rev-parse", "%s^{commit}" % tag)
    if code == 0 and code2 == 0 and head.strip() == tag_commit.strip():
        report.skip("登记偏差无僵尸条目",
                    "HEAD 就是 `%s` —— 这一态没有『相对 tag 的偏差』可言" % tag)
        return
    zombie = [rel for rel in REGISTERED_DEVIATIONS if rel not in committed]
    report.check(
        "登记偏差无僵尸条目",
        not zombie,
        ("登记已过期（`%s` 里该路径已无差异，登记行须一并删除）：%s" % (tag, ", ".join(zombie)))
        if zombie else "登记的 %d 处偏差都仍然存在" % len(REGISTERED_DEVIATIONS),
    )


# ── 模式：--pre-tag ────────────────────────────────────────────────────


def _git(*args: str) -> tuple[int, str]:
    """跑 git。**环境里没有 git 时返回 127 而不是抛异常**。

    为什么必须挡：`--offline` 也在**没有 git 的环境**里跑 —— `.github/offline.Dockerfile`
    基于 `python:3.12-slim`，镜像里**没装 git**（那个 job 要证明的正是"零网络、零安装步骤"）。
    不挡的话 `subprocess.run(["git", ...])` 直接抛 `FileNotFoundError`，
    于是"这一态不适用"变成了"门崩掉"——实测 CI run `39906099706` 的 `offline` job 就是这样红的。
    """
    import shutil

    if shutil.which("git") is None:
        return 127, "git 不在 PATH 上"
    result = subprocess.run(["git", *args], cwd=str(ROOT),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return result.returncode, result.stdout.decode("utf-8", "replace").strip()


def pretag_checks(report: Report) -> None:
    version = _version()
    tag = "v%s" % version

    code, out = _git("tag", "--list", tag)
    report.check("tag 尚未创建", code == 0 and out == "",
                 "标签已存在：%s" % out if out else "`%s` 不存在（符合 tag 前态）" % tag)

    code, out = _git("status", "--porcelain")
    dirty = [line for line in out.splitlines() if line.strip()]
    report.check("工作区干净", code == 0 and not dirty,
                 "有未提交改动：%d 项" % len(dirty) if dirty else "无未提交改动")


# ── 模式：--online ─────────────────────────────────────────────────────


def _gh(*args: str) -> tuple[int, str]:
    import shutil

    if shutil.which("gh") is None:
        return 127, "gh 不在 PATH 上"
    result = subprocess.run(["gh", *args], cwd=str(ROOT),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return result.returncode, result.stdout.decode("utf-8", "replace").strip()


def online_checks(report: Report) -> None:
    import json

    version = _version()
    tag = "v%s" % version

    code, url = _git("remote", "get-url", "origin")
    report.check("远端 origin 存在", code == 0 and bool(url), url or "未配置 origin")

    code, out = _git("ls-remote", "--tags", "origin", tag)
    report.check("tag 已推送到远端", code == 0 and ("refs/tags/%s" % tag) in out,
                 out.splitlines()[-1] if out else "远端没有 %s" % tag)

    code, out = _gh("release", "view", tag, "--json", "body,name")
    ok_release = code == 0
    body = ""
    if ok_release:
        try:
            body = json.loads(out).get("body") or ""
        except json.JSONDecodeError:
            ok_release = False
    missing_words = [w for w in RELEASE_KEYWORDS if w.lower() not in body.lower()]
    report.check("GitHub Release 在位且附三件套", ok_release and not missing_words,
                 "缺要素 %s" % missing_words if missing_words
                 else ("release %s" % tag if ok_release else "查不到 release %s" % tag))

    doc = ROOT / RELEASE_DOC
    text = doc.read_text(encoding="utf-8") if doc.is_file() else ""
    run_ids = RUN_ID_ROW.findall(text)
    push_row = PUSH_RUN_ROW.search(text)
    report.check("第二栏已回填（tag 后）", bool(COLUMN_TWO.search(text)) and bool(run_ids),
                 "CI run id 实录 %s" % run_ids if run_ids else "第二栏缺 CI run id 行")
    if push_row:
        claimed_push, claimed_run = int(push_row.group(1)), int(push_row.group(2))
        report.check("push 数 = run 数 自洽",
                     claimed_push == claimed_run == len(run_ids),
                     "留档 %d = %d，实录 run %d 条" % (claimed_push, claimed_run, len(run_ids)))
    else:
        report.check("push 数 = run 数 自洽", False, "缺 `push 数 = run 数` 行")

    bad_runs = []
    for run_id in run_ids:
        code, out = _gh("run", "view", run_id, "--json", "conclusion,status,event,headSha")
        if code != 0:
            bad_runs.append("%s 查不到" % run_id)
            continue
        try:
            info = json.loads(out)
        except json.JSONDecodeError:
            bad_runs.append("%s 无法解析" % run_id)
            continue
        if info.get("conclusion") not in {"success", "failure"}:
            bad_runs.append("%s conclusion=%s（未完成或异常）" % (run_id, info.get("conclusion")))
    report.check("留档里的 run id 都真实存在", not bad_runs,
                 "；".join(bad_runs[:3]) if bad_runs else "%d 条 run 均可在远端查到" % len(run_ids))

    # ── 认证"当前发布的这棵树"的那批 run 必须全绿 ────────────────────────
    #
    # **为什么不能要求"所有历史 run 都绿"**：历史是不可变的。首推时暴露的
    # `--network none` 容器冲突是**真实发生过**的失败（run 39526291036 /
    # 39526365982），它必须留在留档里。把判据写成"一条失败都不许有"，结果只能是
    # 这条门永远红、然后被人悄悄删掉——那是假门。真正要认证的是：
    # **现在 tag 指向的那棵树，它的构建全绿**；且**任何历史失败都不得被漏记**。
    code, tag_commit = _git("rev-parse", "%s^{commit}" % tag)
    tag_commit = tag_commit.strip()
    report.check("能解析 tag 的提交 OID", code == 0 and len(tag_commit) == 40, tag_commit)

    code, out = _gh("run", "list", "--event", "push", "--limit", "50",
                    "--json", "databaseId,headSha,conclusion,headBranch")
    runs: list[dict] = []
    if code == 0:
        try:
            runs = json.loads(out)
        except json.JSONDecodeError:
            runs = []
    else:
        report.check("能列出 push 构建", False, "gh run list 失败：%s" % out[:80])

    if runs:
        certifying = [r for r in runs if r.get("headSha") == tag_commit]
        not_green = [str(r["databaseId"]) for r in certifying
                     if r.get("conclusion") != "success"]
        report.check("认证发布树的 run 全绿", bool(certifying) and not not_green,
                     "tag 提交 %s 上的 run: %s%s"
                     % (tag_commit[:8],
                        ", ".join("%s=%s" % (r["databaseId"], r.get("conclusion"))
                                  for r in certifying),
                        ("；非 success: " + ", ".join(not_green)) if not_green else ""))

        # 历史失败必须逐条登记在留档里——漏记就是"把红灯抹掉"。
        failures = [str(r["databaseId"]) for r in runs if r.get("conclusion") == "failure"]
        undocumented = [run_id for run_id in failures if run_id not in run_ids]
        report.check("历史失败逐条登记", not undocumented,
                     "未登记的历史失败 run: %s" % undocumented if undocumented
                     else ("%d 条历史失败全部已登记" % len(failures) if failures
                           else "无历史失败"))

        # ── push 数 = run 数 ────────────────────────────────────────────
        #
        # **绝对数字是自指的**：留档写"5 = 5"，下一次改文档的提交就会把它变成 6，
        # 于是每改一次文档就要再改一次数字——这正是"tag 树内不写自指字面值"那条纪律
        # 在 push 计数上的翻版。所以判据落在**不随文档提交变化**的不变量上：
        #
        #   ① 每个 push 事件**都有**一条 run，且**没有一次 push 对应多条**。
        #      注意：**同一个提交**被推两次是合法的——例如 `c84b0c8` 既作为 `main`
        #      的 HEAD 推了一次，又作为 tag `v1.0.0` 指向的提交推了一次，两次 push
        #      就该有两条 run。判据按 (提交, 分支/标签) 去重，而不是按提交去重。
        #   ② 留档声明的两个数字**彼此相等**（内部自洽）。
        #   ③ 留档写明这个计数**截至哪个提交**（`SNAPSHOT_ROW`），该提交真实存在。
        #
        # ③ 是关键：没有它，"6 = 6" 是一句无法对账的空话——它既可能指昨天也可能指现在。
        per_ref: dict[tuple[str, str], int] = {}
        for run in runs:
            key = (run.get("headSha", ""), run.get("headBranch", ""))
            per_ref[key] = per_ref.get(key, 0) + 1
        duplicated = {("%s@%s" % key): n for key, n in per_ref.items() if n > 1}
        report.check("每次 push 恰好一条 run", not duplicated,
                     "同一提交+ref 有多条 run: %s" % duplicated if duplicated
                     else "%d 次 push 各一条 run（无漏、无重）" % len(per_ref))

        if push_row:
            claimed_push, claimed_run = int(push_row.group(1)), int(push_row.group(2))
            report.check("留档 push 数 = run 数 自洽", claimed_push == claimed_run,
                         "留档 %d = %d" % (claimed_push, claimed_run))

        snapshot = SNAPSHOT_ROW.search(text)
        if snapshot:
            snapshot_sha = snapshot.group(1)
            code, resolved = _git("rev-parse", "--verify", "%s^{commit}" % snapshot_sha)
            report.check("留档写明计数截至的提交", code == 0 and len(resolved.strip()) == 40,
                         "计数快照提交 %s %s"
                         % (snapshot_sha,
                            "存在" if code == 0 else "在仓库里查不到"))
        else:
            report.check("留档写明计数截至的提交", False,
                         "缺『计数截至提交』行——绝对数字必须锚在一个可核对的提交上")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="发布门（M6 三态）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--offline", action="store_true",
                       help="不碰网络：发布内容齐备（CI 跑这一档）")
    group.add_argument("--pre-tag", dest="pre_tag", action="store_true",
                       help="tag 之前：内容齐备 + tag 未创建 + 工作区干净")
    group.add_argument("--online", action="store_true",
                       help="推送/Release 之后：内容齐备 + 远端/tag/Release/CI run 实录")
    args = parser.parse_args(argv)

    mode = "--offline" if args.offline else ("--pre-tag" if args.pre_tag else "--online")
    report = Report(mode)
    content_checks(report)
    deliverable_checks(report)
    if args.pre_tag:
        pretag_checks(report)
    if args.online:
        online_checks(report)
    return report.render()


if __name__ == "__main__":
    sys.exit(main())