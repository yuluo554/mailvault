#!/usr/bin/env python3
"""AST / 扫描门的变异验证：**每一条守门都必须能变红**。

做法：把仓库复制到临时目录 → 往被测面**植入一处真实违规** → 跑该副本里的门
→ 断言退出码 1 → 还原。三连断言：植入前 marker 不存在 / 植入后文件已变 / 结束时副本被删。

为什么必须做这一步：一条"永远返回 0"的门与一条"项目确实干净"的门，输出一模一样。
只有植入违规仍绿，才能确定它是假门。

**A09 是本批唯一的异型**：`check_release.py` 的「交付面未被改动」判的是 git 状态，
所以那个临时副本要先被造成**带 tag 的真仓库**（`_prepare_release_history`），
并且**分两段打靶**（不提交 / 提交，对应判据里的两条代码路径），
外加**阳性对照**（植入前必须是绿的）。这两种"本该红却不红"的形态，正是它要防的。

用法：
    py -3.12 tools/verify_ast_gates.py
退出码：0 全部如期变红 / 1 有门没红（= 假门）。
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

COPY_FILES = ["mailvault", "tools", "fixtures", "examples", "plan", "README.md", "pyproject.toml"]

#: (标签, 门脚本, 要植入的文件, 植入内容, 期望门输出里出现的关键词)
CASES = [
    (
        "A01 在 cli.py 里 import socket",
        "tools/check_no_network.py",
        "mailvault/cli.py",
        "\nimport socket  # MUTANT\n",
        "import socket",
    ),
    (
        "A02 在 cli.py 里直接 json.dumps",
        "tools/check_no_direct_json.py",
        "mailvault/cli.py",
        "\nimport json\n\ndef _mutant():\n    return json.dumps({})\n",
        "json 序列化",
    ),
    (
        "A03 在 render.py 里读系统时钟",
        "tools/check_no_clock.py",
        "mailvault/render.py",
        "\nimport time\n\ndef _mutant():\n    return time.time()\n",
        "time.time",
    ),
    (
        "A04 fixture 里放真实域名",
        "tools/check_fixture_hygiene.py",
        "fixtures/mutant-probe.txt",
        "sender: ops@mail.google.com\n",
        "mail.google.com",
    ),
    (
        "A05 examples 里放禁词",
        "tools/check_forbidden_terms.py",
        "examples/mutant-verdict.md",
        "# 结论\n\n该头疑似伪造。\n",
        "禁词",
    ),
    (
        # 精确豁免的**阴性对照**：net.py 是唯一有豁免的文件，但豁免只到 utc_now_z 这一个函数。
        # 同文件里别处读时钟必须照样报红——否则"函数级豁免"就悄悄退化成了"文件级放行"。
        "A06 豁免文件里越界读时钟（net.py 非豁免函数）",
        "tools/check_no_clock.py",
        "mailvault/net.py",
        "\n\ndef _mutant_outside_exemption():\n    import time\n    return time.time()\n",
        "time.time",
    ),
    (
        # M6 新增扫描面的阳性对照：`examples/` 与 `fixtures/` 用的是同一套判据，
        # 所以往 `examples/` 放真实域名必须报红（不是只有 fixtures/ 被扫）。
        "A07 examples 里放真实域名",
        "tools/check_fixture_hygiene.py",
        "examples/mutant-probe.txt",
        "sender: ops@mail.google.com\n",
        "mail.google.com",
    ),
    (
        # 发布门必须真的能红：把 README 换成不含版本号的正文，
        # `check_release.py --offline` 的"版本三处一致"判据必须报 FAIL。
        # 关键在**判据串**（不是那条永远会打印的行标签）。
        "A08 发布门：README 缺版本号",
        "tools/check_release.py",
        "README.md",
        "# MUTANT\n\n（本行是为变异验证植入的假 README，不含版本号）\n",
        "README含v1.0.0=False",
    ),
    (
        # 「交付面未被改动」判据（AGENTS.md 硬性纪律第 1 条）必须真的能红。
        #
        # 这一条与前八条**不同型**：它判的是 git 状态，不是文件内容。所以临时副本必须
        # **先成为一个带 tag 的真仓库**，否则判据会走 SKIP 分支——而"无 .git 就 SKIP"
        # 正是最容易写成"永远绿"的地方，因此这里额外做**阳性对照**：植入前必须是绿的。
        #
        # 而且它有**两条代码路径**（工作区 diff / 已提交历史），只打一条 = 另一条是
        # 未经证伪的假门。所以分两段：先**不提交**（走工作区分支），再**提交**（走历史分支）。
        "A09 发布门：tag 后改动 mailvault/（交付面漂移）",
        "tools/check_release.py",
        "mailvault/__init__.py",
        "\n# MUTANT: tag 之后改了一行源码\n",
        "改了未登记的交付面文件",
    ),
]

#: 需要先把临时副本变成**带 tag 的真 git 仓库**的变异（判据读的是 git 状态）。
NEEDS_GIT = {"A09 发布门：tag 后改动 mailvault/（交付面漂移）"}

#: 有些门需要显式模式参数（发布门三种模式只能选一个）。
GATE_ARGV = {
    "tools/check_release.py": ["--offline"],
}


def _copy_repo(dest: Path) -> None:
    for rel in COPY_FILES:
        source = ROOT / rel
        if not source.exists():
            continue
        target = dest / rel
        if source.is_dir():
            shutil.copytree(str(source), str(target))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(source), str(target))
    (dest / "fixtures").mkdir(exist_ok=True)
    (dest / "examples").mkdir(exist_ok=True)


def _plant(root: Path, rel: str, payload: str, *, append: bool) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    assert "MUTANT" not in (path.read_text(encoding="utf-8") if path.exists() and append else ""), \
        "植入点已有 MUTANT 标记"
    if append:
        before = path.read_text(encoding="utf-8")
        after = before + payload
        assert after != before
        path.write_bytes(after.encode("utf-8"))
    else:
        path.write_bytes(payload.encode("utf-8"))
    text = path.read_text(encoding="utf-8")
    assert "MUTANT" in text or "mutant" in text or "mail.google.com" in text or "伪造" in text


def _run(root: Path, script: str) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, str(root / script), *GATE_ARGV.get(script, [])],
        cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    return result.returncode, result.stdout.decode("utf-8", "replace")


def _git(root: Path, *args: str) -> tuple[int, str]:
    result = subprocess.run(["git", *args], cwd=str(root),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return result.returncode, result.stdout.decode("utf-8", "replace").strip()


#: 临时仓库的提交身份（不能依赖被测机器的全局 git 配置）。
#: **`git tag -a` 也要身份**——它是 annotated tag，要建一个 tag 对象；只在 `commit` 上加
#: `-c user.name=…` 会在没有全局身份的机器上崩在 `git tag`（实测：CI 两个 job 全红，
#: 本机因为 `~/.gitconfig` 有身份而看不出来）。所以这里**写进副本自己的 local config**，
#: 一次设置、后面所有 git 命令（含 tag）都继承。
GIT_ID = (("user.name", "ast-mut"), ("user.email", "ast-mut@example.invalid"))


def _init_git_repo(root: Path) -> None:
    """把副本变成**带 tag 的真仓库**：HEAD 与 tag 同树，即"刚发完版"的那一态。

    身份写进**副本的 local config**（不是全局、也不是逐条 `-c`）：`git tag -a` 没有身份
    会直接失败，而 CI 的运行器没有全局 git 身份。
    """
    code, out = _git(root, "init", "-q")
    assert code == 0, "git init 失败：%s" % out[:200]
    for key, value in GIT_ID:
        code, out = _git(root, "config", key, value)
        assert code == 0, "git config %s 失败：%s" % (key, out[:200])
    code, out = _git(root, "-c", "commit.gpgsign=false", "add", "-A")
    assert code == 0, "git add 失败：%s" % out[:200]
    code, out = _git(root, "commit", "-q", "-m", "baseline")
    assert code == 0, "git commit 失败：%s" % out[:200]
    code, out = _git(root, "tag", "-a", "v1.0.0", "-m", "baseline tag")
    assert code == 0, "git tag 失败：%s" % out[:200]


def _git_commit_all(root: Path, message: str) -> None:
    for args in (("add", "-A"), ("commit", "-q", "-m", message)):
        code, out = _git(root, *args)
        assert code == 0, "git %s 失败：%s" % (" ".join(args), out[:200])


def _prepare_release_history(root: Path) -> None:
    """造出与本仓**同型**的发布历史，好让"已登记偏差"这一态是真实的。

    三段：① tag 上的 `pyproject.toml` 比登记内容多了**一行注释**（= 登记前的样子，
    仍然可解析，所以内容类判据照样全绿）；② 去掉那行注释提交一次 —— 恢复出来的字节
    正是工作区原件的字节，blob OID 因此**等于** `REGISTERED_DEVIATIONS` 里登记的那个，
    于是"仅已登记偏差"这一态是**真的**、不是被构造放行；③ 之后才植入变异。

    为什么要费这个劲：如果让 tag 与 HEAD 同树（`_init_git_repo` 的默认形态），
    `REGISTERED_DEVIATIONS` 里的 `pyproject.toml` 在那个副本里就是一条**僵尸登记**，
    于是植入后会出现**两条** FAIL，"这次的 exit 1 是不是来自我植入的那处"就说不清了。
    """
    pyproject = root / "pyproject.toml"
    original = pyproject.read_bytes()
    pyproject.write_bytes(original + b"# baseline: tag \xe4\xb8\x8a\xe7\x9a\x84 pyproject\n")
    _init_git_repo(root)
    pyproject.write_bytes(original)
    _git_commit_all(root, "PEP 639")


def _status_of(output: str, label: str) -> str | None:
    """取某条判据的 PASS/FAIL/SKIP（不是"整份输出里出现过这个词"）。"""
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in {"PASS", "FAIL", "SKIP"} and label in line:
            return parts[0]
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AST/扫描门的变异验证")
    parser.add_argument("--root", default=None)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else ROOT

    rows = []
    for label, script, rel, payload, needle in CASES:
        tmp = Path(tempfile.mkdtemp(prefix="ast-mut-"))
        try:
            _copy_repo(tmp)
            if label in NEEDS_GIT:
                # 这一型的判据读 git 状态，所以副本必须先成为仓库；且必须有**阳性对照**：
                # 植入之前两条交付面判据自己是绿的、且内容里没有本次植入的串，
                # 否则"植入后 exit 1"可能来自与本变异无关的原因（假阳性）。
                _prepare_release_history(tmp)
                before_code, before_out = _run(tmp, script)
                positive = (_status_of(before_out, "交付面未被改动") == "PASS"
                            and _status_of(before_out, "登记偏差无僵尸条目") == "PASS"
                            and before_code == 0 and needle not in before_out)
                if not positive:
                    print("  阳性对照失败：植入前交付面判据未全绿（exit=%s）" % before_code)

                # 第一段：**不提交** —— 打的是"工作区 diff"那条代码路径。
                _plant(tmp, rel, payload, append=True)
                dirty_code, dirty_out = _run(tmp, script)
                dirty_hit = (needle in dirty_out
                             and _status_of(dirty_out, "交付面未被改动") == "FAIL")

                # 第二段：**提交** —— 打的是"已提交历史"那条代码路径。
                # 两条路径必须都能红，否则其中一条是未经证伪的假门。
                _git_commit_all(tmp, "mutant: 交付面漂移")
                code, out = _run(tmp, script)
                hit = needle in out
                rows.append((label, script,
                             positive and dirty_code == 1 and dirty_hit
                             and code == 1 and hit
                             and _status_of(out, "交付面未被改动") == "FAIL",
                             code, hit))
            else:
                _plant(tmp, rel, payload, append=rel.startswith("mailvault/"))
                code, out = _run(tmp, script)
                hit = needle in out
                rows.append((label, script, code == 1 and hit, code, hit))
        except AssertionError as exc:
            rows.append((label, script, False, None, False))
            print("  构造失败: %s" % exc)
        finally:
            shutil.rmtree(str(tmp), ignore_errors=True)

    print("AST/扫描门变异验证（每条植入违规后必须 red）")
    print("=" * 78)
    for label, script, ok, code, hit in rows:
        print("%-4s  %-32s → %-34s exit=%s 关键词命中=%s"
              % ("PASS" if ok else "FAIL", label, script, code, hit))
    failed = [row for row in rows if not row[2]]
    print("=" * 78)
    print("结论: %s" % ("%d/%d 全部如期变红" % (len(rows), len(rows)) if not failed
                     else "%d 条未如期变红（假门）" % len(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
