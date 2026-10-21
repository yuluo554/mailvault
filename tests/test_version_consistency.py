"""版本"三处一致"（`plan/05` §4.2，M6 定版）。

判据只落**仓库内文件**，不读 git 元数据（与布局门同一纪律：浅克隆下 tag / 历史深度会翻转）。
三处指认：

| 处 | 判据 |
|---|---|
| `mailvault/__init__.py::__version__` | **唯一真源** |
| `pyproject.toml` | `dynamic = ["version"]` + `attr = "mailvault.__version__"`（不得写第二份） |
| `README.md` 状态行 | 含 `v${version}` |

第一条测试同时断言三处；后两条把"单点定义"与"交付版不是 dev 版"分别钉死。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import tomllib

from mailvault import __version__

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
PYPROJECT = ROOT / "pyproject.toml"

#: 交付版形态：`MAJOR.MINOR.PATCH`。**不带** `.dev` / `a` / `b` / `rc` 后缀——
#: M6 是定版棒，交付面不得是开发版本号（改这条要是一次有意识的动作）。
RELEASE_FORM = re.compile(r"^\d+\.\d+\.\d+$")

assert sys.version_info >= (3, 11), "版本一致性检查依赖 tomllib（requires-python >=3.11）"


def _attr_target() -> str:
    """`pyproject.toml` 里版本 dynamism 指向的属性名。"""
    pyproject = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return pyproject["tool"]["setuptools"]["dynamic"]["version"]["attr"]


def _project_table() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8")).get("project", {})


def test_three_places_agree_on_one_version() -> None:
    """`__init__`（真源）/ `pyproject`（引用它）/ `README` 状态行（含 v<version>）三处一致。"""
    readme = README.read_text(encoding="utf-8")
    assert _attr_target() == "mailvault.__version__", (
        "pyproject.toml 必须引用 __version__，而不是写第二份：%r" % (_attr_target(),)
    )
    assert "v" + __version__ in readme, (
        "README.md 状态行未出现 v%s（三处不一致）" % (__version__,)
    )


def test_pyproject_does_not_hardcode_a_second_version() -> None:
    project = _project_table()
    assert "version" not in project, "pyproject.toml 的 [project] 不得写死 version（用 dynamic）"
    assert project.get("dynamic") == ["version"], "pyproject.toml 的 dynamic 必须是 ['version']"


def test_version_is_a_final_release_not_a_dev_version() -> None:
    assert RELEASE_FORM.match(__version__), (
        "交付版必须是 MAJOR.MINOR.PATCH（现为 %r）；dev/a/b/rc 后缀属于开发期" % (__version__,)
    )


def test_init_declares_exactly_one_version_literal() -> None:
    """包内不得有第二处写死的版本号；`__all__` 只导出 `__version__`。"""
    text = (ROOT / "mailvault" / "__init__.py").read_text(encoding="utf-8")
    literal = re.findall(r'__version__\s*=\s*"([^"]+)"', text)
    assert literal == [__version__], "mailvault/__init__.py 里应恰好一处 __version__ 赋值"