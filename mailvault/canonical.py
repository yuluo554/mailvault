"""确定性序列化：**全仓唯一的 JSON 出口**。

为什么必须唯一：字典键序、缩进、`ensure_ascii`、浮点 repr 四个细节里任何一个在不同调用点
不一致，两次运行就不再逐字节相同。把它收成一个函数，才有可能写一条"扫描源码"的门
（`tools/check_no_direct_json.py`）保证没有第二条路。

三条纪律：

1. 键**递归排序**（`sort_keys=True` 只排顶层？不——它递归，但仍是唯一入口才可靠）。
2. 浮点**禁止**出现在账本里：比率一律走 :func:`fixed6` 变成定点字符串。
3. 落盘文本一律 ``\\n`` 换行、UTF-8、末尾一个换行。
"""

from __future__ import annotations

import hashlib
import json
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Any

#: ``json.dumps`` 的固定参数。**任何调用点都必须等价于这一组**。
_DUMPS_KWARGS: dict[str, Any] = {
    "ensure_ascii": False,
    "sort_keys": True,
    "separators": (",", ":"),
    "allow_nan": False,
}


def dumps(obj: Any) -> str:
    """把对象序列化为确定性 JSON 文本（无尾换行）。

    这是全仓唯一允许出现 ``json.dumps`` 的地方（K2）。
    """
    reject_floats(obj)
    return json.dumps(obj, **_DUMPS_KWARGS)


def dumps_pretty(obj: Any) -> str:
    """人读版 JSON（缩进 2）。仍排序键、仍禁浮点。

    `verdict.json` 用 :func:`dumps`（机读、逐字节可比）；
    调试/样例展示用本函数。**两者不得混用于同一份产物**——换一种写法就是换一份字节。
    """
    reject_floats(obj)
    return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True, allow_nan=False)


def dump_file(path: Any, obj: Any, *, pretty: bool = False) -> None:
    """写文件：UTF-8、``\\n``、末尾恰好一个换行。

    直接 ``write_bytes`` 而不是 ``write_text(newline=...)``：
    后者在 3.8 上不存在 ``newline=`` 参数，且不同平台的默认转换不同。
    """
    text = (dumps_pretty(obj) if pretty else dumps(obj)) + "\n"
    with open(path, "wb") as handle:
        handle.write(text.encode("utf-8"))


def write_text(path: Any, text: str) -> None:
    """写文本产物（如 `verdict.md`）：UTF-8、``\\n``、末尾恰好一个换行。"""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if not normalized.endswith("\n"):
        normalized += "\n"
    with open(path, "wb") as handle:
        handle.write(normalized.encode("utf-8"))


def canonical_bytes(obj: Any) -> bytes:
    """规范化字节（用于算摘要）。"""
    return dumps(obj).encode("utf-8")


def digest(obj: Any) -> str:
    """对规范化 JSON 取 sha256。用于 ``ledger_id`` 与双跑一致性断言。"""
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def digest_text(text: str) -> str:
    """对已归一的文本取 sha256（``\\n`` 换行）。"""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def fixed6(value: float | int | str | Decimal) -> str:
    """定点化到 6 位小数，返回**字符串**（K8）。

    用 ``Decimal`` + 半偶舍入（``ROUND_HALF_EVEN``），不用 ``round()``：
    后者在二进制浮点上做舍入，"0.5 进位方向"会随值变化，且跨语言不一致。

    >>> fixed6(0.5)
    '0.500000'
    >>> fixed6("1")
    '1.000000'
    >>> fixed6(Decimal("0.1234565"))
    '0.123456'
    """
    quant = Decimal("0.000001")
    if isinstance(value, Decimal):
        dec = value
    elif isinstance(value, int):
        dec = Decimal(value)
    elif isinstance(value, str):
        dec = Decimal(value)
    else:
        dec = Decimal(repr(float(value)))
    return str(dec.quantize(quant, rounding=ROUND_HALF_EVEN))


def reject_floats(obj: Any, _path: str = "$") -> None:
    """递归拒绝裸浮点（K8）。

    浮点在 JSON 里的文本表示依赖解释器与平台，是"两次运行字节级一致"的头号敌人。
    账本里只允许 ``int`` / ``str`` / ``bool`` / ``None`` / ``list`` / ``dict``。
    """
    if isinstance(obj, float):
        raise TypeError(
            "%s 是裸浮点——账本内禁止。比率走 canonical.fixed6()，计数用 int。" % _path
        )
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise TypeError("%s 的键不是字符串: %r" % (_path, key))
            reject_floats(value, "%s.%s" % (_path, key))
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            reject_floats(value, "%s[%d]" % (_path, index))
