"""退出码：**一处定义 + 一处优先级**。

题面 §3：

- ``0`` 全 pass / none
- ``1`` 存在 fail
- ``2`` 存在 undecidable
- ``3`` 输入或快照错误
- ``4`` 内部错误（不得吞异常）

优先级（一处定义）：``4 > 3 > 2 > 1 > 0``。

为什么优先级是"越大越严重"：一个账本里可能同时有 fail 与 undecidable，退出码只能取一个。
取最严重的那个，是为了让 CI 不会因为"有 fail 但有 undecidable"而判成 2 就放过。
"""

from __future__ import annotations

from enum import IntEnum

from .constants import FAIL_RESULTS


class ExitCode(IntEnum):
    """退出码。数值即优先级。"""

    OK = 0
    FAIL = 1
    UNDECIDABLE = 2
    INPUT_ERROR = 3
    INTERNAL_ERROR = 4


#: 输入/快照错误的统一异常基类 → exit 3。
class InputError(Exception):
    """输入或快照错误（文件缺失、JSON 语法、schema 不匹配、字段非法）。"""

    exit_code = ExitCode.INPUT_ERROR


class InternalError(Exception):
    """内部错误 → exit 4。**必须打印栈，不得吞。**"""

    exit_code = ExitCode.INTERNAL_ERROR


class ModuleNotReady(InputError):
    """该模块尚未实现（M0 骨架期）。

    刻意**不**返回 OK，也不返回失败——"没做"不能长得像"通过"。
    退出码取 ``2``（undecidable 语义：数据/能力不足，无法判定），与题面灰区口径一致。
    """

    exit_code = ExitCode.UNDECIDABLE


def exit_code_for(results: list[str]) -> ExitCode:
    """由一组判定结果算出退出码。

    优先级一处实现：``4 > 3 > 2 > 1 > 0``。输入错误与内部错误由异常路径产生，
    本函数只处理"判定结果"这一层。

    >>> int(exit_code_for(["pass", "none"]))
    0
    >>> int(exit_code_for(["pass", "fail"]))
    1
    >>> int(exit_code_for(["fail", "undecidable"]))
    2
    """
    if not results:
        return ExitCode.OK
    for value in results:
        if value not in _KNOWN_RESULTS:
            raise InternalError("未知判定结果: %r" % (value,))
    if "undecidable" in results:
        return ExitCode.UNDECIDABLE
    if any(value in FAIL_RESULTS for value in results):
        return ExitCode.FAIL
    return ExitCode.OK


def _known_results() -> frozenset[str]:
    from .constants import RESULTS

    return frozenset(RESULTS)


_KNOWN_RESULTS = _known_results()


def worst(*codes: ExitCode) -> ExitCode:
    """取最严重的一个（数值最大）。空入参 → OK。"""
    return max(codes) if codes else ExitCode.OK
