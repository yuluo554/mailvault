"""`query.json` 解析（M1）。

输入三件套的第二件：描述"谁在什么时候、从哪个 IP、用哪个 HELO、以哪个信封发件人"
投递了这条消息，以及收件方信任哪些 ``authserv-id``。

字段（`plan/03` §3.1 / `docs/ledger-format.md` §1）：

- ``mail_from``：信封发件人。允许 ``""`` 表示空发件人（``MAIL FROM:<>``，RFC 7208 §2.4 的
  postmaster 形态），**不允许缺字段**——缺字段与空发件人是两回事。
- ``client_ip``：必需，必须是合法 IP 字面量（v4/v6）。SPF 求值的第一输入。
- ``helo``：可选；``null`` 表示报文没带 HELO 名（此时 ``check_host`` 的 ``%{h}`` 宏
  只能取 ``unknown``，见 RFC 7208 §7.3）。
- ``trusted_authserv_ids``：可选，默认 ``[]``。为空时对账模块必须 fail-closed
  判 ``undecidable``（M4），**不得**当成"全部可信"。

解析纪律：

- 未知字段 → :class:`~mailvault.exits.InputError`（拼错字段名不能静默变默认值）。
- 所有校验错误带字段名与收到的值，便于用户定位。
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .exits import InputError

#: 允许出现的字段。多一个就报错——静默忽略拼错的键，会让"我以为设了"变成"其实没设"。
ALLOWED_FIELDS = ("mail_from", "client_ip", "helo", "trusted_authserv_ids")


@dataclass(frozen=True)
class Query:
    """一次投递的查询上下文。"""

    mail_from: str
    client_ip: str
    helo: str | None = None
    trusted_authserv_ids: tuple[str, ...] = ()

    # ── 派生量 ─────────────────────────────────────────────────────────
    @property
    def sender_domain(self) -> str:
        """信封发件人的域名部分；空发件人 → 空串（调用方据此走 postmaster 规则）。"""
        _, _, domain = self.mail_from.rpartition("@")
        return domain.strip().rstrip(".").lower()

    @property
    def ip_version(self) -> int:
        return ipaddress.ip_address(self.client_ip).version

    def to_dict(self) -> dict[str, Any]:
        """账本里的 ``query`` 块（字段名与 `docs/ledger-format.md` §1 一致）。"""
        return {
            "mail_from": self.mail_from,
            "helo": self.helo,
            "client_ip": self.client_ip,
            "trusted_authserv_ids": list(self.trusted_authserv_ids),
        }


def load_query(path: str | Path) -> Query:
    """读 ``query.json`` 并校验。"""
    data = _load_json_object(path, what="查询")
    return from_dict(data, source=str(path))


def from_dict(data: Any, *, source: str = "<memory>") -> Query:
    if not isinstance(data, dict):
        raise InputError("%s：query.json 顶层必须是对象，收到 %s"
                         % (source, type(data).__name__))

    unknown = [key for key in data if key not in ALLOWED_FIELDS]
    if unknown:
        raise InputError("%s：未知字段 %s（允许：%s）"
                         % (source, "、".join(sorted(unknown)), "、".join(ALLOWED_FIELDS)))

    if "mail_from" not in data:
        raise InputError("%s：缺 mail_from（空发件人请写 \"\"，不要省略字段）" % source)
    mail_from = data["mail_from"]
    if not isinstance(mail_from, str):
        raise InputError("%s：mail_from 必须是字符串，收到 %r" % (source, mail_from))
    if mail_from and "@" not in mail_from:
        raise InputError("%s：mail_from 必须形如 local@domain，收到 %r" % (source, mail_from))

    if "client_ip" not in data:
        raise InputError("%s：缺 client_ip" % source)
    client_ip = data["client_ip"]
    if not isinstance(client_ip, str):
        raise InputError("%s：client_ip 必须是字符串，收到 %r" % (source, client_ip))
    try:
        ipaddress.ip_address(client_ip.strip())
    except ValueError:
        raise InputError("%s：client_ip 不是合法 IP：%r" % (source, client_ip)) from None

    helo = data.get("helo")
    if helo is not None and not isinstance(helo, str):
        raise InputError("%s：helo 必须是字符串或 null，收到 %r" % (source, helo))

    trusted = data.get("trusted_authserv_ids", [])
    if not isinstance(trusted, list) or any(not isinstance(item, str) for item in trusted):
        raise InputError("%s：trusted_authserv_ids 必须是字符串列表，收到 %r"
                         % (source, trusted))

    return Query(
        mail_from=mail_from,
        client_ip=client_ip.strip(),
        helo=helo,
        trusted_authserv_ids=tuple(item.strip() for item in trusted),
    )


def _load_json_object(path: str | Path, *, what: str) -> Any:
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        raise InputError("%s文件不存在：%s" % (what, path)) from None
    except OSError as exc:
        raise InputError("%s文件不可读：%s（%s）" % (what, path, exc)) from None
    try:
        return json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InputError("%s不是 UTF-8：%s（%s）" % (what, path, exc)) from None
    except json.JSONDecodeError as exc:
        raise InputError("%s JSON 语法错误：%s 第 %d 行第 %d 列：%s"
                         % (what, path, exc.lineno, exc.colno, exc.msg)) from None
