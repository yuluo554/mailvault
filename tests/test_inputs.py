"""输入三件套解析（M1）：`snap.json` / `query.json` / `.eml`。

这些测试锁的都是**可证伪的语义**，不是"能读出来"：

- `queries` 是有序列表：同 `(qname,qtype)` 查两次、答案不同时，`resolve()` 取第一次，
  且下标可见（`plan/03` §3.1）；
- 非 NOERROR 带 answer → 拒绝（否则"不存在"会被读成"有记录"）；
- 缺 `psl_version` / `psl_date` / 未知 `schema_version` → `InputError`（→ exit 3）；
- "快照没查过" 与 "查过了没有" 必须是两种不同结果（`plan/04` §2.3）；
- `.eml` 保序、保留重复头、多 `DKIM-Signature` 不折叠。
"""

from __future__ import annotations

import json

import pytest

from mailvault import eml, query, snapshot
from mailvault.constants import SNAPSHOT_SCHEMA_VERSION
from mailvault.exits import InputError

BASE = {
    "schema_version": SNAPSHOT_SCHEMA_VERSION,
    "fetched_at": "2026-10-19T18:35:00Z",
    "resolver": "synthetic",
    "psl_version": "2026-10-20_08-40-56_UTC",
    "psl_date": "2026-10-20",
    "queries": [],
}


def _snap(**overrides):
    data = dict(BASE)
    data.update(overrides)
    return data


def _write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


# ── schema 版本 ─────────────────────────────────────────────────────────


def test_valid_snapshot_loads(tmp_path):
    path = _write(tmp_path, "snap.json", _snap(queries=[
        snapshot.make_query(qname="example.invalid", qtype="TXT", answer=["v=spf1 -all"], ttl=300),
    ]))
    snap = snapshot.load_snapshot(path)
    assert snap.schema_version == SNAPSHOT_SCHEMA_VERSION
    assert snap.query_count == 1
    assert snap.meta()["psl_date"] == "2026-10-20"


def test_unknown_schema_version_is_input_error():
    with pytest.raises(InputError) as exc:
        snapshot.from_dict(_snap(schema_version=99))
    # 错误信息必须列出支持版本（K6）
    assert str(SNAPSHOT_SCHEMA_VERSION) in str(exc.value)


def test_missing_schema_version_is_input_error():
    data = _snap()
    del data["schema_version"]
    with pytest.raises(InputError) as exc:
        snapshot.from_dict(data)
    assert "schema_version" in str(exc.value)


def test_schema_version_must_be_int_not_bool():
    with pytest.raises(InputError):
        snapshot.from_dict(_snap(schema_version=True))


@pytest.mark.parametrize("field", ["psl_version", "psl_date"])
def test_missing_psl_fields_are_input_error(field):
    """题面 §2.5 灰区 3：输出必须带 PSL 版本与日期 → 输入缺了就不能继续。"""
    data = _snap()
    del data[field]
    with pytest.raises(InputError) as exc:
        snapshot.from_dict(data)
    assert field in str(exc.value)


@pytest.mark.parametrize("field", ["fetched_at", "resolver"])
def test_missing_meta_fields_are_input_error(field):
    data = _snap()
    del data[field]
    with pytest.raises(InputError):
        snapshot.from_dict(data)


def test_queries_must_be_list_not_dict():
    """字典形态在加载期就会把"同名查两次"合并掉——这是必须拒绝的形态。"""
    with pytest.raises(InputError) as exc:
        snapshot.from_dict(_snap(queries={"example.invalid": "v=spf1 -all"}))
    assert "有序列表" in str(exc.value)


# ── 逐查询字段 ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("field", list(snapshot.QUERY_FIELDS))
def test_missing_query_field_is_input_error(field):
    entry = snapshot.make_query(qname="example.invalid", qtype="TXT", answer=["v=spf1 -all"])
    del entry[field]
    with pytest.raises(InputError) as exc:
        snapshot.from_dict(_snap(queries=[entry]))
    assert field in str(exc.value)


def test_non_noerror_with_answer_is_rejected():
    """NXDOMAIN 还带 answer 会让下游把"不存在"读成"有记录"。"""
    entry = snapshot.make_query(qname="nope.example.invalid", qtype="TXT",
                                rcode="NXDOMAIN", answer=["v=spf1 -all"])
    with pytest.raises(InputError) as exc:
        snapshot.from_dict(_snap(queries=[entry]))
    assert "answer 必须为空" in str(exc.value)


def test_nxdomain_with_empty_answer_is_fine():
    entry = snapshot.make_query(qname="nope.example.invalid", qtype="TXT", rcode="NXDOMAIN")
    snap = snapshot.from_dict(_snap(queries=[entry]))
    resolved = snap.resolve("nope.example.invalid", "TXT")
    assert resolved.found is True
    assert resolved.is_nxdomain is True
    assert resolved.answer == ()


def test_negative_ttl_is_rejected():
    entry = snapshot.make_query(qname="a.example.invalid", qtype="TXT", ttl=-1)
    with pytest.raises(InputError):
        snapshot.from_dict(_snap(queries=[entry]))


def test_answer_items_must_be_strings():
    entry = snapshot.make_query(qname="a.example.invalid", qtype="TXT")
    entry["answer"] = [300]
    with pytest.raises(InputError):
        snapshot.from_dict(_snap(queries=[entry]))


# ── resolve 语义 ────────────────────────────────────────────────────────


def test_resolve_takes_first_hit_and_records_index():
    queries = [
        snapshot.make_query(qname="dup.example.invalid", qtype="TXT", answer=["first"], ttl=60),
        snapshot.make_query(qname="dup.example.invalid", qtype="TXT", answer=["second"], ttl=60),
    ]
    snap = snapshot.from_dict(_snap(queries=queries))
    trace: list[dict] = []
    resolved = snap.resolve("dup.example.invalid", "TXT", trace)
    assert resolved.answer == ("first",)
    assert resolved.index == 0
    assert trace and "queries[0]" in trace[0]["note"]

    # 两次都看得见——"查了两次结果不同"不被静默掩盖
    assert [item.answer for item in snap.occurrences("dup.example.invalid", "TXT")] == [
        ("first",), ("second",)]


def test_resolve_is_case_and_trailing_dot_insensitive():
    queries = [snapshot.make_query(qname="Example.INVALID.", qtype="txt", answer=["x"])]
    snap = snapshot.from_dict(_snap(queries=queries))
    assert snap.resolve("example.invalid", "TXT").answer == ("x",)
    assert snap.resolve("EXAMPLE.INVALID.", "txt").answer == ("x",)


def test_unqueried_name_is_distinguishable_from_nxdomain():
    """"没抓" ≠ "没有"。两者必须给出不同的 Resolved。"""
    snap = snapshot.from_dict(_snap(queries=[
        snapshot.make_query(qname="missing.example.invalid", qtype="TXT", rcode="NXDOMAIN"),
    ]))
    never_asked = snap.resolve("other.example.invalid", "TXT")
    asked_and_absent = snap.resolve("missing.example.invalid", "TXT")

    assert never_asked.found is False and never_asked.rcode is None
    assert asked_and_absent.found is True and asked_and_absent.rcode == "NXDOMAIN"
    assert "数据缺口" in never_asked.trace_note()


# ── 文件级错误 ──────────────────────────────────────────────────────────


def test_missing_file_is_input_error(tmp_path):
    with pytest.raises(InputError) as exc:
        snapshot.load_snapshot(tmp_path / "nope.json")
    assert "不存在" in str(exc.value)


def test_malformed_json_reports_position(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text('{"schema_version": 1,,}', encoding="utf-8")
    with pytest.raises(InputError) as exc:
        snapshot.load_snapshot(path)
    assert "第" in str(exc.value) and "列" in str(exc.value)


def test_non_utf8_is_input_error(tmp_path):
    path = tmp_path / "latin1.json"
    path.write_bytes(b'{"resolver": "\xff\xfe"}')
    with pytest.raises(InputError):
        snapshot.load_snapshot(path)


# ── query.json ──────────────────────────────────────────────────────────


def test_query_minimal_valid():
    q = query.from_dict({"mail_from": "sender@example.invalid", "client_ip": "192.0.2.10"})
    assert q.sender_domain == "example.invalid"
    assert q.ip_version == 4
    assert q.helo is None
    assert q.trusted_authserv_ids == ()


def test_query_full_valid():
    q = query.from_dict({
        "mail_from": "sender@Example.INVALID.",
        "client_ip": "2001:db8::1",
        "helo": "mail.example.invalid",
        "trusted_authserv_ids": ["mx.example.invalid"],
    })
    assert q.sender_domain == "example.invalid"
    assert q.ip_version == 6
    assert q.to_dict()["helo"] == "mail.example.invalid"


def test_query_empty_mail_from_is_allowed():
    """空发件人（`MAIL FROM:<>`）是合法形态，与"缺字段"必须区分。"""
    q = query.from_dict({"mail_from": "", "client_ip": "192.0.2.10"})
    assert q.mail_from == ""
    assert q.sender_domain == ""


def test_query_missing_mail_from_rejected():
    with pytest.raises(InputError) as exc:
        query.from_dict({"client_ip": "192.0.2.10"})
    assert "mail_from" in str(exc.value)


def test_query_unknown_field_rejected():
    """拼错字段名不能静默变成默认值。"""
    with pytest.raises(InputError) as exc:
        query.from_dict({"mail_from": "a@example.invalid", "client_ip": "192.0.2.10",
                         "client_ip_": "typo"})
    assert "未知字段" in str(exc.value)


@pytest.mark.parametrize("ip", ["not-an-ip", "192.0.2.999", ""])
def test_query_bad_ip_rejected(ip):
    with pytest.raises(InputError):
        query.from_dict({"mail_from": "a@example.invalid", "client_ip": ip})


def test_query_mail_from_without_at_rejected():
    with pytest.raises(InputError):
        query.from_dict({"mail_from": "no-at-sign", "client_ip": "192.0.2.10"})


def test_query_trusted_ids_must_be_string_list():
    with pytest.raises(InputError):
        query.from_dict({"mail_from": "a@example.invalid", "client_ip": "192.0.2.10",
                         "trusted_authserv_ids": [1, 2]})


# ── .eml ────────────────────────────────────────────────────────────────

SAMPLE = (
    b"Received: from relay.example.invalid by mx.example.invalid\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; d=example.invalid; s=sel1;\r\n"
    b" b=AAAA\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; d=example.invalid; s=sel2;\r\n"
    b" b=BBBB\r\n"
    b"Dkim-Signature: v=1; a=rsa-sha256; d=example.invalid; s=sel3;\r\n"
    b" b=CCCC\r\n"
    b"Subject: =?utf-8?q?hi?=\r\n"
    b"\r\n"
    b"body line 1\r\n"
    b"body line 2\r\n"
)


def test_eml_preserves_header_order_and_duplicates():
    message = eml.parse(SAMPLE)
    assert message.header_names() == [
        "Received", "DKIM-Signature", "DKIM-Signature", "Dkim-Signature", "Subject"]
    assert len(message.get_all("DKIM-Signature")) == 3  # 大小写不同的同名头都算
    assert message.get("DKIM-Signature").split("s=")[1].startswith("sel1")


def test_eml_body_is_raw_bytes():
    message = eml.parse(SAMPLE)
    assert message.body == b"body line 1\r\nbody line 2\r\n"
    assert message.body_sha256 == eml.parse(SAMPLE).body_sha256


def test_eml_unfolds_continuation_lines():
    message = eml.parse(SAMPLE)
    value = message.get_all("DKIM-Signature")[0]
    assert "b=AAAA" in value
    assert "\n" in value  # 折行保留为换行，供 DKIM 规范化阶段处理


def test_eml_without_body_is_valid():
    message = eml.parse(b"Subject: x\r\n")
    assert message.body == b""
    assert message.get("Subject") == "x"


def test_eml_bad_header_line_is_input_error():
    with pytest.raises(InputError):
        eml.parse(b"this line has no colon\r\n")


def test_eml_parse_rejects_str():
    with pytest.raises(TypeError):
        eml.parse("Subject: x\r\n\r\nbody")  # type: ignore[arg-type]


def test_eml_missing_file_is_input_error(tmp_path):
    with pytest.raises(InputError):
        eml.load_eml(tmp_path / "nope.eml")


def test_eml_without_dkim_signature_is_not_an_error():
    """题面 §3 边界：无 DKIM-Signature 不是错误，dkim 判 none，其余照常。"""
    message = eml.parse(b"Subject: x\r\n\r\nbody\r\n")
    assert message.dkim_signatures == []
