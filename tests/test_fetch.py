"""`snapshot fetch` 与 DNS 编解码（M1）。

**这是唯一联网路径**，所以断言分两类：

1. **编解码**：报文构造/解析是纯函数，用**手搭的字节**逐位断言——
   不能"跑一次真查询看着对"，那样只能证明"这次运气好"。
2. **抓取流程**：注入传输桩（``transport=``），证明
   - 推导出的查询清单覆盖信封域 / `_dmarc` / DKIM 选择器 / 有界 include；
   - 超时落成 ``rcode="TIMEOUT"`` 而**不是** NXDOMAIN（`plan/04` §2.3）；
   - 落盘经 `canonical`（键排序、无浮点、单尾换行）；
   - 全程零真实 socket（桩就是证据：真 socket 根本没被构造）。
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from mailvault import canonical, net
from mailvault.cli import main
from mailvault.exits import InputError

REPO_ROOT = Path(__file__).resolve().parent.parent


# ── 报文编解码 ──────────────────────────────────────────────────────────


def test_encode_name_basic():
    assert net.encode_name("example.com") == b"\x07example\x03com\x00"


def test_encode_name_strips_trailing_dot():
    assert net.encode_name("example.com.") == net.encode_name("example.com")


def test_encode_name_rejects_long_label():
    with pytest.raises(InputError):
        net.encode_name("a" * 64 + ".com")


def test_encode_name_rejects_empty():
    with pytest.raises(InputError):
        net.encode_name("")


def test_build_query_has_header_and_question():
    wire = net.build_query("example.com", "TXT", message_id=0x1234)
    message_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", wire[:12])
    assert message_id == 0x1234
    assert flags & 0x0100  # RD=1
    assert (qdcount, ancount, nscount, arcount) == (1, 0, 0, 0)
    qtype, qclass = struct.unpack("!HH", wire[-4:])
    assert qtype == 16 and qclass == 1


def test_build_query_rejects_unknown_type():
    with pytest.raises(InputError):
        net.build_query("example.com", "NAPTR")


def _response(qname: str, qtype: int, rcode: int, answers: list[tuple[int, bytes, int]]) -> bytes:
    """手搭一份 DNS 响应：问题段 + answer 段（**不用压缩指针**，便于逐字节核对）。"""
    header = struct.pack("!HHHHHH", 0x1234, 0x8180 | (rcode & 0xF), 1, len(answers), 0, 0)
    question = net.encode_name(qname) + struct.pack("!HH", qtype, 1)
    body = b""
    for rtype, rdata, ttl in answers:
        body += net.encode_name(qname)
        body += struct.pack("!HHIH", rtype, 1, ttl, len(rdata))
        body += rdata
    return header + question + body


def test_parse_response_txt():
    rdata = b"\x11v=spf1 include:_x"  # 单段 17 字节
    wire = _response("example.com", 16, 0, [(16, rdata, 300)])
    answers, ttl, rcode = net.parse_response(wire, expected_id=0x1234)
    assert rcode == "NOERROR"
    assert answers == ["v=spf1 include:_x"]
    assert ttl == 300


def test_parse_response_txt_multiple_segments_are_concatenated():
    """TXT 多个 `<len>` 段在语义上是**一个**逻辑值（RFC 7208 §3.3 的 255 字节切分）。"""
    rdata = b"\x07v=spf1 " + b"\x04-all"
    wire = _response("example.com", 16, 0, [(16, rdata, 60)])
    answers, _ttl, _rcode = net.parse_response(wire)
    assert answers == ["v=spf1 -all"]


def test_parse_response_a_record():
    wire = _response("mail.example.com", 1, 0, [(1, bytes([192, 0, 2, 25]), 120)])
    answers, _ttl, _rcode = net.parse_response(wire)
    assert answers == ["192.0.2.25"]


def test_parse_response_aaaa_record():
    rdata = bytes.fromhex("20010db8" + "00" * 10 + "0001")
    wire = _response("mail.example.com", 28, 0, [(28, rdata, 120)])
    answers, _ttl, _rcode = net.parse_response(wire)
    assert answers == ["2001:db8::1"]


def test_parse_response_mx_and_ptr_and_cname():
    mx = struct.pack("!H", 10) + net.encode_name("mx.example.com")
    cname = net.encode_name("target.example.com")
    wire = _response("example.com", 15, 0, [(15, mx, 60), (5, cname, 60), (12, cname, 60)])
    answers, _ttl, _rcode = net.parse_response(wire)
    assert answers == ["10 mx.example.com", "target.example.com", "target.example.com"]


def test_parse_response_nxdomain_has_no_answers():
    wire = _response("absent.example.com", 16, 3, [])
    answers, _ttl, rcode = net.parse_response(wire)
    assert rcode == "NXDOMAIN"
    assert answers == []


def test_parse_response_refused_rcode():
    wire = _response("example.com", 16, 5, [])
    assert net.parse_response(wire)[2] == "REFUSED"


def test_parse_response_id_mismatch_is_error():
    wire = _response("example.com", 16, 0, [])
    with pytest.raises(net.DnsError):
        net.parse_response(wire, expected_id=0xBEEF)


def test_parse_response_handles_compression_pointer():
    """真实响应普遍用压缩指针；不支持的解析器会在真实网络上才炸。"""
    question = net.encode_name("example.com") + struct.pack("!HH", 16, 1)
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    # answer 的 owner 用指针指回 offset 12（问题段的名字）
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, 6) + b"\x05hello"
    wire = header + question + answer
    answers, ttl, rcode = net.parse_response(wire, expected_id=0x1234)
    assert answers == ["hello"]
    assert ttl == 60
    assert rcode == "NOERROR"


def test_parse_response_truncated_is_error():
    with pytest.raises(net.DnsError):
        net.parse_response(b"\x12\x34")


def test_parse_response_bad_rdata_length_is_error():
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 0, 1, 0, 0)
    answer = net.encode_name("a.example.com") + struct.pack("!HHIH", 16, 1, 60, 99)
    with pytest.raises(net.DnsError):
        net.parse_response(header + answer)


# ── resolver 解析 ───────────────────────────────────────────────────────


@pytest.mark.parametrize("text,expected", [
    ("192.0.2.53", ("192.0.2.53", 53)),
    ("192.0.2.53:5353", ("192.0.2.53", 5353)),
    ("2001:db8::53", ("2001:db8::53", 53)),
    ("[2001:db8::53]:5353", ("2001:db8::53", 5353)),
])
def test_parse_resolver_forms(text, expected):
    assert net._parse_resolver(text) == expected


def test_parse_resolver_default():
    from mailvault.constants import DNS_DEFAULT_RESOLVER

    assert net._parse_resolver(None)[0] == DNS_DEFAULT_RESOLVER


def test_server_label_omits_default_port():
    assert net.server_label(("192.0.2.53", 53)) == "192.0.2.53"
    assert net.server_label(("192.0.2.53", 5353)) == "192.0.2.53:5353"


# ── 抓取流程（注入传输桩，零真实 socket） ───────────────────────────────


class StubTransport(net.Transport):
    """按预设答复的传输层。记录被问过的 (qname, qtype)。"""

    def __init__(self, table: dict[tuple[str, str], tuple[list[str], int, str]]):
        self.table = table
        self.calls: list[tuple[str, str]] = []

    def query(self, qname: str, qtype: str) -> tuple[list[str], int, str]:
        key = (qname.lower().rstrip("."), qtype.upper())
        self.calls.append(key)
        if key not in self.table:
            return [], 0, "NXDOMAIN"
        return self.table[key]


SPF_EML = (
    b"DKIM-Signature: v=1; a=rsa-sha256; d=example.invalid; s=sel1; b=AA\r\n"
    b"Subject: hello\r\n"
    b"\r\n"
    b"body\r\n"
)


@pytest.fixture()
def inputs(tmp_path):
    eml_path = tmp_path / "message.eml"
    eml_path.write_bytes(SPF_EML)
    query_path = tmp_path / "query.json"
    query_path.write_text(json.dumps({
        "mail_from": "sender@example.invalid",
        "client_ip": "192.0.2.10",
        "helo": "mail.example.invalid",
    }), encoding="utf-8")
    return eml_path, query_path


def test_fetch_derives_expected_queries(inputs):
    eml_path, query_path = inputs
    transport = StubTransport({
        ("example.invalid", "TXT"): (["v=spf1 include:_spf.example.invalid -all"], 300, "NOERROR"),
        ("_spf.example.invalid", "TXT"): (["v=spf1 ip4:192.0.2.0/24 -all"], 300, "NOERROR"),
        ("_dmarc.example.invalid", "TXT"): (["v=DMARC1; p=none"], 300, "NOERROR"),
        ("sel1._domainkey.example.invalid", "TXT"): (["v=DKIM1; k=rsa; p=AA"], 300, "NOERROR"),
    })
    snapshot = net.fetch_snapshot(
        eml=str(eml_path), query=str(query_path), transport=transport)

    asked = {(q["qname"], q["qtype"]) for q in snapshot["queries"]}
    assert ("example.invalid", "TXT") in asked
    assert ("_spf.example.invalid", "TXT") in asked       # include 已展开
    assert ("_dmarc.example.invalid", "TXT") in asked
    assert ("sel1._domainkey.example.invalid", "TXT") in asked  # DKIM 选择器


def test_fetch_include_expansion_is_bounded(inputs):
    """include 展开必须有界：不能因为一条自指记录跑到天荒地老。"""
    eml_path, query_path = inputs
    transport = StubTransport({
        ("example.invalid", "TXT"): (["v=spf1 include:example.invalid -all"], 300, "NOERROR"),
    })
    snapshot = net.fetch_snapshot(
        eml=str(eml_path), query=str(query_path), transport=transport)
    names = [q["qname"] for q in snapshot["queries"]]
    assert names.count("example.invalid") == 1  # 同键只问一次


def test_fetch_timeout_is_its_own_rcode(inputs):
    eml_path, query_path = inputs

    class TimeoutTransport(net.Transport):
        def query(self, qname, qtype):
            raise net.DnsTimeout("stub timeout")

    snapshot = net.fetch_snapshot(
        eml=str(eml_path), query=str(query_path), transport=TimeoutTransport())
    rcodes = {q["rcode"] for q in snapshot["queries"]}
    assert rcodes == {"TIMEOUT"}
    assert all(q["answer"] == [] for q in snapshot["queries"])


def test_fetch_metadata_comes_from_psl_and_clock_exemption(inputs):
    eml_path, query_path = inputs
    snapshot = net.fetch_snapshot(
        eml=str(eml_path), query=str(query_path), transport=StubTransport({}))

    from mailvault.psl import default_psl

    psl = default_psl()
    assert snapshot["psl_version"] == psl.version
    assert snapshot["psl_date"] == psl.date
    assert snapshot["schema_version"] == 1
    # fetched_at 必须是 `...Z` 形态（唯一允许读时钟的地方产出的）
    assert snapshot["fetched_at"].endswith("Z")


def test_fetch_result_is_schema_valid(inputs):
    """抓出来的东西必须能被自己的 loader 读回去——否则快照就是死数据。"""
    eml_path, query_path = inputs
    snapshot = net.fetch_snapshot(
        eml=str(eml_path), query=str(query_path), transport=StubTransport({}))

    from mailvault.snapshot import from_dict

    reloaded = from_dict(snapshot)
    assert reloaded.resolver == snapshot["resolver"]


def test_fetch_psl_override_reads_meta_from_same_dir(inputs, tmp_path):
    """`--psl` 指向自定义冻结件时，元数据必须从**同目录**取，不能回退到随包件。"""
    eml_path, query_path = inputs
    import hashlib as _hashlib

    custom = tmp_path / "custom-psl"
    custom.mkdir()
    rules = "com\nuk\nco.uk\n"
    (custom / "public_suffix_list.dat").write_bytes(rules.encode("utf-8"))
    (custom / "psl.meta.json").write_text(json.dumps({
        "version": "custom-v",
        "date": "2026-02-02",
        "source_url": "https://publicsuffix.org/list/public_suffix_list.dat",
        "sha256": _hashlib.sha256(rules.encode("utf-8")).hexdigest(),
    }), encoding="utf-8")

    snapshot = net.fetch_snapshot(
        eml=str(eml_path), query=str(query_path),
        psl_path=str(custom / "public_suffix_list.dat"),
        transport=StubTransport({}))
    assert snapshot["psl_version"] == "custom-v"
    assert snapshot["psl_date"] == "2026-02-02"


# ── CLI 落盘 ────────────────────────────────────────────────────────────


def test_cli_snapshot_fetch_writes_canonical_file(inputs, tmp_path, monkeypatch):
    eml_path, query_path = inputs
    out = tmp_path / "snap.json"

    def fake_fetch(*, eml, query, resolver=None, psl_path=None, transport=None):
        return {
            "schema_version": 1,
            "fetched_at": "2026-10-21T00:00:00Z",
            "resolver": "synthetic",
            "psl_version": "v",
            "psl_date": "d",
            "queries": [],
        }

    monkeypatch.setattr(net, "fetch_snapshot", fake_fetch)
    code = main(["snapshot", "fetch", "--eml", str(eml_path),
                 "--query", str(query_path), "-o", str(out)])
    assert code == 0

    raw = out.read_bytes()
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    assert b"\r" not in raw
    # 键排序（canonical 口径）
    text = raw.decode("utf-8").strip()
    assert text.startswith('{"fetched_at"') or text.startswith('{"queries"')


def test_cli_snapshot_fetch_is_byte_stable(inputs, tmp_path, monkeypatch):
    """同一份输入两次抓取 → 落盘字节一致（除 fetched_at 由桩固定外）。"""
    eml_path, query_path = inputs

    def fake_fetch(*, eml, query, resolver=None, psl_path=None, transport=None):
        return {
            "schema_version": 1, "fetched_at": "2026-10-21T00:00:00Z",
            "resolver": "synthetic", "psl_version": "v", "psl_date": "d",
            "queries": [],
        }

    monkeypatch.setattr(net, "fetch_snapshot", fake_fetch)
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    assert main(["snapshot", "fetch", "--eml", str(eml_path),
                 "--query", str(query_path), "-o", str(first)]) == 0
    assert main(["snapshot", "fetch", "--eml", str(eml_path),
                 "--query", str(query_path), "-o", str(second)]) == 0
    assert first.read_bytes() == second.read_bytes()


def test_cli_snapshot_fetch_missing_eml_is_input_error(tmp_path):
    query_path = tmp_path / "query.json"
    query_path.write_text(json.dumps({"mail_from": "", "client_ip": "192.0.2.1"}),
                          encoding="utf-8")
    code = main(["snapshot", "fetch", "--eml", str(tmp_path / "nope.eml"),
                 "--query", str(query_path), "-o", str(tmp_path / "s.json")])
    assert code == 3


def test_canonical_rejects_floats_in_snapshot():
    """抓取结果里若混进浮点（例如把 ttl 算成 float），canonical 必须当场拒绝。"""
    with pytest.raises(TypeError):
        canonical.dump_file(Path("unused.json"), {"ttl": 1.5})
