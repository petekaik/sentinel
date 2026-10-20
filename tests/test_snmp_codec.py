"""The BER codec and the SNMP v2c client, against a loopback agent.

Nothing here touches a device. The client's only network peer is a UDP socket
this suite binds on 127.0.0.1, and the response it sends is built by the same
codec the client decodes with -- so a codec bug that both sides share would be
invisible. That is what the KNOWN GET BYTES below are for: they pin the
encoding against a value computed by hand from the BER rules, not by calling
`ber.sequence`.

The community string is a secret (the spec says it never appears in a log,
detail or evidence). The client has no logger at all; the tests assert the fact
that would leak it if one were added -- the exception text.
"""

import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                                   # noqa: E402

from modules.snmp import ber, snmp                            # noqa: E402

OID = "1.3.6.1.2.1.1.1.0"
SECRET_COMMUNITY = "monitor-test-community"  # secretscan:ignore (test literal, no device)


# ---------------------------------------------------------------------------
# A fake agent on loopback
# ---------------------------------------------------------------------------


class FakeAgent:
    """A UDP socket on 127.0.0.1 that answers with `reply(request_bytes)`.

    `reply=None` keeps the socket bound but silent, which is what a timeout
    looks like from the client without depending on how the host reports an
    unreachable port (macOS raises ECONNREFUSED for an unbound one; the client
    is not tested against that, it is tested against silence).
    """

    def __init__(self, reply=None):
        self.reply = reply
        self.seen = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.02)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self.seen.append(data)
            if self.reply is not None:
                self.sock.sendto(self.reply(data), addr)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()
        return False


def _wait_for(predicate, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def _request_parts(data):
    """(version, community, pdu_tag, request_id, oid) from a received GET."""
    _, msg, _ = ber.parse(data, 0)
    _, version, i = ber.parse(msg, 0)
    _, community, i = ber.parse(msg, i)
    pdu_tag, pdu, _ = ber.parse(msg, i)
    _, rid, j = ber.parse(pdu, 0)
    _, _status, j = ber.parse(pdu, j)
    _, _index, j = ber.parse(pdu, j)
    _, varbinds, j = ber.parse(pdu, j)
    _, vb, _ = ber.parse(varbinds, 0)
    _, name, k = ber.parse(vb, 0)
    return (ber.parse_int(version), ber.parse_string(community), pdu_tag,
            ber.parse_int(rid), ber.parse_oid(name))


def _reply_with(value_tlv, status=0, index=0, vb_oid=OID, rid=None,
                pdu_tag=0xA2):
    """A reply builder: the response echoes the request's id unless overridden."""

    def build(request):
        _, msg, _ = ber.parse(request, 0)
        _, _version, i = ber.parse(msg, 0)
        _, _community, i = ber.parse(msg, i)
        _, pdu, _ = ber.parse(msg, i)
        _, req_rid, _ = ber.parse(pdu, 0)
        return ber.sequence(
            ber.integer(1),
            ber.octet("public"),
            ber.tlv(pdu_tag,
                    (ber.integer(rid) if rid is not None
                     else ber.tlv(0x02, req_rid))
                    + ber.integer(status)
                    + ber.integer(index)
                    + ber.sequence(ber.sequence(
                        ber.oid(vb_oid), value_tlv))))
    return build


# ---------------------------------------------------------------------------
# 1. The codec
# ---------------------------------------------------------------------------


def test_integer_round_trip(results):
    cases = [0, 1, 127, 128, 255, 256, 1234, -1, -129, 2 ** 31 - 1]
    bad = []
    for n in cases:
        tag, value, nxt = ber.parse(ber.integer(n))
        if tag != 0x02 or ber.parse_int(value) != n or nxt != len(ber.integer(n)):
            bad.append((n, ber.integer(n).hex(), ber.parse_int(value)))
    results.check(
        "integers round-trip through the BER TLV, including both signs",
        not bad,
        "these did not survive encode->decode: %r -- a negative or multi-byte "
        "integer read back as another number is a threshold graded against a "
        "value nothing measured" % (bad,))


def test_octet_string_round_trip(results):
    long_text = "x" * 200
    bad = []
    for text in ("", "public", "Sentinel agent", long_text):
        tag, value, _ = ber.parse(ber.octet(text))
        if tag != 0x04 or ber.parse_string(value) != text:
            bad.append(text[:20])
    tag, value, _ = ber.parse(ber.octet(b"\x00\xffraw"))
    results.check(
        "octet strings round-trip, including 200 bytes (long-form length) "
        "and raw bytes",
        not bad and ber.parse_string(value) == "\x00�raw",
        "bad=%r -- a length above 127 must use the long form, and a payload "
        "decoded as the wrong length shifts every following field" % (bad,))


def test_oid_round_trip(results):
    cases = [
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.4.1.2021.10.1.3.1",
        "1.3.6.1.2.1.2.2.1.8.1",
        "1.3.6.1.4.1.9999.1",          # a multi-byte arc
        "1.3.6.1.4.1.2021.4.6.0",
    ]
    bad = []
    for text in cases:
        tag, value, _ = ber.parse(ber.oid(text))
        if tag != 0x06 or ber.parse_oid(value) != text:
            bad.append((text, ber.oid(text).hex(), ber.parse_oid(value)))
    results.check(
        "OIDs round-trip, including a multi-byte arc",
        not bad,
        "these did not survive: %r -- an OID is the address of the reading, "
        "so a wrong one grades a different object (or nothing) as green"
        % (bad,))


def test_sequence_nesting_round_trip(results):
    payload = ber.sequence(ber.integer(7), ber.sequence(ber.octet("a"),
                                                       ber.integer(9)))
    tag, value, nxt = ber.parse(payload)
    t1, v1, i = ber.parse(value, 0)
    t2, v2, _ = ber.parse(value, i)
    _, inner, _ = ber.parse(v2, 0)
    results.check(
        "nested sequences parse by offset, and parse() reports where the "
        "outer TLV ends",
        tag == 0x30 and nxt == len(payload)
        and ber.parse_int(v1) == 7 and t2 == 0x30
        and ber.parse_string(inner) == "a",
        "tag=%r next=%r -- an offset that is off by one shifts every later "
        "field in the response" % (tag, nxt))


# ---------------------------------------------------------------------------
# 2. The request, against literal bytes
# ---------------------------------------------------------------------------


def test_get_request_bytes_are_the_known_encoding(results):
    """A hand-computed GET, so the test cannot agree with a broken encoder."""
    expected = (
        "30 25 "                             # message sequence, 37 bytes
        "02 01 01 "                          # version 1 (v2c)
        "04 06 70 75 62 6c 69 63 "           # community "public"
        "a0 18 "                             # GetRequest, 24 bytes
        "02 02 04 d2 "                       # request-id 1234
        "02 01 00 "                          # error-status 0
        "02 01 00 "                          # error-index 0
        "30 0c "
        "30 0a "
        "06 08 2b 06 01 02 01 01 01 00"      # OID 1.3.6.1.2.1.1.1.0
    ).split()
    got = snmp._request("public", OID, 1234).hex(" ").split()
    results.check(
        "a GET request encodes to the known BER bytes",
        got == expected,
        "got      %s\nexpected %s\n-- a request the agent misparses is a "
        "timeout that reads as a dead device" % (" ".join(got),
                                                 " ".join(expected)))


# ---------------------------------------------------------------------------
# 3. The client against the fake agent
# ---------------------------------------------------------------------------


def test_get_returns_string_and_integer(results):
    with FakeAgent(_reply_with(ber.octet("Sentinel agent"))) as agent:
        value, kind = snmp.get("127.0.0.1", "public", OID,
                               port=agent.port, timeout=2)
    parts = _request_parts(agent.seen[0]) if agent.seen else None
    results.check(
        "a string reply is returned as (value, 'string')",
        (value, kind) == ("Sentinel agent", "string"),
        "got %r -- the agent answered, so a timeout here would be the client "
        "discarding a good packet" % ((value, kind),))
    results.check(
        "the agent decoded a v2c GET for the requested OID",
        parts is not None and parts[:3] == (1, "public", 0xA0)
        and isinstance(parts[3], int) and parts[4] == OID,
        "version/community/pdu-tag/oid=%r -- the request is only a GET if the "
        "agent sees an A0 PDU with an integer id at version 1 for that OID"
        % (parts,))

    with FakeAgent(_reply_with(ber.integer(42))) as agent:
        value, kind = snmp.get("127.0.0.1", "public", OID,
                               port=agent.port, timeout=2)
    results.check(
        "an integer reply is returned as (value, 'integer')",
        (value, kind) == (42, "integer"),
        "got %r" % ((value, kind),))

    with FakeAgent(_reply_with(ber.tlv(0x41, b"\x00\x00\x01\x00"))) as agent:
        value, kind = snmp.get("127.0.0.1", "public", OID,
                               port=agent.port, timeout=2)
    results.check(
        "a Counter32 is read as an integer, not refused",
        (value, kind) == (256, "integer"),
        "got %r -- ifOperStatus and the byte counters arrive as 0x41/0x42/"
        "0x43, so refusing them refuses the device's whole MIB" % ((value, kind),))


def test_error_status_is_an_error(results):
    with FakeAgent(_reply_with(ber.octet(""), status=2, index=1)) as agent:
        try:
            snmp.get("127.0.0.1", "public", OID, port=agent.port, timeout=2)
            text = None
        except snmp.SnmpError as exc:
            text = str(exc)
    results.check(
        "a non-zero error-status raises, naming the status and the index",
        text is not None and "error-status 2" in text and "at 1" in text,
        "exception=%r -- an error-status read as a value would grade an agent "
        "error as a reading" % (text,))


def test_no_such_object_and_no_such_instance_are_errors(results):
    for vtag, word in ((0x80, "no such object"), (0x81, "no such instance")):
        with FakeAgent(_reply_with(ber.tlv(vtag, b""))) as agent:
            try:
                snmp.get("127.0.0.1", "public", OID, port=agent.port,
                         timeout=2)
                text = None
            except snmp.SnmpError as exc:
                text = str(exc)
        results.check(
            "tag 0x%02x raises SnmpError (%s) naming the OID" % (vtag, word),
            text is not None and word in text and OID in text,
            "exception=%r -- noSuchObject is the agent saying the OID does "
            "not exist, and an absence must never read as a value" % (text,))


def test_the_codec_refuses_truncation(results):
    """A short datagram must be an error, never a shorter value.

    `data[i:i + n]` on a truncated TLV silently yields fewer bytes, and an
    empty payload read as an integer is 0 -- so an unchecked parse turns a
    damaged reply into a device reporting zero.
    """
    bad = []
    cases = (
        ("an integer with no payload", lambda: ber.parse_int(b"")),
        ("a TLV that claims four bytes and carries two",
         lambda: ber.parse(b"\x02\x04\x00\x00")),
        ("a header cut in half", lambda: ber.parse(b"\x30")),
        ("a long-form length with no length bytes",
         lambda: ber.parse(b"\x30\x82")),
    )
    for name, thunk in cases:
        try:
            got = thunk()
            bad.append((name, "returned %r" % (got,)))
        except ValueError:
            pass
        except Exception as exc:                  # noqa: BLE001 - reported
            bad.append((name, "%s: %s" % (type(exc).__name__, exc)))
    results.check(
        "the codec raises ValueError on a truncated TLV and an empty integer",
        not bad,
        "bad=%r -- a silent short read is the value-zero path this test "
        "exists for" % (bad,))


def test_a_malformed_reply_is_an_snmp_error(results):
    """Decode faults are SnmpError, not IndexError/ValueError.

    Task 9 isolates failures per device by catching SnmpError; a raw IndexError
    would escape that and blank every SNMP row for the epoch.
    """
    cases = (
        ("a short integer (02 04 00 00)",
         _reply_with(b"\x02\x04\x00\x00")),
        ("a string that claims five bytes and carries one",
         _reply_with(b"\x04\x05a")),
        ("a message cut off before its payload",
         lambda request: b"\x30\x20"),
        ("an empty datagram", lambda request: b""),
    )
    bad = []
    for name, reply in cases:
        with FakeAgent(reply) as agent:
            try:
                got = snmp.get("127.0.0.1", "public", OID,
                               port=agent.port, timeout=1)
                bad.append((name, "returned %r" % (got,)))
            except snmp.SnmpError:
                pass
            except Exception as exc:              # noqa: BLE001 - reported
                bad.append((name, "%s: %s" % (type(exc).__name__, exc)))
    results.check(
        "a malformed or truncated reply raises SnmpError",
        not bad,
        "bad=%r -- the 02 04 00 00 case used to return (0, 'integer'), and "
        "the others escaped as IndexError" % (bad,))


def test_a_reply_to_another_request_is_ignored(results):
    """A late datagram on a reused port is not this request's answer."""
    state = {"n": 0}

    def stale_then_fresh(request):
        state["n"] += 1
        if state["n"] == 1:
            return _reply_with(ber.octet("stale"), rid=12345)(request)
        return _reply_with(ber.octet("fresh"))(request)

    with FakeAgent(stale_then_fresh) as agent:
        got = snmp.get("127.0.0.1", "public", OID, port=agent.port,
                       timeout=1)
        sent = len(agent.seen)
    results.check(
        "a reply whose request-id does not match is ignored and the retry is "
        "answered",
        got == ("fresh", "string") and sent == 2,
        "got=%r requests=%d -- accepting the stale reply grades another "
        "request's value as this OID's" % (got, sent))

    with FakeAgent(_reply_with(ber.octet("next"), pdu_tag=0xA1)) as agent:
        try:
            snmp.get("127.0.0.1", "public", OID, port=agent.port,
                     timeout=0.1)
            text = None
        except snmp.SnmpTimeout as exc:
            text = str(exc)
        sent = len(agent.seen)
    results.check(
        "a GetNext response (0xA1) is not accepted as this GET's answer",
        text is not None and sent == 2,
        "exception=%r requests=%d -- a PDU tag nobody checked is a reply "
        "from a different kind of request" % (text, sent))


def test_timeout_after_one_retry(results):
    with FakeAgent(reply=None) as agent:
        try:
            snmp.get("127.0.0.1", "public", OID, port=agent.port, timeout=0.05)
            text = None
        except snmp.SnmpTimeout as exc:
            text = str(exc)
        _wait_for(lambda: len(agent.seen) >= 2)
        seen = len(agent.seen)
    results.check(
        "silence raises SnmpTimeout",
        text is not None and "127.0.0.1" in text and OID in text,
        "exception=%r -- a silent agent is a dead device, and the caller must "
        "be able to tell it from a value" % (text,))
    results.check(
        "exactly one retry is sent (two datagrams, no more)",
        seen == 2,
        "the silent agent saw %d request(s) -- an unbounded retry loop turns "
        "one dead device into a poll that never ends" % (seen,))


def test_an_unsupported_value_tag_is_an_error(results):
    got = None
    with FakeAgent(_reply_with(ber.tlv(0x40, b"\x0a\x00\x00\x01"))) as agent:
        try:
            got = snmp.get("127.0.0.1", "public", OID, port=agent.port,
                           timeout=2)
            text = None
        except snmp.SnmpError as exc:
            text = str(exc)
    results.check(
        "an unsupported value tag raises SnmpError naming the tag",
        text is not None and "0x40" in text,
        "got=%r exception=%r -- returning the raw bytes of a type the checks "
        "cannot grade would be a value nothing understands" % (got, text))


def test_an_unresolvable_host_is_an_snmp_error(results):
    """A name that does not resolve is SnmpError, not a raw gaierror."""
    try:
        snmp.get("no-such-host.invalid", "public", OID, timeout=0.5)
        text = None
        timed_out = False
    except snmp.SnmpError as exc:
        text = str(exc)
        timed_out = isinstance(exc, snmp.SnmpTimeout)
    results.check(
        "an unresolvable host raises SnmpError naming the host, not a raw "
        "OSError and not a timeout",
        text is not None and "no-such-host.invalid" in text
        and not timed_out,
        "exception=%r -- a DNS failure read as 'device silent' sends the "
        "operator to the switch instead of to the resolver" % (text,))


def test_the_community_never_reaches_an_exception(results):
    """The client has no logger; the text of what it raises is the leak risk.

    EVERY error path that carries a message is driven with the community as
    the credential, so mutating any one of them to include it goes red.
    """
    leaked = []
    raised = set()

    replies = (
        ("noSuchObject", _reply_with(ber.tlv(0x80, b""))),
        ("noSuchInstance", _reply_with(ber.tlv(0x81, b""))),
        ("error-status", _reply_with(ber.octet(""), status=2, index=1)),
        ("unsupported tag", _reply_with(ber.tlv(0x40, b"\x0a\x00\x00\x01"))),
        ("malformed", _reply_with(b"\x02\x04\x00\x00")),
    )
    for name, reply in replies:
        with FakeAgent(reply) as agent:
            try:
                snmp.get("127.0.0.1", SECRET_COMMUNITY, OID,
                         port=agent.port, timeout=2)
            except snmp.SnmpError as exc:
                raised.add(name)
                if SECRET_COMMUNITY in str(exc):
                    leaked.append((name, str(exc)))
            else:
                leaked.append((name, "no exception"))

    with FakeAgent(reply=None) as agent:
        try:
            snmp.get("127.0.0.1", SECRET_COMMUNITY, OID, port=agent.port,
                     timeout=0.05)
        except snmp.SnmpError as exc:
            raised.add("timeout")
            if SECRET_COMMUNITY in str(exc):
                leaked.append(("timeout", str(exc)))

    results.check(
        "the community string never appears in any exception message",
        not leaked and len(raised) == len(replies) + 1,
        "leaked=%r raised=%r -- exception text becomes the incident detail, "
        "which is stored and shown on the dashboard, and a path that raised "
        "nothing makes this test vacuous" % (leaked, sorted(raised)))


def test_the_client_holds_no_logger(results):
    source = open(snmp.__file__).read()
    results.check(
        "snmp.py imports no logging module, so there is no log to leak into",
        "import logging" not in source and "getLogger" not in source,
        "snmp.py grew a logger -- if it logs a request it logs the community "
        "unless it is masked, and nothing currently asserts that")


TESTS = (
    test_integer_round_trip,
    test_octet_string_round_trip,
    test_oid_round_trip,
    test_sequence_nesting_round_trip,
    test_the_codec_refuses_truncation,
    test_get_request_bytes_are_the_known_encoding,
    test_get_returns_string_and_integer,
    test_error_status_is_an_error,
    test_no_such_object_and_no_such_instance_are_errors,
    test_a_malformed_reply_is_an_snmp_error,
    test_a_reply_to_another_request_is_ignored,
    test_an_unsupported_value_tag_is_an_error,
    test_an_unresolvable_host_is_an_snmp_error,
    test_timeout_after_one_retry,
    test_the_community_never_reaches_an_exception,
    test_the_client_holds_no_logger,
)
