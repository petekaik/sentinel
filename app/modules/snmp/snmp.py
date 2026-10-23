"""The SNMP v2c client: GET, GetNext, a bounded walk, one retry per request.

No logging on purpose -- the community string is a secret and there is nothing
this module could log that would not be either the packet or the credential.
Errors carry the host and the OID, never the community.
"""

import os
import socket

from . import ber


class SnmpError(Exception):
    pass


class SnmpTimeout(SnmpError):
    pass


class SnmpEndOfMib(SnmpError):
    """The v2c endOfMibView exception: a GetNext past the last object.

    It is an ANSWER, not a failure -- the agent looked and says there is
    nothing after this OID. walk() turns it into a clean end; nothing else
    should read it as a dead device.
    """


class SnmpTransportError(SnmpError):
    """The socket could not be used (DNS, unreachable, permission, ...).

    The two TRANSPORT failures -- this and SnmpTimeout -- are "I could not
    ask". Every other SnmpError carries an ANSWER: a noSuchObject, an error-
    status or a malformed reply all come from something that is alive. The
    module's preload grades device reachability on exactly that distinction,
    and telling the two apart by message prefix would rot with the wording.
    """


def _request(community, oid, request_id, tag=0xA0):
    return ber.sequence(
        ber.integer(1),                       # v2c
        ber.octet(community),
        ber.tlv(tag,                          # 0xA0 GetRequest, 0xA1 GetNext
                ber.integer(request_id) + ber.integer(0) +
                ber.integer(0) +
                # THE VARBIND ENDS WITH AN EXPLICIT NULL (RFC 3416 §4.2.1).
                # Leaving it out produced a request that every real agent
                # silently dropped -- a timeout per device, which the module
                # then graded as "not answering". The unit test agreed with the
                # encoder because it was hand-computed from the same bytes, so
                # the fake agent below now REFUSES a varbind without it.
                ber.sequence(ber.sequence(ber.oid(oid) + ber.tlv(0x05, b"")))))


def _value(vtag, value):
    """(decoded_value, kind) for a standard SNMP v2c value type.

    EVERY STANDARD TYPE, because a WALK meets all of them: a subtree contains
    OBJECT IDENTIFIERs (sysObjectID), IpAddresses (ipAdEntAddr), Counter64s
    (ifHCInOctets) and the occasional Opaque. Refusing a type does not skip
    that row -- it aborts the whole walk, which on a switch hid every object
    after the first OID-valued one ("unsupported value tag 0x06").
    """
    if vtag == 0x02:                              # INTEGER, signed
        return ber.parse_int(value), "integer"
    if vtag in (0x41, 0x42, 0x43, 0x46, 0x47):
        # Counter32 / Gauge32 / TimeTicks / Counter64 / Uinteger32
        return ber.parse_uint(value), "integer"
    if vtag == 0x04:
        return ber.parse_string(value), "string"
    if vtag == 0x06:
        return ber.parse_oid(value), "oid"
    if vtag == 0x40:
        return ber.parse_ip(value), "string"
    if vtag == 0x44:
        # Opaque is agent-defined bytes, not text: hex is the honest form.
        return value.hex(), "opaque"
    raise SnmpError("unsupported value tag 0x%02x" % vtag)


def _decode_varbind(vb):
    """(oid, value, kind) for one varbind; exceptions get their own kind."""
    _, name, k = ber.parse(vb, 0)
    name_text = ber.parse_oid(name)
    vtag, value, _ = ber.parse(vb, k)
    if vtag == 0x80:
        return name_text, None, "no_such_object"
    if vtag == 0x81:
        return name_text, None, "no_such_instance"
    if vtag == 0x82:
        return name_text, None, "end"
    decoded, kind = _value(vtag, value)
    return name_text, decoded, kind


def _message(data, rid, host):
    """(status, index, varbinds) for a reply that answers `rid`, else None.

    A LATE DATAGRAM IS NOT THIS REQUEST'S ANSWER. The socket is fresh per
    attempt, but an ephemeral port can be reused, so the request-id (and the
    GetResponse tag) decide whether this reply is ours.
    """
    try:
        _, msg, _ = ber.parse(data, 0)
        _, _version, i = ber.parse(msg, 0)
        _, _community, i = ber.parse(msg, i)
        ptag, pdu, _ = ber.parse(msg, i)
        _, req, j = ber.parse(pdu, 0)
        req_id = ber.parse_int(req)
        if ptag != 0xA2 or req_id != rid:
            return None
        _, err_status, j = ber.parse(pdu, j)
        _, err_index, j = ber.parse(pdu, j)
        _, varbinds, _ = ber.parse(pdu, j)
        return ber.parse_int(err_status), ber.parse_int(err_index), varbinds
    except (IndexError, ValueError):
        raise SnmpError("malformed response from %s" % host)


def _decode(data, rid, host):
    """(oid, value, kind) from a reply, or None when it answers another request.

    The error-status and the v2c exception tags are answers, not values: 0x80
    and 0x81 raise, and 0x82 raises SnmpEndOfMib so a walk can stop cleanly.
    """
    got = _message(data, rid, host)
    if got is None:
        return None
    status, index, varbinds = got
    if status:
        raise SnmpError("error-status %d at %d" % (status, index))
    try:
        _, vb, _ = ber.parse(varbinds, 0)
        name_text, value, kind = _decode_varbind(vb)
    except (IndexError, ValueError):
        raise SnmpError("malformed response from %s" % host)
    if kind == "no_such_object":
        raise SnmpError("no such object: %s" % name_text)
    if kind == "no_such_instance":
        raise SnmpError("no such instance: %s" % name_text)
    if kind == "end":
        raise SnmpEndOfMib("end of MIB view at %s" % name_text)
    return name_text, value, kind


def _decode_many(data, rid, host):
    """[(oid, value, kind)] from a GetBulk reply, or None for another request."""
    got = _message(data, rid, host)
    if got is None:
        return None
    status, index, varbinds = got
    if status:
        raise SnmpError("error-status %d at %d" % (status, index))
    out, k = [], 0
    try:
        while k < len(varbinds):
            _, vb, k = ber.parse(varbinds, k)
            out.append(_decode_varbind(vb))
    except (IndexError, ValueError):
        raise SnmpError("malformed response from %s" % host)
    return out


def _request_bulk(community, oid, request_id, max_repetitions):
    """A GetBulk: the two INTEGER fields after the id are non-repeaters and
    max-repetitions, not error-status/error-index (RFC 3416 §4.2.3)."""
    return ber.sequence(
        ber.integer(1),                       # v2c
        ber.octet(community),
        ber.tlv(0xA5,
                ber.integer(request_id) + ber.integer(0) +
                ber.integer(max_repetitions) +
                ber.sequence(ber.sequence(ber.oid(oid) + ber.tlv(0x05, b"")))))


def _one(host, community, oid, tag, port=161, timeout=3.0, retries=1):
    """(oid, value, kind) for one request, or raise SnmpError/SnmpTimeout."""
    rid = int.from_bytes(os.urandom(4), "big") & 0x7fffffff
    packet = _request(community, oid, rid, tag)
    for _ in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError as exc:                   # gaierror, unreachable, ...
            raise SnmpTransportError("cannot query %s: %s" % (host, exc))
        finally:
            sock.close()
        got = _decode(data, rid, host)
        if got is not None:
            return got
    raise SnmpTimeout("no answer from %s for %s" % (host, oid))


def _bulk(host, community, oid, port=161, timeout=3.0, retries=1,
          max_repetitions=25):
    """[(oid, value, kind)] for up to `max_repetitions` objects after `oid`."""
    rid = int.from_bytes(os.urandom(4), "big") & 0x7fffffff
    packet = _request_bulk(community, oid, rid, max_repetitions)
    for _ in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError as exc:
            raise SnmpTransportError("cannot query %s: %s" % (host, exc))
        finally:
            sock.close()
        got = _decode_many(data, rid, host)
        if got is not None:
            return got
    raise SnmpTimeout("no answer from %s for %s" % (host, oid))


def get(host, community, oid, port=161, timeout=3.0, retries=1):
    """(value, type) for one OID, or raise SnmpError/SnmpTimeout.

    EVERY failure is a SnmpError. A decode fault is wrapped because callers
    isolate per device -- a raw IndexError from a truncated datagram would
    escape that isolation and blank the module's rows for the epoch instead of
    failing the one device that sent it.
    """
    _, value, kind = _one(host, community, oid, 0xA0, port=port,
                          timeout=timeout, retries=retries)
    return value, kind


def getnext(host, community, oid, port=161, timeout=3.0, retries=1):
    """(next_oid, value, type) after `oid`, or raise SnmpEndOfMib.

    The returned name is the agent's, not ours: only the reply can say which
    object follows, which is why a walk trusts it and then checks the subtree.
    """
    return _one(host, community, oid, 0xA1, port=port, timeout=timeout,
                retries=retries)


def _walk_getnext(host, community, root, port, timeout, max_oids, retries):
    rows, oid = [], root
    while len(rows) < max_oids:
        try:
            next_oid, value, kind = getnext(host, community, oid, port=port,
                                            timeout=timeout, retries=retries)
        except SnmpEndOfMib:
            return rows, False
        # A GetNext that leaves the subtree is the end of it: the next object
        # exists, but it is not this walk's.
        if not next_oid.startswith(root + "."):
            return rows, False
        rows.append((next_oid, value, kind))
        oid = next_oid
    return rows, _truncation_probe(host, community, root, rows, oid, port,
                                   timeout, retries)


def _walk_bulk(host, community, root, port, timeout, max_oids, retries):
    rows, oid = [], root
    while len(rows) < max_oids:
        try:
            batch = _bulk(host, community, oid, port=port, timeout=timeout,
                          retries=retries,
                          max_repetitions=min(25, max_oids - len(rows)))
        except SnmpError:
            # A FAILURE AFTER ROWS HAVE BEEN READ IS A TRUNCATED WALK, NOT A
            # REASON TO RE-WALK FROM THE ROOT. Only a first-request failure can
            # mean "this agent does not do GetBulk"; re-walking 20,000 objects
            # with GetNext because one bulk datagram was lost is how a scan
            # times out.
            if rows:
                return rows, True
            raise
        if not batch:
            return rows, False
        advanced = False
        for next_oid, value, kind in batch:
            if kind == "end":
                return rows, False
            if not next_oid.startswith(root + "."):
                return rows, False
            advanced = True
            oid = next_oid
            if kind in ("no_such_object", "no_such_instance"):
                continue
            rows.append((next_oid, value, kind))
            if len(rows) >= max_oids:
                break
        # A batch that names nothing new would spin forever; report what was
        # read as truncated rather than pretending it was the end.
        if not advanced:
            return rows, True
    return rows, _truncation_probe(host, community, root, rows, oid, port,
                                   timeout, retries)


def _truncation_probe(host, community, root, rows, oid, port, timeout,
                      retries):
    if not rows:                                # max_oids <= 0: asked for none
        return False
    # The cap stopped the walk. ONE probe says whether the subtree really
    # ended at it; silence or a transport failure leaves the answer unknown,
    # and unknown must be reported as truncated rather than as complete.
    try:
        nxt, _, _ = getnext(host, community, oid, port=port, timeout=timeout,
                            retries=retries)
    except SnmpEndOfMib:
        return False
    except SnmpError:
        return True
    return nxt.startswith(root + ".")


def walk(host, community, root, port=161, timeout=3.0, max_oids=2000,
         retries=1):
    """(rows, truncated) for objects after `root`, within its subtree.

    `root` itself is never returned: a GetNext is strictly greater than the
    OID it names, so a walk starts at the first object after the root.

    GETBULK IS THE DEFAULT. One GetNext per object is a round trip per object;
    a switch with 34,000 objects is minutes of latency and a guaranteed
    timeout. GetBulk asks for 25 at a time. An agent that refuses the PDU (a
    non-compliant v2c agent, or one that ignores it) falls back to GetNext --
    once, from the root, because a partially read bulk cannot be trusted to
    resume.

    `rows` is [(oid, value, type)], in the agent's order. `truncated` is True
    when objects remain past the cap.
    """
    try:
        return _walk_bulk(host, community, root, port, timeout, max_oids,
                          retries)
    except SnmpError:
        return _walk_getnext(host, community, root, port, timeout, max_oids,
                             retries)
