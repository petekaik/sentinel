"""The SNMP v2c client: one GET, one retry, a bounded UDP timeout.

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


def _request(community, oid, request_id):
    return ber.sequence(
        ber.integer(1),                       # v2c
        ber.octet(community),
        ber.tlv(0xA0,                         # GetRequest
                ber.integer(request_id) + ber.integer(0) +
                ber.integer(0) +
                ber.sequence(ber.sequence(ber.oid(oid)))))


def get(host, community, oid, port=161, timeout=3.0, retries=1):
    """(value, type) for one OID, or raise SnmpError/SnmpTimeout."""
    rid = int.from_bytes(os.urandom(4), "big") & 0x7fffffff
    packet = _request(community, oid, rid)
    for _ in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        finally:
            sock.close()
        _, msg, _ = ber.parse(data, 0)
        _, _version, i = ber.parse(msg, 0)
        _, _community, i = ber.parse(msg, i)
        _ptag, pdu, _ = ber.parse(msg, i)
        _, _req, j = ber.parse(pdu, 0)
        _, err_status, j = ber.parse(pdu, j)
        _, err_index, j = ber.parse(pdu, j)
        _, varbinds, j = ber.parse(pdu, j)
        _, vb, _ = ber.parse(varbinds, 0)
        _, name, k = ber.parse(vb, 0)
        vtag, value, _ = ber.parse(vb, k)
        if ber.parse_int(err_status):
            raise SnmpError("error-status %d at %d"
                            % (ber.parse_int(err_status),
                               ber.parse_int(err_index)))
        if vtag == 0x80:
            raise SnmpError("no such object: %s" % ber.parse_oid(name))
        if vtag == 0x81:
            raise SnmpError("no such instance: %s" % ber.parse_oid(name))
        if vtag in (0x02, 0x41, 0x42, 0x43):     # integer/counter/gauge/ticks
            return ber.parse_int(value), "integer"
        if vtag == 0x04:
            return ber.parse_string(value), "string"
        raise SnmpError("unsupported value tag 0x%02x" % vtag)
    raise SnmpTimeout("no answer from %s for %s" % (host, oid))
