"""Operator-supplied MIB files, stored under the monitor's data volume.

A MIB is the authority on what an OID means; the bundled `SEMANTICS` table is
only the subset we could review. An operator can upload a vendor MIB (the
UniFi AP MIB, for example) per device, and it is kept beside the store so it
survives a redeploy. This delivery STORES them and makes them visible; parsing
them into names/units is a later step, and nothing here executes a file.

The data directory is the one the SQLite store lives in (`MONITOR_DATA`),
mounted from the NAS by compose.yml, so `mibs/<device>/<file>` is on the host.
"""

import os
import re
import time

# A MIB name is a file name, not a path: no separators, no leading dot, a
# conservative character set and a text extension. The content is text; the
# caller has already JSON-decoded it.
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_EXT = re.compile(r"\.(mib|txt|my)$", re.IGNORECASE)
MAX_BYTES = 4 * 1024 * 1024


def root(cfg):
    """`<data>/mibs` -- next to the store, on the mounted volume."""
    return os.path.join(os.path.dirname(os.path.abspath(cfg.db_path)), "mibs")


def device_dir(cfg, device):
    """A filesystem-safe directory name for one device.

    Device names are settings values and may contain anything; the sanitised
    form is what the operator sees in the path, and `list_for` maps it back
    from the configured name.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(device or "")).strip("._")
    return os.path.join(root(cfg), safe or "device")


def check_name(filename):
    name = os.path.basename(str(filename or ""))
    if name != str(filename or "").strip() or not _NAME.match(name):
        raise ValueError("the file name must be a plain name "
                         "(letters, digits, dot, dash, underscore)")
    # A MIB DOWNLOADED FROM A VENDOR SITE OFTEN HAS NO EXTENSION
    # ("UI-Combined-MIB"). The extension is a hint, not a gate: a plain name
    # with no suffix is allowed, and a WRONG suffix (.exe) is still refused.
    _base, ext = os.path.splitext(name)
    if ext and not _EXT.search(name):
        raise ValueError("only .mib, .txt or .my files (or no extension) "
                         "can be uploaded")
    return name


def store(cfg, device, filename, content):
    """Write one MIB atomically and return its metadata.

    ATOMIC, because a half-written MIB is worse than none: the next reader
    would parse a truncated module. The temporary name is in the same
    directory, so `os.replace` is atomic on the NAS filesystem.
    """
    name = check_name(filename)
    if not isinstance(content, str) or not content.strip():
        raise ValueError("the file is empty")
    data = content.encode("utf-8")
    if len(data) > MAX_BYTES:
        raise ValueError("the file is larger than %d bytes" % MAX_BYTES)
    directory = device_dir(cfg, device)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    final = os.path.join(directory, name)
    temp = final + ".upload"
    with open(temp, "wb") as fh:
        fh.write(data)
    os.chmod(temp, 0o600)
    os.replace(temp, final)
    return {"name": name, "size": len(data)}


def list_for(cfg, device):
    directory = device_dir(cfg, device)
    try:
        entries = os.listdir(directory)
    except OSError:
        return []
    out = []
    for name in entries:
        if not _NAME.match(name) or not _EXT.search(name):
            continue
        path = os.path.join(directory, name)
        try:
            stat = os.stat(path)
        except OSError:
            continue
        out.append({"name": name, "size": stat.st_size,
                    "mtime": stat.st_mtime})
    return sorted(out, key=lambda f: f["name"].lower())


def list_all(cfg, devices):
    """{configured device name: [files]} -- for the module page."""
    return {str(d): list_for(cfg, d) for d in devices}
