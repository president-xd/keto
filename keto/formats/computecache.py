"""CUDA JIT ComputeCache (``%APPDATA%\\NVIDIA\\ComputeCache`` / ``~/.nv/ComputeCache``).

The driver stores every JIT-compiled module here: the full PTX source and the
finalized cubin. The format is undocumented; this layout was decoded from real
caches written by driver 592.82 on Windows and WSL2 (docs/research/
HOST_SIDE_DETECTION.md section 4.3)::

    index   u32 version (0x41) | u32 count | u64 total | count x {u64 key_hash, u64 payload_size}
    entry   <root>/<h[0]>/<h[1]>/<h[2:16]>  where h = "%016x" % key_hash
            u32 version | u64 text_len | u64 cubin_len | u64 hash | text[text_len] | cubin[cubin_len]
            text = compiler build stamp, "HOST64", target, padding, then the PTX source

Sizes are validated, so a format change on another driver version is reported
instead of being misparsed.
"""

from __future__ import annotations

import os
import re
import struct
from typing import Iterator, List, Optional

ENTRY_HDR = struct.Struct("<IQQQ")  # 28 bytes
INDEX_HDR = struct.Struct("<IIQ")   # 16 bytes


_STAMP_RE = re.compile(r"([A-Z][a-z]{2} [ \d]\d \d{4}) ?(\d{2}:\d{2}:\d{2}) ?(HOST\d+)? ?(sm_\d+[a-z]?)?")


class CacheEntry:
    def __init__(self, path: str, key_hash: Optional[int], version: int, text: bytes, cubin: bytes, hash_: int,
                 size_ok: bool, error: Optional[str] = None):
        self.path, self.key_hash, self.version, self.text, self.cubin = path, key_hash, version, text, cubin
        self.hash, self.size_ok, self.error = hash_, size_ok, error

    @property
    def ptx(self) -> bytes:
        i = self.text.find(b".version")
        if i < 0:
            return b""
        start = self.text.rfind(b"\n//", 0, i)
        return self.text[start + 1 if start >= 0 else i:].rstrip(b"\x00\r\n ")

    @property
    def stamp(self) -> str:
        head = self.text[:max(self.text.find(b".version"), 0) or 200]
        parts = [p.decode("ascii", "replace").strip() for p in head.replace(b"\r", b"\n").split(b"\n")]
        text = " ".join(p for p in parts if p and not p.startswith("//"))
        # the driver writes __DATE__, __TIME__, the host ABI and the target back to back:
        # "Jun  3 202617:23:34HOST64sm_89" -> "Jun 3 2026 17:23:34, HOST64, sm_89"
        m = _STAMP_RE.match(text)
        if m:
            fields = ["%s %s" % (" ".join(m.group(1).split()), m.group(2))] + [g for g in m.group(3, 4) if g]
            text = ", ".join(fields) + text[m.end():]
        return text[:120]


def parse_entry(data: bytes, path: str = "", key_hash: Optional[int] = None) -> CacheEntry:
    if len(data) < ENTRY_HDR.size:
        return CacheEntry(path, key_hash, 0, b"", b"", 0, False, "file shorter than entry header")
    version, text_len, cubin_len, h = ENTRY_HDR.unpack_from(data)
    size_ok = ENTRY_HDR.size + text_len + cubin_len == len(data)
    if text_len > len(data) or cubin_len > len(data):
        return CacheEntry(path, key_hash, version, b"", b"", h, False, "lengths exceed file size")
    text = data[ENTRY_HDR.size:ENTRY_HDR.size + text_len]
    cubin = data[ENTRY_HDR.size + text_len:ENTRY_HDR.size + text_len + cubin_len]
    err = None if size_ok else "entry size mismatch (format may differ on this driver version)"
    return CacheEntry(path, key_hash, version, text, cubin, h, size_ok, err)


def parse_index(data: bytes):
    """``(version, [(key_hash, payload_size)], ok)``."""
    if len(data) < INDEX_HDR.size:
        return None, [], False
    version, count, _total = INDEX_HDR.unpack_from(data)
    entries = []
    for i in range(count):
        off = INDEX_HDR.size + 16 * i
        if off + 16 > len(data):
            return version, entries, False
        entries.append(struct.unpack_from("<QQ", data, off))
    return version, entries, len(data) == INDEX_HDR.size + 16 * count


def entry_path(root: str, key_hash: int) -> str:
    h = "%016x" % key_hash
    return os.path.join(root, h[0], h[1], h[2:])


def iter_cache(root: str) -> Iterator[CacheEntry]:
    """Every entry under a cache directory: indexed entries first, then stray files (deleted from the index)."""
    seen = set()
    idx_path = os.path.join(root, "index")
    if os.path.isfile(idx_path):
        with open(idx_path, "rb") as fh:
            _, entries, _ = parse_index(fh.read())
        for key, _size in entries:
            p = entry_path(root, key)
            seen.add(os.path.normcase(os.path.abspath(p)))
            if os.path.isfile(p):
                with open(p, "rb") as fh:
                    yield parse_entry(fh.read(), p, key)
            else:
                yield CacheEntry(p, key, 0, b"", b"", 0, False, "indexed entry missing on disk")
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(dirpath, f)
            if f == "index" or os.path.normcase(os.path.abspath(p)) in seen:
                continue
            with open(p, "rb") as fh:
                e = parse_entry(fh.read(), p, None)
            e.error = (e.error + "; " if e.error else "") + "not referenced by the index"
            yield e


def default_roots() -> List[str]:
    roots = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.append(os.path.join(appdata, "NVIDIA", "ComputeCache"))
    custom = os.environ.get("CUDA_CACHE_PATH")
    if custom:
        roots.append(custom)
    roots.append(os.path.join(os.path.expanduser("~"), ".nv", "ComputeCache"))
    return [r for r in roots if os.path.isdir(r)]
