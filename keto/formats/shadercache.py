"""Graphics/compute shader caches on disk: which programs compiled GPU shaders, when, on which adapter.

* Microsoft D3D shader cache (``%LOCALAPPDATA%\\D3DSCache\\<app hash>\\<GUID>[_VEN_xxxx&DEV_xxxx...].dxcache``):
  SQLite databases (observed schema: ``app_id(exe_path, app_name, engine_name, ...)``,
  ``keys(keyid, key, last_accessed REAL = Unix time)``, ``vals(keyid, type, value BLOB)``); values hold DXBC/DXIL
  shader containers. Opened read-only from a private copy (database + WAL), never in place.
* NVIDIA DXCache (``%LOCALAPPDATA%\\NVIDIA\\DXCache\\*.nvph``, magic ``nvph``) and GLCache
  (``%LOCALAPPDATA%\\NVIDIA\\GLCache\\<app hash>\\<n>\\*.bin|.toc``, magic ``CDVN``; Linux ``~/.nv/GLCache``,
  ``~/.cache/nvidia/GLCache``): undocumented; reported by file, time, magic, embedded program names and the
  shader containers found inside.
* Mesa (``~/.cache/mesa_shader_cache``) is listed by file and time for completeness.

Like the CUDA ComputeCache, these are execution artefacts: a program that ran GPU shaders leaves entries even
after it is deleted.
"""

from __future__ import annotations

import glob
import os
import re
import shutil
import sqlite3
import tempfile
from typing import Iterator, List, Optional

from keto.formats import gpucode

PCI_VENDORS = {0x10DE: "NVIDIA", 0x8086: "Intel", 0x1002: "AMD", 0x1414: "Microsoft (software)"}
_ADAPTER_RE = re.compile(r"VEN_([0-9A-Fa-f]{4})&DEV_([0-9A-Fa-f]{4})")
_EXE_RE = re.compile(rb"(?:[A-Za-z]:\\[\x20-\x7e]{1,240}?|[\w\-. ]{2,80})\.exe\b", re.I)
_EXE16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){2,200}?\.\x00[eE]\x00[xX]\x00[eE]\x00")


class CacheEntry:
    __slots__ = ("kind", "path", "app", "adapter", "entries", "shaders", "compute_shaders", "first", "last",
                 "names", "error")

    def __init__(self, kind, path):
        self.kind, self.path = kind, path
        self.app: Optional[str] = None
        self.adapter: Optional[str] = None
        self.entries = 0
        self.shaders = 0
        self.compute_shaders = 0
        self.first: Optional[float] = None
        self.last: Optional[float] = None
        self.names: List[str] = []
        self.error: Optional[str] = None


def default_roots() -> List[tuple]:
    """``[(kind, root)]`` present on this machine."""
    out = []
    local = os.environ.get("LOCALAPPDATA")
    home = os.path.expanduser("~")
    for kind, path in (("d3d", os.path.join(local, "D3DSCache") if local else None),
                       ("nvdx", os.path.join(local, "NVIDIA", "DXCache") if local else None),
                       ("nvgl", os.path.join(local, "NVIDIA", "GLCache") if local else None),
                       ("nvgl", os.path.join(home, ".nv", "GLCache")),
                       ("nvgl", os.path.join(home, ".cache", "nvidia", "GLCache")),
                       ("mesa", os.path.join(home, ".cache", "mesa_shader_cache"))):
        if path and os.path.isdir(path):
            out.append((kind, path))
    return out


def adapter_label(name: str) -> Optional[str]:
    m = _ADAPTER_RE.search(name)
    if not m:
        return None
    ven, dev = int(m.group(1), 16), int(m.group(2), 16)
    return "%s %04X:%04X" % (PCI_VENDORS.get(ven, "vendor %04X" % ven), ven, dev)


def _count_shaders(blob: bytes, e: CacheEntry, limit: Optional[int] = None):
    """Count DXBC/DXIL and SPIR-V containers in ``blob`` that start before ``limit`` (default: anywhere)."""
    end = len(blob) if limit is None else limit
    pos = blob.find(gpucode.DXBC_MAGIC, 0, end)
    while pos != -1:
        c = gpucode.parse_dxbc(blob[pos:pos + (1 << 20)])
        if c is not None:
            e.shaders += 1
            if c.program_type == "compute":
                e.compute_shaders += 1
        pos = blob.find(gpucode.DXBC_MAGIC, pos + 4, end)
    pos = blob.find(gpucode.SPIRV_MAGIC_BYTES, 0, end)
    while pos != -1:
        m = gpucode.parse_spirv(blob[pos:pos + gpucode.MAX_SPIRV])
        if m is not None:
            e.shaders += 1
            if any(model in ("glcompute", "kernel") for model, _ in m.entries):
                e.compute_shaders += 1
        pos = blob.find(gpucode.SPIRV_MAGIC_BYTES, pos + 4, end)


def _names(blob: bytes) -> List[str]:
    out = {m.group().decode("latin-1") for m in _EXE_RE.finditer(blob)}
    out |= {m.group().decode("utf-16-le", "replace") for m in _EXE16_RE.finditer(blob)}
    return sorted(n.strip() for n in out if len(n.strip()) > 4)


def read_d3d(path: str) -> CacheEntry:
    """One D3DSCache database, read from a private copy (database, -wal) so the evidence is not modified."""
    e = CacheEntry("d3d", path)
    e.adapter = adapter_label(os.path.basename(path))
    tmp = tempfile.mkdtemp(prefix="keto-d3d-")
    try:
        copy = os.path.join(tmp, "c.db")
        shutil.copyfile(path, copy)
        if os.path.exists(path + "-wal"):
            shutil.copyfile(path + "-wal", copy + "-wal")
        db = sqlite3.connect(copy)
        try:
            tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
            if "app_id" in tables:
                row = db.execute("select exe_path, app_name from app_id limit 1").fetchone()
                if row:
                    e.app = row[0] or row[1]
            if "keys" in tables:
                e.entries, e.first, e.last = db.execute(
                    "select count(*), min(last_accessed), max(last_accessed) from keys").fetchone()
            if "vals" in tables:
                for (blob,) in db.execute("select value from vals"):
                    if isinstance(blob, bytes):
                        _count_shaders(blob, e)
        finally:
            db.close()
    except (sqlite3.Error, OSError) as exc:
        e.error = "%s: %s" % (type(exc).__name__, exc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return e


READ_CHUNK = 64 << 20
CHUNK_OVERLAP = 1 << 20  # a shader container (<= 1 MiB parsed) or a program name crossing a chunk is still seen


def read_blob_file(kind: str, path: str) -> CacheEntry:
    """One NVIDIA DXCache/GLCache or Mesa file, read completely in overlapping chunks (large caches are common:
    hundreds of MB), counting shader containers and collecting embedded program names."""
    e = CacheEntry(kind, path)
    names = set()
    try:
        st = os.stat(path)
        e.first, e.last = st.st_ctime, st.st_mtime
        with open(path, "rb") as fh:
            magic = fh.read(4)
            fh.seek(0)
            pos = 0
            while True:
                fh.seek(pos)
                blob = fh.read(READ_CHUNK + CHUNK_OVERLAP)
                if not blob:
                    break
                last = len(blob) < READ_CHUNK + CHUNK_OVERLAP
                part = CacheEntry(kind, path)
                # count only containers that start in this chunk's own part (the overlap belongs to the next one)
                _count_shaders(blob, part, limit=None if last else READ_CHUNK)
                e.shaders += part.shaders
                e.compute_shaders += part.compute_shaders
                names.update(_names(blob))
                if last:
                    break
                pos += READ_CHUNK
    except OSError as exc:
        e.error = str(exc)
        return e
    e.entries = 1
    e.names = sorted(names)
    if kind == "nvdx" and magic != b"nvph":
        e.error = "unexpected magic %r" % magic
    if kind == "nvgl" and magic not in (b"CDVN",) and not path.endswith(".toc"):
        e.error = "unexpected magic %r" % magic
    return e


def guess_kind(root: str) -> Optional[str]:
    """The cache kind of a collected directory, from its files (``*.dxcache`` = D3D, ``nvph`` magic = NVIDIA
    DXCache, ``CDVN`` magic = NVIDIA GLCache, Mesa's ``index`` file / ``mesa`` path); None when unknown."""
    if glob.glob(os.path.join(root, "*", "*.dxcache")) or glob.glob(os.path.join(root, "*.dxcache")):
        return "d3d"
    checked = 0
    for dp, _dns, fns in os.walk(root):
        for fn in fns:
            try:
                with open(os.path.join(dp, fn), "rb") as fh:
                    magic = fh.read(4)
            except OSError:
                continue
            if magic == b"nvph":
                return "nvdx"
            if magic == b"CDVN":
                return "nvgl"
            checked += 1
            if checked > 200:
                break
        if checked > 200:
            break
    if "mesa" in root.lower() or os.path.exists(os.path.join(root, "index")):
        return "mesa"
    return None


def iter_cache(kind: str, root: str) -> Iterator[CacheEntry]:
    if kind == "d3d":
        for p in sorted(glob.glob(os.path.join(root, "*", "*.dxcache"))):
            yield read_d3d(p)
        return
    for dp, _dns, fns in os.walk(root):
        for fn in sorted(fns):
            if fn.endswith(("-shm", ".lock")):
                continue
            yield read_blob_file(kind, os.path.join(dp, fn))
