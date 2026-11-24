"""Finding a module's symbols on disk, and fetching them from a symbol server on explicit request.

Analysis never touches the network. ``keto pdb fetch`` (or :func:`fetch`) is the only path that does; it
sends the PDB file name and its GUID/age (a build identifier, nothing about the case) to the server and stores
the file in Keto's symbol cache in the symbol-store layout ``<pdb>/<GUID><age>/<pdb>``.

Search order (:func:`search_dirs`): directories given by the analyst, Keto's cache (``KETO_SYMBOLS``, else
``%LOCALAPPDATA%\\keto\\symbols`` / ``~/.cache/keto/symbols``), local stores named in ``_NT_SYMBOL_PATH``,
WinDbg's default cache ``C:\\ProgramData\\Dbg\\sym``, ``C:\\Symbols`` and the Windows SDK debugger's ``sym``
folders. A directory may also hold Volatility symbol packs (``windows/<pdb>/<GUID-age>.json.xz``).
"""

from __future__ import annotations

import os
import struct
import tempfile
import urllib.error
import urllib.request
import zlib
from typing import Callable, Iterable, List, Optional

from keto.winmem import isf, pdb
from keto.winmem.symtab import SymbolError, SymbolTable

SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"
USER_AGENT = "keto-symbols/1.0"
MAX_PDB = 1 << 30


def default_cache() -> str:
    env = os.environ.get("KETO_SYMBOLS")
    if env:
        return env
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return os.path.join(os.environ["LOCALAPPDATA"], "keto", "symbols")
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "keto", "symbols")


def _nt_symbol_path_dirs(value: str) -> List[str]:
    out = []
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        low = part.lower()
        if low.startswith(("srv*", "symsrv*", "cache*")):
            for piece in part.split("*")[1:]:
                if piece and not piece.lower().startswith(("http:", "https:")) and not piece.lower().endswith(".dll"):
                    out.append(piece)
        elif not low.startswith(("http:", "https:")):
            out.append(part)
    return out


def search_dirs(extra: Iterable[str] = ()) -> List[str]:
    dirs = [d for d in extra if d] + [default_cache()]
    dirs += _nt_symbol_path_dirs(os.environ.get("_NT_SYMBOL_PATH", ""))
    if os.name == "nt":
        pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        dirs += [r"C:\ProgramData\Dbg\sym", r"C:\Symbols",
                 os.path.join(pf86, "Windows Kits", "10", "Debuggers", "x64", "sym"),
                 os.path.join(pf86, "Windows Kits", "10", "Debuggers", "sym")]
    seen, out = set(), []
    for d in dirs:
        key = os.path.normcase(os.path.abspath(d))
        if key not in seen and os.path.isdir(d):
            seen.add(key)
            out.append(d)
    return out


def find_local(pdb_name: str, key: str, dirs: Iterable[str]) -> Optional[str]:
    """Path of a PDB or ISF file for ``pdb_name`` with symbol-server ``key`` (GUID + age in hex)."""
    stem = key[:32]
    isf_names = []
    for k in (key, "%s-%s" % (stem, key[32:]), stem):
        isf_names += [k + ".json.xz", k + ".json.gz", k + ".json"]
    for d in dirs:
        cand = os.path.join(d, pdb_name, key, pdb_name)
        if os.path.isfile(cand):
            return cand
        for sub in (os.path.join(d, "windows", pdb_name), os.path.join(d, pdb_name)):
            for name in isf_names:
                cand = os.path.join(sub, name)
                if os.path.isfile(cand):
                    return cand
    return None


def load(path: str) -> SymbolTable:
    low = path.lower()
    if low.endswith((".json", ".json.xz", ".json.gz", ".json.bz2")):
        return isf.load(path)
    return pdb.load(path)


def check_match(table: SymbolTable, pdb_name: str, key: str) -> List[str]:
    """Problems that make ``table`` the wrong symbols for an image whose CodeView record gave ``key``."""
    problems = []
    if table.guid and table.guid != key[:32]:
        problems.append("symbol file GUID %s does not match the image (%s)" % (table.guid, key[:32]))
    return problems


# -- fetching ------------------------------------------------------------------------------------------------
def _download(url: str, timeout: float, progress: Optional[Callable[[int], None]]) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https symbol server only
        out = bytearray()
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            out += chunk
            if len(out) > MAX_PDB:
                raise SymbolError("symbol download exceeds %d bytes" % MAX_PDB)
            if progress:
                progress(len(out))
        return bytes(out)


def cab_extract(data: bytes) -> bytes:
    """The single file of a cabinet using no compression or MSZIP (what symbol servers serve as ``.pd_``).
    MSZIP blocks are raw deflate streams (after a ``CK`` marker) that may refer to the previous block's output."""
    if data[:4] != b"MSCF":
        raise SymbolError("not a cabinet file")
    _cab_size, = struct.unpack_from("<I", data, 8)
    files_off, = struct.unpack_from("<I", data, 16)
    nfolders, nfiles, flags = struct.unpack_from("<HHH", data, 26)
    pos = 36
    cf_folder_res = cf_data_res = 0
    if flags & 4:  # cfhdrRESERVE_PRESENT
        hdr_res, cf_folder_res, cf_data_res = struct.unpack_from("<HBB", data, pos)
        pos += 4 + hdr_res
    for bit in (1, 2):  # previous / next cabinet names
        if flags & bit:
            for _ in range(2):
                pos = data.index(b"\x00", pos) + 1
    if nfolders != 1 or nfiles != 1:
        raise SymbolError("cabinet holds %d folders / %d files; expected one file" % (nfolders, nfiles))
    data_off, ndata, comp = struct.unpack_from("<IHH", data, pos)
    method = comp & 0x0F
    if method not in (0, 1):
        raise SymbolError("cabinet compression %d (LZX/Quantum) is not supported; fetch the PDB with symchk instead"
                          % method)
    out = bytearray()
    pos = data_off
    for _ in range(ndata):
        _csum, cb, _ucb = struct.unpack_from("<IHH", data, pos)
        pos += 8 + cf_data_res
        block = data[pos:pos + cb]
        pos += cb
        if method == 0:
            out += block
            continue
        if block[:2] != b"CK":
            raise SymbolError("bad MSZIP block signature")
        d = zlib.decompressobj(-15, zdict=bytes(out[-32768:])) if out else zlib.decompressobj(-15)
        out += d.decompress(block[2:]) + d.flush()
    _ = files_off
    return bytes(out)


def fetch(pdb_name: str, key: str, dest: Optional[str] = None, server: str = SYMBOL_SERVER, timeout: float = 120,
          progress: Optional[Callable[[int], None]] = None) -> str:
    """Download ``pdb_name`` for ``key`` into the cache (or ``dest``); returns the stored path. The file is
    checked to be a PDB with the requested GUID before it is stored."""
    dest = dest or default_cache()
    base = "%s/%s/%s/" % (server.rstrip("/"), pdb_name, key)
    try:
        data = _download(base + pdb_name, timeout, progress)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise SymbolError("symbol server answered HTTP %d for %s" % (e.code, base + pdb_name))
        try:
            data = cab_extract(_download(base + pdb_name[:-1] + "_", timeout, progress))
        except urllib.error.HTTPError as e2:
            raise SymbolError("symbol server has no %s for %s (HTTP %d)" % (pdb_name, key, e2.code))
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise SymbolError(
            "cannot reach the symbol server %s: %s. If this network blocks it, run the same 'keto pdb fetch' on "
            "another network (any machine; the file depends only on the build) and copy %s into %s, or give the "
            "analysis --pdb / --isf / --symbols-dir" % (server, reason, os.path.join(pdb_name, key, pdb_name), dest))
    table = pdb.PdbSymbols(data, source=base + pdb_name)
    if table.guid != key[:32]:
        raise SymbolError("downloaded PDB has GUID %s, expected %s" % (table.guid, key[:32]))
    folder = os.path.join(dest, pdb_name, key)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, pdb_name)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".part-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return path
