"""Offline analysis of collected CUDA JIT ComputeCache directories (Windows or Linux)."""

from __future__ import annotations

import datetime as _dt
import hashlib
import os

from keto.formats import computecache, cubin as cubin_fmt, ptx as ptx_fmt
from keto.framework.exceptions import RequirementError
from keto.framework.plugin import Plugin, Requirement, TimeLinerInterface
from keto.framework.treegrid import Hex, TreeGrid, na
from keto.indicators import driver_kernels, miners


class JitCache(Plugin, TimeLinerInterface):
    NAME = "nvidia.jitcache"
    CATEGORY = "nvidia.code"
    DESCRIPTION = ("Parses a CUDA JIT ComputeCache directory collected from any machine (Windows "
                   "%APPDATA%\\NVIDIA\\ComputeCache, Linux ~/.nv/ComputeCache): one row per JIT-compiled module with "
                   "its PTX entry points, the compiled cubin's kernels and SM target, the build stamp and file times, "
                   "and flags miner/cracker kernels and entries removed from the index. Can extract the PTX and cubin.")
    METHOD = ("Reads the index (u32 version, u32 count, u64 total, count x {u64 key, u64 size}), resolves each key to "
              "<root>/h[0]/h[1]/h[2:16], parses the 28-byte entry header (version, text_len, cubin_len, hash), "
              "validates sizes, splits the build stamp + PTX text from the cubin, and parses both; files present but "
              "not indexed are reported too.")
    ANALOG = "windows.shimcachemem / windows.registry.amcache (execution evidence from caches)"
    SOURCES = ("file",)
    REQUIREMENTS = [Requirement("path", str, None, "cache directory (default: this machine's cache locations)"),
                    Requirement("dump", bool, False, "extract each entry's PTX and cubin into the output directory")]

    def _roots(self):
        if self.opts["path"]:
            if not os.path.isdir(self.opts["path"]):
                raise RequirementError("not a directory: %s" % self.opts["path"])
            return [self.opts["path"]]
        roots = computecache.default_roots()
        if not roots:
            raise RequirementError("no ComputeCache found; pass --path <collected cache directory>")
        return roots

    def _entries(self):
        for root in self._roots():
            for e in computecache.iter_cache(root):
                yield root, e

    def run(self):
        def rows():
            for root, e in self._entries():
                try:
                    st = os.stat(e.path)
                    mtime = _dt.datetime.fromtimestamp(st.st_mtime, tz=_dt.timezone.utc)
                except OSError:
                    mtime = na("missing")
                mod = ptx_fmt.parse(e.ptx) if e.ptx else None
                kernels, arch = [], na("no cubin")
                if e.cubin[:4] == b"\x7fELF":
                    try:
                        c = cubin_fmt.parse_cubin(e.cubin)
                        kernels, arch = c.kernel_names(), c.arch
                    except Exception as exc:
                        arch = na("cubin parse error: %s" % exc)
                names = sorted(set(kernels) | set(mod.entries if mod else []))
                flags = sorted({"%s:%s" % (c, i) for n in names for c, i in miners.classify(n)})
                if e.error:
                    flags.append(e.error)
                files = na("")
                if self.opts["dump"] and (e.ptx or e.cubin):
                    stem = "jitcache_%s" % ("%016x" % e.key_hash if e.key_hash is not None else
                                            hashlib.sha256(e.path.encode()).hexdigest()[:16])
                    out = []
                    for ext, blob in (("ptx", e.ptx), ("cubin", e.cubin)):
                        if blob:
                            p = self.ctx.output_path("%s.%s" % (stem, ext))
                            with open(p, "wb") as fh:
                                fh.write(blob)
                            out.append(p)
                    files = "; ".join(out)
                internal = names and driver_kernels.all_driver_internal(names)
                yield 0, (os.path.relpath(e.path, root), Hex(e.key_hash) if e.key_hash is not None else na("unindexed"),
                          mtime, (mod.target if mod else None) or na(""), arch, ", ".join(names[:8]) or "-",
                          "NVIDIA internal" if internal else "application", e.stamp or "-", len(e.text), len(e.cubin),
                          "; ".join(flags), files)
        return TreeGrid([("Entry", str), ("Key", Hex), ("Modified", object), ("PTX target", str), ("SASS", str),
                         ("Kernels", str), ("Origin", str), ("Build stamp", str), ("PTX bytes", int),
                         ("Cubin bytes", int), ("Flags", str), ("Extracted", str)], rows())

    def generate_timeline(self):
        for _root, e in self._entries():
            try:
                t = _dt.datetime.fromtimestamp(os.stat(e.path).st_mtime, tz=_dt.timezone.utc)
            except OSError:
                continue
            names = ptx_fmt.parse(e.ptx).entries if e.ptx else []
            yield ("CUDA JIT compiled module %s (%s)" % (", ".join(names[:3]) or "?", os.path.basename(e.path)),
                   "Modified", t)
