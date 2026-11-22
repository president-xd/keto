"""Shader caches as evidence of which programs used the GPU (D3D, NVIDIA DX/GL caches, Mesa)."""

from __future__ import annotations

import datetime as _dt
import os
import re

from keto.formats import shadercache
from keto.framework.exceptions import RequirementError
from keto.framework.plugin import Plugin, Requirement, TimeLinerInterface
from keto.framework.treegrid import TreeGrid, na
from keto.indicators import miners

# user-writable program locations (same notion as windows.gpuprocs: anything under the user profile's AppData,
# temporary folders, Downloads/Desktop, Public, ProgramData; /tmp, /dev/shm, home directories on Linux)
USER_WRITABLE = re.compile(r"\\(?:appdata\\(?:local|locallow|roaming)|windows\\temp|temp|tmp|downloads|users\\public"
                           r"|programdata|desktop)\\|^/tmp/|^/var/tmp/|^/dev/shm/|^/home/|/Downloads/", re.I)
KINDS = {"d3d": "D3D shader cache", "nvdx": "NVIDIA DXCache", "nvgl": "NVIDIA GLCache", "mesa": "Mesa shader cache"}


def _utc(t):
    if not t:
        return na("")
    try:
        return _dt.datetime.fromtimestamp(float(t), tz=_dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return na("bad time")


class ShaderCache(Plugin, TimeLinerInterface):
    NAME = "nvidia.shadercache"
    CATEGORY = "nvidia.code"
    DESCRIPTION = ("Reads graphics/compute shader caches (Microsoft D3DSCache, NVIDIA DXCache and GLCache, Mesa) as "
                   "execution evidence: which programs compiled GPU shaders, on which adapter, how many (and how many "
                   "compute shaders), first and last use, and flags programs that ran from user-writable locations, no "
                   "longer exist on disk, or carry miner indicators.")
    METHOD = ("D3DSCache: each <app>/<GUID>[_VEN_xxxx&DEV_xxxx].dxcache is an SQLite database, opened from a private "
              "copy (with its WAL): app_id.exe_path, keys.last_accessed (Unix time), vals.value blobs parsed as DXBC/"
              "DXIL containers (program type from the SHEX/DXIL version token). NVIDIA DXCache (nvph) and GLCache "
              "(CDVN) files: times, embedded program names (UTF-8/UTF-16 *.exe strings), DXBC/SPIR-V containers.")
    ANALOG = "windows.registry.amcache / windows.shimcachemem (execution evidence from caches)"
    SOURCES = ("file",)
    LOCAL_DEFAULTS = True  # without --path it reads this machine's caches (timeliner only uses it with --live)
    REQUIREMENTS = [Requirement("path", str, None, "a collected cache directory (default: this machine's caches)"),
                    Requirement("kind", str, None, "with --path: d3d, nvdx, nvgl or mesa (default: guess)"),
                    Requirement("files", bool, False, "one row per cache file instead of per program")]

    def _roots(self):
        if self.opts["path"]:
            p = self.opts["path"]
            if not os.path.isdir(p):
                raise RequirementError("not a directory: %s" % p)
            kind = self.opts["kind"] or shadercache.guess_kind(p)
            if kind is None:
                raise RequirementError("cannot tell what kind of shader cache %s is: give --kind (%s)"
                                       % (p, ", ".join(KINDS)))
            if kind not in KINDS:
                raise RequirementError("--kind must be one of %s" % ", ".join(KINDS))
            return [(kind, p)]
        roots = shadercache.default_roots()
        if not roots:
            raise RequirementError("no shader cache found; pass --path <collected cache directory>")
        return roots

    def _entries(self):
        for kind, root in self._roots():
            for e in shadercache.iter_cache(kind, root):
                yield kind, root, e

    def _flags(self, app):
        flags = []
        if not app:
            return flags
        if USER_WRITABLE.search(app):
            flags.append("program in a user-writable location")
        # existence can only be checked on the machine the cache came from: this one, when no --path was given
        if not self.opts["path"] and re.match(r"^[A-Za-z]:\\", app) and os.name == "nt" and not os.path.exists(app):
            flags.append("program no longer on disk")
        for cat, ind in miners.classify(os.path.basename(app), context="process"):
            flags.append("%s indicator (%s)" % (cat, ind))
        return flags

    @staticmethod
    def _group(kind, root, e):
        """Program name(s) an entry belongs to. Caches that record no program name (NVIDIA DXCache/GLCache from
        recent drivers) are grouped per cache directory, so different programs' caches stay apart."""
        if e.app:
            return [e.app]
        if e.names:
            return e.names
        rel = os.path.relpath(e.path, root)
        top = rel.split(os.sep)[0] if os.sep in rel else os.path.splitext(rel)[0].split("_")[0]
        return ["(no program name recorded: %s %s)" % (KINDS[kind], top)]

    def run(self):
        if self.opts["files"]:
            return self._per_file()
        progs = {}
        unreadable = []
        for kind, root, e in self._entries():
            if e.error and not e.entries:
                unreadable.append(e)
                continue
            for app in self._group(kind, root, e):
                key = app.lower()
                p = progs.setdefault(key, {"app": app, "kinds": set(), "adapters": set(),
                                           "files": 0, "entries": 0, "shaders": 0, "compute": 0, "first": None,
                                           "last": None, "named": not app.startswith("(no program")})
                p["kinds"].add(KINDS[kind])
                if e.adapter:
                    p["adapters"].add(e.adapter)
                p["files"] += 1
                p["entries"] += e.entries or 0
                p["shaders"] += e.shaders
                p["compute"] += e.compute_shaders
                for t, k, f in ((e.first, "first", min), (e.last, "last", max)):
                    if t:
                        p[k] = t if p[k] is None else f(p[k], t)

        def rows():
            for p in sorted(progs.values(), key=lambda x: -(x["last"] or 0)):
                flags = self._flags(p["app"] if p["named"] else None)
                if p["compute"]:
                    flags.append("%d compute shader(s) cached" % p["compute"])
                # NVIDIA's own cache formats hold driver-compiled machine code, not DXBC/SPIR-V containers: a zero
                # count there means "not countable", not "no shaders"
                countable = p["shaders"] or p["kinds"] & {KINDS["d3d"]}
                shaders = p["shaders"] if countable else na("not countable in this cache format")
                compute = p["compute"] if countable else na("not countable in this cache format")
                yield 0, (p["app"], ", ".join(sorted(p["kinds"])), ", ".join(sorted(p["adapters"])) or na(""),
                          p["files"], p["entries"], shaders, compute, _utc(p["first"]), _utc(p["last"]),
                          "; ".join(flags) or na(""))
            if unreadable:
                yield 0, ("(%d unreadable cache file(s))" % len(unreadable),
                          ", ".join(sorted({KINDS[e.kind] for e in unreadable})), na(""), len(unreadable), 0,
                          na("unreadable"), na("unreadable"), na(""), na(""),
                          "not analysed (e.g. locked by a running program): %s" % unreadable[0].error)
        return TreeGrid([("Program", str), ("Cache", str), ("Adapter", str), ("Files", int), ("Entries", int),
                         ("Shaders", int), ("Compute", int), ("First", object), ("Last used", object),
                         ("Attention", str)], rows())

    def _per_file(self):
        def rows():
            for kind, root, e in self._entries():
                yield 0, (KINDS[kind], os.path.relpath(e.path, root), e.app or ", ".join(e.names[:3]) or na(""),
                          e.adapter or na(""), e.entries or 0, e.shaders, e.compute_shaders, _utc(e.last),
                          e.error or na(""))
        return TreeGrid([("Cache", str), ("File", str), ("Program", str), ("Adapter", str), ("Entries", int),
                         ("Shaders", int), ("Compute", int), ("Last used", object), ("Error", str)], rows())

    def generate_timeline(self):
        for kind, _root, e in self._entries():
            if e.last:
                yield ("%s: %s compiled/used GPU shaders (%d)" % (KINDS[kind], e.app or ", ".join(e.names[:2]) or
                                                                  os.path.basename(e.path), e.shaders),
                       "Last used", _utc(e.last))
