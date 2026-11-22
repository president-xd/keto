"""Host-side GPU artefacts: GPU code, command streams and launch descriptors in
host RAM images, process dumps and live process memory."""

from __future__ import annotations

from keto.framework.exceptions import RequirementError, UnsupportedError
from keto.framework.layers import BytesLayer
from keto.framework.plugin import Plugin, Requirement
from keto.framework.treegrid import Address, TreeGrid, na
from keto.framework.util import parse_size
from keto.formats import fatbin
from keto.gpu import artifacts, sass
from typing import Dict, Optional

from keto.indicators import driver_kernels, miners
from keto.live import procfs
from keto.plugins.nvidia.live_procs import HOME_PREFIXES, WIN_TEMP_RE, is_temp_path, win_gpu_procs, win_name
from keto.plugins.windows import gpu as wgpu

KINDS_REQ = Requirement("kinds", str, ",".join(artifacts.KINDS), "comma-separated artefact kinds to look for")


def _kinds(opts):
    kinds = [k.strip() for k in (opts["kinds"] or "").split(",") if k.strip()]
    bad = [k for k in kinds if k not in artifacts.KINDS]
    if bad:
        raise RequirementError("unknown kinds %s (valid: %s)" % (bad, ", ".join(artifacts.KINDS)))
    return kinds


def _names(a):
    return a.detail.get("kernels") or a.detail.get("entries") or []


BASELINE_REQS = [Requirement("baseline", str, None, "kernel baseline JSON from a known-clean process (hash allow-list)"),
                 Requirement("write_baseline", str, None, "write every kernel hash found here as a baseline JSON")]


def trusted_library(path: str) -> bool:
    """An NVIDIA driver library mapped from a system location: not temporary, deleted, fileless or
    user-writable (a copy of nvcuda.dll in %TEMP% or libcuda in /home proves nothing)."""
    if not driver_kernels.is_nvidia_library(path or ""):
        return False
    if "\\" in path:
        return not (wgpu.USER_WRITABLE.search(path) or WIN_TEMP_RE.search(path))
    return not (is_temp_path(path) or path.startswith(HOME_PREFIXES))


def library_hashes(found, read=None) -> Dict[str, str]:
    """``kernel hash -> library basename`` for artefacts found inside trusted NVIDIA library mappings;
    ``found`` is ``[(artefact, backing path)]`` of one capture. With ``read(artefact) -> bytes``, the SASS functions
    inside those libraries' cubins (raw images and decompressed fatbin entries) are added by skeleton hash, so raw
    SASS the driver copies out of its libraries into anonymous memory is attributed too."""
    out = {}
    for a, path in found:
        if not trusted_library(path):
            continue
        lib = wgpu.basename(path)
        for h in a.detail.get("hashes") or []:
            out.setdefault(h, lib)
        if read is None or a.kind not in ("cubin", "fatbin"):
            continue
        blob = read(a)
        if not blob:
            continue
        if a.kind == "fatbin":
            f = fatbin.parse_fatbin(blob)
            images = [e.data for e in (f.entries if f else []) if e.kind == fatbin.KIND_ELF and e.data]
        else:
            images = [blob]
        for img in images:
            for h in sass.function_skeletons(img):
                out.setdefault(h, lib)
    return out


#: the CUDA driver's kernel archive, read (not mapped) at cuInit from the directory of its libraries: Windows
#: DriverStore nvhm.inf_*\nvcubins.bin, mounted under /usr/lib/wsl/drivers/ on WSL2
DRIVER_ARCHIVES = ("nvcubins.bin",)
MAX_ARCHIVE = 512 << 20


def cubin_images(blob: bytes):
    """Every cubin in ``blob``: raw ELF images and decompressed ELF entries of fat binaries."""
    from keto.formats import elf
    pos = blob.find(b"\x7fELF")
    while pos != -1:
        try:
            ext = elf.elf_extent(blob[pos:pos + (64 << 20)])
        except Exception:  # malformed ELF header: skip it
            ext = None
        if ext:
            yield blob[pos:pos + ext]
        pos = blob.find(b"\x7fELF", pos + 4)
    pos = blob.find(fatbin.FATBIN_MAGIC_BYTES)
    while pos != -1:
        f = fatbin.parse_fatbin(blob[pos:pos + (256 << 20)])
        for e in (f.entries if f else []):
            if e.kind == fatbin.KIND_ELF and e.data:
                yield e.data
        pos = blob.find(fatbin.FATBIN_MAGIC_BYTES, pos + 4)


def archive_hashes(ctx, src, lib_paths) -> Dict[str, str]:
    """SASS skeleton hash -> archive name for the CUDA driver's kernel archive(s) next to the trusted NVIDIA
    libraries in ``lib_paths``. The driver reads these kernels into anonymous memory at cuInit, so no mapping
    vouches for them. Cached per directory for the run."""
    out = {}
    cache = ctx.cache.setdefault("driver_archives", {})
    for d in sorted({p.rsplit("\\" if "\\" in p else "/", 1)[0] for p in lib_paths if trusted_library(p)}):
        sep = "\\" if "\\" in d else "/"
        for name in DRIVER_ARCHIVES:
            path = d + sep + name
            if path not in cache:
                blob = src.read_bytes(path, MAX_ARCHIVE)
                hashes = {}
                for img in cubin_images(blob or b""):
                    for h in sass.function_skeletons(img):
                        hashes.setdefault(h, name)
                cache[path] = hashes
            out.update(cache[path])
    return out


def provenance(a, baseline: Optional[driver_kernels.Baseline], libs: Optional[Dict[str, str]] = None) -> str:
    """Baseline hash first, then the same code inside an NVIDIA driver library of the same capture, then the
    driver-internal kernel name allow-list."""
    hashes = a.detail.get("hashes") or []
    if baseline is not None and baseline.covers(hashes):
        return "known-good (baseline hash)"
    if libs and hashes and all(h in libs for h in hashes):
        return "NVIDIA driver library code (same code in %s)" % ", ".join(sorted({libs[h] for h in hashes}))
    names = _names(a)
    if names and driver_kernels.all_driver_internal(names):
        return "NVIDIA driver-internal (name match only)"
    return "unknown"


def assess(a, backing: str, perms: str = "", prov: str = "unknown"):
    """Why an artefact found in host memory deserves attention (empty when it looks routine)."""
    reasons = []
    anon = backing in ("", "[heap]", "[anon]") or backing.startswith(("[anon", "/memfd:", "memfd:")) or \
        backing.endswith("(deleted)")
    has_code = a.kind == "sass" or bool(_names(a))  # a bare ELF header without kernels is not a payload
    if a.kind in ("cubin", "fatbin", "ptx", "sass", "opencl", "spirv") and anon and prov == "unknown" and has_code:
        reasons.append("GPU code of unknown provenance in anonymous/fileless memory (generated, downloaded or "
                       "decrypted at run time)")
    if a.kind == "dxbc" and anon and prov == "unknown" and a.detail.get("program_type") == "compute":
        reasons.append("Direct3D compute shader of unknown provenance in anonymous memory")
    if a.detail.get("decryptor"):
        reasons.append("GPU decryptor indicator: XOR with a modulo-indexed key (out[i] = in[i] ^ key[i % n], the "
                       "CoffeeLoader/ArmouryLoader OpenCL stage)")
    if "w" in perms and "x" in perms and a.kind in ("cubin", "fatbin", "sass"):
        reasons.append("GPU code in writable+executable memory")
    for name in _names(a):
        for cat, ind in miners.classify(name, context="kernel"):
            if cat != "hash-primitive":  # generic primitives (argon2, blake3...) are a weak hint, not an indicator
                reasons.append("%s indicator in kernel name %s (%s)" % (cat, name, ind))
    return "; ".join(sorted(set(reasons)))


def severity(a, why: str) -> str:
    """high: abuse indicator or W+X code; medium: unknown GPU module in anonymous memory;
    low: unattributed raw SASS (typically driver code not seen as a module); info: routine."""
    if not why:
        return "info"
    if "indicator" in why or "writable+executable" in why:
        return "high"
    return "low" if a.kind in ("sass", "dxbc") else "medium"


class _BaselineMixin:
    def _baseline(self):
        path = self.opts.get("baseline")
        return driver_kernels.Baseline.load(path) if path else None

    def _collect(self, a, sink):
        if self.opts.get("write_baseline"):
            sink.update(a.detail.get("kernel_hashes") or {})

    def _flush(self, sink):
        path = self.opts.get("write_baseline")
        if path:
            from keto import __version__
            driver_kernels.Baseline(sink, {"tool": "Keto %s" % __version__,
                                           "device": self.ctx.metadata.get("device"),
                                           "note": "hashes of kernels observed in a process believed clean"}).save(path)


class ArtifactScan(_BaselineMixin, Plugin):
    NAME = "nvidia.artifactscan"
    CATEGORY = "nvidia.code"
    DESCRIPTION = ("Sweeps any memory image (VRAM, host RAM, a process dump) in one pass for every kind of GPU "
                   "artefact: fat binaries, fatbin descriptors, cubins, PTX, pushbuffers, launch descriptors (QMDs) "
                   "and raw SASS functions.")
    METHOD = ("Runs the fatbin (0xBA55ED50), __nv_fatbinwrap (0x466243B1), EM_CUDA ELF, PTX '.version', "
              "SET_OBJECT-anchored pushbuffer, QMD-version-signature and SASS-epilogue scanners over the primary "
              "layer and any --host-image, decoding each hit with the same parsers as the dedicated plugins. Raw "
              "zstd frames (GPU code NVIDIA drivers ship compressed) are decoded too and their cubins reported as "
              "kind cubin when a zstd back-end is installed (at most 16 MiB compressed and 64 MiB output per frame, "
              "1 GiB per layer). A hit that fails to parse is reported as an '(undecodable: ...)' artefact with "
              "severity info instead of stopping the sweep. In "
              "process dumps each hit is attributed to its mapping; provenance is a --baseline hash match, else "
              "the same kernel code inside an NVIDIA driver library mapped from a system location in the same "
              "capture (cubin hashes, and SASS skeleton hashes of every function in the library's cubins, so raw "
              "SASS the driver copies out of its libraries is attributed too), else the driver-internal "
              "kernel-name allow-list.")
    ANALOG = "windows.poolscanner (one generic pass for many object types)"
    REQUIREMENTS = [KINDS_REQ, Requirement("suspicious_only", bool, False, "only rows with an Attention reason")] \
        + BASELINE_REQS

    def run(self):
        kinds = _kinds(self.opts)
        baseline = self._baseline()
        layers = [self.ctx.primary] + ([self.ctx.layers["sysmem"]] if "sysmem" in self.ctx.layers and
                                       self.ctx.layers["sysmem"] is not self.ctx.primary else [])
        meta_maps = (self.ctx.metadata.get("process") or {}).get("mappings", [])

        def backing(off):
            for m in meta_maps:
                if m["start"] <= off < m["end"]:
                    return m.get("path") or "[anon]", m.get("perms", "")
            return "-", ""

        def rows():
            sink = {}
            for layer in layers:
                # two passes: code found inside an NVIDIA driver library mapping vouches for the same code in
                # anonymous memory of the same capture (driver modules the runtime loads or builds)
                found = [(a, backing(a.offset) if meta_maps else ("-", ""))
                         for a in artifacts.sweep(layer, self.ctx.classdb, kinds, self.ctx.profile.qmd)]
                libs = library_hashes(((a, b[0]) for a, b in found),
                                      read=lambda a, layer=layer: layer.read(a.offset, a.size, pad=True)) \
                    if meta_maps else {}
                for a, (path, perms) in found:
                    self._collect(a, sink)
                    prov = provenance(a, baseline, libs)
                    why = assess(a, path, perms, prov) if meta_maps else assess(a, "-", "", prov)
                    if self.opts["suspicious_only"] and not why:
                        continue
                    names = ", ".join(_names(a)[:6])
                    yield 0, (a.layer, Address(a.offset), a.kind, a.size, a.summary, names or "-", path, prov,
                              severity(a, why), why)
            self._flush(sink)
        return TreeGrid([("Layer", str), ("Offset", Address), ("Kind", str), ("Size", int), ("Summary", str),
                         ("Kernels", str), ("Backing", str), ("Provenance", str), ("Severity", str),
                         ("Attention", str)], rows())


class ProcScan(_BaselineMixin, Plugin):
    NAME = "nvidia.procscan"
    CATEGORY = "nvidia.processes"
    DESCRIPTION = ("Scans the memory of running GPU processes for GPU payloads and activity: fat binaries, cubins, "
                   "PTX, raw SASS, pushbuffers and launch descriptors - and flags GPU code held in anonymous or "
                   "fileless memory (runtime-decrypted payloads, the usual way GPU malware hides from EDR file scans).")
    METHOD = ("For every process with GPU evidence (or --pid), reads each readable mapping from /proc/<pid>/mem "
              "in overlapping windows and runs the nvidia.artifactscan sweep; each hit is attributed to its "
              "mapping (file-backed vs anonymous, permissions). Needs root (CAP_SYS_PTRACE) for other users' "
              "processes when ptrace_scope >= 1. On Windows the regions are the committed, accessible ones from "
              "VirtualQueryEx (backing file from GetMappedFileNameW) read with ReadProcessMemory, as in acquire "
              "--method process (other users' processes need Administrator). Provenance as in "
              "nvidia.artifactscan (baseline, same code in an NVIDIA driver library of the same process, name "
              "allow-list), plus the CUDA driver's kernel archive next to its libraries (nvcubins.bin, read into "
              "anonymous memory at cuInit, never mapped). Raw SASS that no NVIDIA file on disk contains (driver "
              "code compiled at run time, or a payload) stays 'unknown' at low severity. Needs a live system: "
              "snapshots do not record process memory.")
    ANALOG = "windows.vadyarascan / windows.malware.malfind (process memory sweep)"
    SOURCES = ("live",)
    SNAPSHOT = False  # reads large amounts of process memory; run it explicitly
    REQUIREMENTS = [Requirement("pid", int, None, "only this PID"), KINDS_REQ,
                    Requirement("max_bytes", "size", 1 << 30, "maximum bytes read per process (default 1G)"),
                    Requirement("suspicious_only", bool, False, "only rows with an Attention reason")] + BASELINE_REQS
    WINDOW, OVERLAP = 32 << 20, 1 << 20

    def _targets(self, src):
        """``pid -> (name, mappings or None)``: Linux /proc maps, or Windows VirtualQueryEx regions."""
        pid = self.opts["pid"]
        if src.is_windows:
            if pid is not None:
                procs = {p["pid"]: p for p in src.win_processes() if p["pid"] == pid}
            else:
                procs = {k: v["proc"] for k, v in win_gpu_procs(self.ctx).items() if v["proc"] is not None}
            return {k: (win_name(p), src.win_regions(k)) for k, p in procs.items()}
        if pid is not None:
            p = src.proc(pid)
            targets = {pid: {"proc": p}} if p else {}
        else:
            targets = procfs.gpu_processes(src)
        return {k: (procfs.proc_name(v["proc"]), v["proc"].get("maps", [])) for k, v in targets.items()
                if v["proc"] is not None}

    def run(self):
        src = self.ctx.live
        if src.kind == "snapshot":
            raise UnsupportedError("nvidia.procscan reads live process memory, which snapshots do not record: run "
                                   "it with --live on the system itself, or capture with acquire --method process "
                                   "and run nvidia.artifactscan on the container")
        if not (src.is_linux or src.is_windows):
            raise UnsupportedError("nvidia.procscan needs Linux /proc/<pid>/mem or Windows ReadProcessMemory (use "
                                   "acquire --method process, then nvidia.artifactscan on the capture)")
        kinds = _kinds(self.opts)
        baseline = self._baseline()
        targets = self._targets(src)
        self_pid = (src.platform() or {}).get("self_pid")
        max_bytes = self.opts["max_bytes"] if isinstance(self.opts["max_bytes"], int) else parse_size(self.opts["max_bytes"])
        advice = "run as Administrator" if src.is_windows else "run as root / CAP_SYS_PTRACE"

        def scan(pid, maps):
            """``([(artefact, mapping)], unreadable mappings)`` of one process."""
            budget, unreadable, seen, found = max_bytes, 0, set(), []
            for m in maps:
                if "r" not in m["perms"] or m["path"] in ("[vvar]", "[vsyscall]", "[vvar_vclock]"):
                    continue
                pos = m["start"]
                while pos < m["end"] and budget > 0:
                    n = min(self.WINDOW + self.OVERLAP, m["end"] - pos, budget)
                    data = src.proc_mem(pid, pos, n)
                    if not data:
                        unreadable += 1
                        break
                    layer = BytesLayer("pid%d" % pid, data, base=pos)
                    for a in artifacts.sweep(layer, self.ctx.classdb, kinds, self.ctx.profile.qmd):
                        if a.offset not in seen:
                            seen.add(a.offset)
                            found.append((a, m))
                    step = min(self.WINDOW, n)
                    pos += step
                    budget -= step
            return found, unreadable

        def rows():
            sink = {}
            for pid, (name, maps) in sorted(targets.items()):
                if pid == self_pid:
                    continue
                if maps is None:
                    yield 0, (pid, name, Address(0), "unreadable", 0, "process cannot be opened: %s" % advice,
                              "-", "-", "-", "-", "info", na(""))
                    continue
                found, unreadable = scan(pid, maps)
                libs = library_hashes(((a, m["path"]) for a, m in found),
                                      read=lambda a, pid=pid: src.proc_mem(pid, a.offset, a.size))
                for h, lib in archive_hashes(self.ctx, src, [m["path"] for m in maps if m.get("path")]).items():
                    libs.setdefault(h, lib)
                for a, m in found:
                    self._collect(a, sink)
                    path = m["path"] or "[anon]"
                    prov = provenance(a, baseline, libs)
                    why = assess(a, path, m["perms"], prov)
                    if self.opts["suspicious_only"] and not why:
                        continue
                    yield 0, (pid, name, Address(a.offset), a.kind, a.size, a.summary,
                              ", ".join(_names(a)[:6]) or "-", path, m["perms"], prov, severity(a, why), why)
                if unreadable and not found:
                    yield 0, (pid, name, Address(0), "unreadable", 0,
                              "%d mapping(s) unreadable: %s" % (unreadable, advice), "-", "-", "-",
                              "-", "info", na(""))
            self._flush(sink)
        return TreeGrid([("PID", int), ("Name", str), ("VA", Address), ("Kind", str), ("Size", int),
                         ("Summary", str), ("Kernels", str), ("Mapping", str), ("Perms", str), ("Provenance", str),
                         ("Severity", str), ("Attention", str)], rows())
