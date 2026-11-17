"""Host-side GPU artefacts: GPU code, command streams and launch descriptors in
host RAM images, process dumps and live process memory."""

from __future__ import annotations

from keto.framework.exceptions import RequirementError, UnsupportedError
from keto.framework.layers import BytesLayer
from keto.framework.plugin import Plugin, Requirement
from keto.framework.treegrid import Address, TreeGrid, na
from keto.framework.util import parse_size
from keto.gpu import artifacts
from typing import Optional

from keto.indicators import driver_kernels, miners
from keto.live import procfs

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


def provenance(a, baseline: Optional[driver_kernels.Baseline]) -> str:
    hashes = a.detail.get("hashes") or []
    if baseline is not None and baseline.covers(hashes):
        return "known-good (baseline hash)"
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
        for cat, ind in miners.classify(name):
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
              "layer and any --host-image, decoding each hit with the same parsers as the dedicated plugins.")
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
                for a in artifacts.sweep(layer, self.ctx.classdb, kinds, self.ctx.profile.qmd):
                    self._collect(a, sink)
                    path, perms = backing(a.offset) if meta_maps else ("-", "")
                    prov = provenance(a, baseline)
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
              "processes when ptrace_scope >= 1.")
    ANALOG = "windows.vadyarascan / windows.malware.malfind (process memory sweep)"
    SOURCES = ("live",)
    SNAPSHOT = False  # reads large amounts of process memory; run it explicitly
    REQUIREMENTS = [Requirement("pid", int, None, "only this PID"), KINDS_REQ,
                    Requirement("max_bytes", "size", 1 << 30, "maximum bytes read per process (default 1G)"),
                    Requirement("suspicious_only", bool, False, "only rows with an Attention reason")] + BASELINE_REQS
    WINDOW, OVERLAP = 32 << 20, 1 << 20

    def run(self):
        src = self.ctx.live
        if not src.is_linux:
            raise UnsupportedError("nvidia.procscan needs Linux /proc/<pid>/mem (use acquire --method process on Linux, then nvidia.artifactscan on the capture)")
        kinds = _kinds(self.opts)
        baseline = self._baseline()
        if self.opts["pid"] is not None:
            p = src.proc(self.opts["pid"])
            targets = {self.opts["pid"]: {"proc": p, "evidence": {"--pid"}}} if p else {}
        else:
            targets = procfs.gpu_processes(src)
        self_pid = (src.platform() or {}).get("self_pid")
        max_bytes = self.opts["max_bytes"] if isinstance(self.opts["max_bytes"], int) else parse_size(self.opts["max_bytes"])

        def rows():
            sink = {}
            for pid, info in sorted(targets.items()):
                p = info["proc"]
                if p is None or pid == self_pid:
                    continue
                budget, unreadable, seen = max_bytes, 0, set()
                for m in p.get("maps", []):
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
                            if a.offset in seen:
                                continue
                            seen.add(a.offset)
                            self._collect(a, sink)
                            path = m["path"] or "[anon]"
                            prov = provenance(a, baseline)
                            why = assess(a, path, m["perms"], prov)
                            if self.opts["suspicious_only"] and not why:
                                continue
                            yield 0, (pid, procfs.proc_name(p), Address(a.offset), a.kind, a.size, a.summary,
                                      ", ".join(_names(a)[:6]) or "-", path, m["perms"], prov, severity(a, why), why)
                        step = min(self.WINDOW, n)
                        pos += step
                        budget -= step
                if unreadable and not seen:
                    yield 0, (pid, procfs.proc_name(p), Address(0), "unreadable", 0,
                              "%d mapping(s) unreadable: run as root / CAP_SYS_PTRACE" % unreadable, "-", "-", "-",
                              "-", "info", na(""))
            self._flush(sink)
        return TreeGrid([("PID", int), ("Name", str), ("VA", Address), ("Kind", str), ("Size", int),
                         ("Summary", str), ("Kernels", str), ("Mapping", str), ("Perms", str), ("Provenance", str),
                         ("Severity", str), ("Attention", str)], rows())
