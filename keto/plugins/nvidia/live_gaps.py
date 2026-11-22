"""Live detectors for GPU abuse that bypasses process accounting, the NVIDIA driver, or the GPU watchdog."""

from __future__ import annotations

import re

from keto.framework.exceptions import UnsupportedError
from keto.framework.plugin import Plugin, Requirement
from keto.framework.treegrid import TreeGrid, na
from keto.framework.util import human_size

GRAPHICS_DRIVERS_KEY = r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers"


def _bus_key(bus_id):
    """``bus:device.function`` of a PCI bus id in NVML (00000000:01:00.0) or CUDA (0000:01:00.0) form."""
    return ":".join(str(bus_id).lower().split(":")[-2:]) if bus_id else None


def nvml_index_by_luid(src, nv) -> dict:
    """Windows adapter LUID (normalised) -> NVML device index: through the CUDA device's LUID and PCI bus id,
    else through the adapter name when exactly one NVML device has it."""
    from keto.live.windows import normalise_luid
    devices = [d for d in nv.get("devices", []) if isinstance(d, dict)]
    by_bus = {_bus_key((d.get("pci") or {}).get("bus_id")): d.get("index") for d in devices
              if isinstance(d.get("pci"), dict)}
    out = {}
    cuda = src.cuda() or {}
    for c in cuda.get("devices", []) if cuda.get("available") else []:
        if c.get("luid") and _bus_key(c.get("pci_bus_id")) in by_bus:
            out[normalise_luid(c["luid"])] = by_bus[_bus_key(c.get("pci_bus_id"))]
    for a in src.win_adapters() or []:
        same = [d.get("index") for d in devices if d.get("name") == a.get("name")]
        if len(same) == 1:
            out.setdefault(normalise_luid(a["luid"]), same[0])
    return out
# Microsoft "Timeout Detection and Recovery (TDR) registry keys"
TDR_LEVELS = {0: "TdrLevelOff (detection disabled)", 1: "TdrLevelBugcheck", 2: "TdrLevelRecoverVGA",
              3: "TdrLevelRecover (default)"}
TDR_DEBUG = {0: "break into the kernel debugger before recovery", 1: "IGNORE ANY TIMEOUT",
             2: "recover without the debugger (default)", 3: "recover unconditionally"}


class Unaccounted(Plugin):
    NAME = "nvidia.malware.unaccounted"
    CATEGORY = "nvidia.malware"
    DESCRIPTION = ("Compares each GPU's used memory and utilisation with what the per-process lists account for: "
                   "memory or activity no listed process owns points at process-less execution, hidden or "
                   "dashboard-evading workloads (e.g. ShadowRay 2.0 used 23.9 GB while dashboards showed 0%).")
    METHOD = ("NVML nvmlDeviceGetMemoryInfo.used and nvmlDeviceGetUtilizationRates.gpu against the sum of "
              "usedGpuMemory over the compute, graphics and MPS process lists. On Windows (WDDM, where NVML has no "
              "per-process memory) the PDH counters are used instead: 'GPU Adapter Memory(*) / Dedicated Usage' "
              "per adapter LUID against the sum of 'GPU Process Memory(*) / Dedicated Usage' on that LUID; the GPU "
              "number is the NVML index of that adapter (CUDA device LUID and PCI bus id). Under WSL2 NVML counts "
              "the Windows host's memory and activity but lists only the VM's processes, so no cross-view is made "
              "there.")
    ANALOG = "windows.malware.psxview (accounting cross-view)"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("threshold", "size", 1 << 30, "unaccounted memory that is flagged (default 1G)"),
                    Requirement("util_threshold", int, 20, "GPU utilisation % flagged when no process is listed")]

    def run(self):
        src = self.ctx.live
        nv = src.nvml()
        if (src.platform() or {}).get("system") == "Windows":
            g = src.win_gpu()
            if g.get("available") and g.get("adapters"):
                return self._windows(src, g, nv)

        def rows():
            for i, d in enumerate(nv.get("devices", [])):
                mem = d.get("memory") or {}
                used = mem.get("used") if isinstance(mem, dict) else None
                procs, total, unknown = {}, 0, 0
                for key in ("compute_processes", "graphics_processes", "mps_compute_processes"):
                    for p in d.get(key) or []:
                        if not isinstance(p, dict) or p.get("pid") in procs:
                            continue
                        procs[p.get("pid")] = p
                        if p.get("used_memory") is None:
                            unknown += 1
                        else:
                            total += p["used_memory"]
                util = (d.get("utilization") or {}).get("gpu") if isinstance(d.get("utilization"), dict) else None
                dm = d.get("driver_model")
                wddm = isinstance(dm, dict) and dm.get("current") in ("WDDM", "MCDM")
                findings = []
                unacc = None
                if src.is_wsl:
                    note = ("WSL2: NVML reports adapter-wide memory and utilisation (Windows host processes "
                            "included) but lists only this VM's processes, so no cross-view is possible here: run "
                            "nvidia.malware.unaccounted on the Windows host")
                elif used is not None and (wddm or (procs and unknown == len(procs))):
                    note = "driver does not report per-process memory (WDDM): memory cross-view not possible"
                else:
                    note = ""
                    if used is not None:
                        unacc = used - total
                        if unacc >= self.opts["threshold"]:
                            findings.append("%s of used GPU memory belongs to no listed process" % human_size(unacc))
                if not src.is_wsl and isinstance(util, int) and not procs and util >= self.opts["util_threshold"]:
                    findings.append("GPU %d%% busy with no process listed" % util)
                yield 0, (d.get("index", i), d.get("name") or na(""), human_size(used) if used is not None else na("?"),
                          human_size(total), len(procs), human_size(unacc) if unacc is not None else na(""),
                          util if isinstance(util, int) else na("?"), "; ".join(findings) or note or na(""))
        return TreeGrid([("GPU", int), ("Name", str), ("Used", str), ("ProcessesUse", str), ("Processes", int),
                         ("Unaccounted", str), ("Util%", int), ("Finding", str)], rows())

    def _windows(self, src, g, nv):
        """WDDM: NVML has no per-process memory, but the Windows GPU counters do. Per adapter (LUID), compare the
        adapter's dedicated usage with the sum of every process's dedicated usage on that adapter, and engine
        activity with the processes that show it."""
        from keto.live.windows import normalise_luid
        names = {a["luid"]: a for a in src.win_adapters() or []}
        index = nvml_index_by_luid(src, nv)
        util_by_index = {d.get("index"): (d.get("utilization") or {}).get("gpu") for d in nv.get("devices", [])
                         if isinstance(d.get("utilization"), dict)}
        per = {}
        for pid, p in (g.get("processes") or {}).items():
            for luid, m in (p.get("by_luid") or {}).items():
                e = per.setdefault(normalise_luid(luid), {"dedicated": 0, "shared": 0, "pids": set()})
                e["dedicated"] += m.get("dedicated") or 0
                e["shared"] += m.get("shared") or 0
                if (m.get("dedicated") or 0) or (m.get("shared") or 0):
                    e["pids"].add(pid)

        def rows():
            for luid, a in sorted((g.get("adapters") or {}).items()):
                key = normalise_luid(luid)
                info = names.get(key) or {}
                p = per.get(key, {"dedicated": 0, "shared": 0, "pids": set()})
                used = a.get("dedicated") or 0
                unacc = used - p["dedicated"]
                findings = []
                if unacc >= self.opts["threshold"]:
                    findings.append("%s of dedicated GPU memory belongs to no process (Windows GPU counters)"
                                    % human_size(unacc))
                util = util_by_index.get(index.get(key))
                if isinstance(util, int) and util >= self.opts["util_threshold"] and not p["pids"]:
                    findings.append("GPU %d%% busy with no process using it" % util)
                gpu = index[key] if key in index else na("not an NVML device (LUID %s)" % key)
                yield 0, (gpu, info.get("name") or key, human_size(used), human_size(p["dedicated"]), len(p["pids"]),
                          human_size(unacc) if unacc >= 0 else "0 B (processes report more than the adapter)",
                          util if isinstance(util, int) else na("?"),
                          "; ".join(findings) or na(""))
        return TreeGrid([("GPU", int), ("Name", str), ("Used", str), ("ProcessesUse", str), ("Processes", int),
                         ("Unaccounted", str), ("Util%", int), ("Finding", str)], rows())


_VFIO_RE = re.compile(r"^/dev/vfio/(?:vfio|\d+|devices/.*)$")
_BAR_RE = re.compile(r"^/sys/(?:bus/pci/devices|devices/pci[^ ]*)/.*/resource\d(?:_wc)?$")


class RawAccess(Plugin):
    NAME = "nvidia.malware.rawaccess"
    CATEGORY = "nvidia.malware"
    DESCRIPTION = ("Finds GPU use that bypasses the NVIDIA driver and therefore NVML, /dev/nvidia* and driver "
                   "telemetry: NVIDIA PCI functions bound to vfio-pci (user-space drivers such as tinygrad's NV-over-"
                   "VFIO, or VM pass-through) and processes holding VFIO handles or mapping PCI BARs directly.")
    METHOD = ("Reads /sys/bus/pci/devices/*/{vendor,class,driver,iommu_group}; flags vendor 0x10de functions not "
              "bound to nvidia/nvidia-drm/nouveau. Scans every process's fds for /dev/vfio/* and its maps for "
              "/sys/.../resourceN BAR mappings and /dev/mem.")
    ANALOG = "linux.lsof / linux.proc.Maps (raw device access)"
    SOURCES = ("live",)

    def run(self):
        src = self.ctx.live
        if src.is_windows:
            raise UnsupportedError(
                "nvidia.malware.rawaccess looks for VFIO and PCI BAR access from Linux user space, which has no "
                "Windows counterpart. On Windows, a GPU driven by something other than the NVIDIA driver shows as "
                "an NVIDIA PCI function with another service (nvidia.devicetree) or an extra kernel/filter driver "
                "(nvidia.modules); GPU use without the user-mode driver is nvidia.malware.rawioctl")
        if not src.is_linux:
            raise UnsupportedError("nvidia.malware.rawaccess reads Linux sysfs and /proc")

        def rows():
            base = "/sys/bus/pci/devices"
            for bdf in sorted(src.listdir(base) or []):
                vendor = (src.read_text("%s/%s/vendor" % (base, bdf)) or "").strip()
                if vendor.lower() != "0x10de":
                    continue
                cls = (src.read_text("%s/%s/class" % (base, bdf)) or "").strip()
                drv = (src.readlink("%s/%s/driver" % (base, bdf)) or "").rsplit("/", 1)[-1] or "none"
                group = (src.readlink("%s/%s/iommu_group" % (base, bdf)) or "").rsplit("/", 1)[-1] or "-"
                if drv in ("nvidia", "nvidia-drm", "nouveau", "snd_hda_intel", "xhci_hcd", "nvidia-gpu", "i2c-nvidia-gpu",
                           "ucsi_ccg"):
                    finding = ""
                elif drv == "vfio-pci":
                    finding = "bound to vfio-pci: driven from user space or passed to a VM (invisible to NVML)"
                elif drv == "none":
                    finding = "no driver bound" if cls.startswith("0x03") else ""
                else:
                    finding = "unexpected driver %s" % drv
                yield 0, ("pci", bdf, "class %s, driver %s, iommu group %s" % (cls, drv, group), finding or na(""))
            for pid in src.pids():
                p = src.proc(pid)
                if not p:
                    continue
                hits = [t for _fd, t in p.get("fds", []) if _VFIO_RE.match(t)]
                hits += sorted({m["path"] for m in p.get("maps", []) if _BAR_RE.match(m.get("path", ""))
                                or m.get("path") == "/dev/mem"})
                if hits:
                    vfio = any(h.startswith("/dev/vfio") for h in hits)
                    yield 0, ("process", "%d %s" % (pid, p.get("comm", "")), ", ".join(hits),
                              "VFIO handle: drives a device from user space" if vfio else
                              "maps PCI BAR/physical memory directly")
        return TreeGrid([("Kind", str), ("Object", str), ("Details", str), ("Finding", str)], rows())


class Watchdog(Plugin):
    NAME = "nvidia.malware.watchdog"
    CATEGORY = "nvidia.malware"
    DESCRIPTION = ("Checks whether the GPU watchdog was weakened so kernels can run without limit (persistent "
                   "GPU malware, long-running miners): Windows TDR registry settings and the Linux i915 hang-check, "
                   "plus NVIDIA RM registry overrides for review.")
    METHOD = ("Windows: HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers TdrLevel, TdrDelay, TdrDdiDelay, "
              "TdrDebugMode, TdrLimitTime, TdrLimitCount (Microsoft TDR registry keys). Linux: "
              "/sys/module/i915/parameters/enable_hangcheck and the RegistryDwords line of "
              "/proc/driver/nvidia/params. WSL2: TDR is enforced by the Windows host.")
    ANALOG = "windows.registry.printkey (security-relevant settings)"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("max_delay", int, 10, "TdrDelay/TdrDdiDelay seconds above which to flag")]

    def run(self):
        src = self.ctx.live
        plat = src.platform() or {}

        def rows():
            if plat.get("system") == "Windows":
                for name in ("TdrLevel", "TdrDelay", "TdrDdiDelay", "TdrDebugMode", "TdrLimitTime", "TdrLimitCount"):
                    v = src.registry(GRAPHICS_DRIVERS_KEY, name)
                    finding, meaning = "", "not set (default)"
                    if v is not None:
                        meaning = str(v)
                        if name == "TdrLevel":
                            meaning = TDR_LEVELS.get(v, str(v))
                            finding = "GPU timeout detection disabled: kernels can run indefinitely" if v == 0 else ""
                        elif name == "TdrDebugMode":
                            meaning = TDR_DEBUG.get(v, str(v))
                            finding = "GPU timeouts ignored" if v == 1 else ""
                        elif name in ("TdrDelay", "TdrDdiDelay") and isinstance(v, int):
                            meaning = "%d s" % v
                            finding = "long GPU timeout (%d s)" % v if v > self.opts["max_delay"] else ""
                    yield 0, ("registry", "HKLM\\%s\\%s" % (GRAPHICS_DRIVERS_KEY, name), meaning, finding or na(""))
                return
            if plat.get("wsl"):
                yield 0, ("note", "WSL2", "GPU timeouts are enforced by the Windows host's TDR; run this plugin "
                                          "on Windows", na(""))
            hc = src.read_text("/sys/module/i915/parameters/enable_hangcheck")
            if hc is not None:
                yield 0, ("param", "i915.enable_hangcheck", hc.strip(),
                          "Intel GPU hang check disabled" if hc.strip() in ("N", "0") else na(""))
            params = src.read_text("/proc/driver/nvidia/params") or ""
            for line in params.splitlines():
                if line.startswith("RegistryDwords"):
                    val = line.split(":", 1)[1].strip().strip('"')
                    yield 0, ("param", "nvidia RegistryDwords", val or "(empty)",
                              "RM registry overrides set: review (watchdog/timeout keys can be changed here)"
                              if val else na(""))
        return TreeGrid([("Kind", str), ("Setting", str), ("Value", str), ("Finding", str)], rows())


class Scraper(Plugin):
    NAME = "nvidia.malware.scraper"
    CATEGORY = "nvidia.malware"
    DESCRIPTION = ("Flags processes that hold most of a GPU's memory: the remanence-scraping pattern (allocate nearly "
                   "all free VRAM, often fill it with a marker, then read back what other tenants left behind) and "
                   "GPU memory squatting.")
    METHOD = ("Windows: per-process dedicated GPU memory from the GPU Process Memory counters against the adapter's "
              "DedicatedVideoMemory (DXGI). Linux/NVML: usedGpuMemory per process against the device total. A "
              "process at or above --fraction is reported; windowless (window inherited as in windows.gpuprocs) or "
              "user-writable-path processes rank higher. Under WSL2 (NVML has no per-process memory and lists only "
              "the VM's processes) and on Windows without GPU counters the check is refused, not reported empty.")
    ANALOG = "(GPU-specific: residual-data scraping, CUDA Leaks / GPU remanence research)"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("fraction", float, 0.6, "share of the GPU's memory held by one process that is flagged")]

    def run(self):
        src = self.ctx.live
        frac = self.opts["fraction"]
        rows = []
        if src.is_wsl:
            raise UnsupportedError("nvidia.malware.scraper cannot evaluate WSL2: NVML reports no per-process GPU "
                                   "memory there (WDDM) and lists only this VM's processes, not the Windows host's. "
                                   "Run it on the Windows host, where the Windows GPU counters give per-process "
                                   "dedicated memory")
        if (src.platform() or {}).get("system") == "Windows":
            from keto.live.windows import normalise_luid
            from keto.plugins.windows.gpu import USER_WRITABLE, has_window
            gpu = src.win_gpu()
            if not gpu.get("available"):
                raise UnsupportedError("nvidia.malware.scraper needs the Windows GPU performance counters, which are "
                                       "unavailable: %s" % gpu.get("error"))
            adapters = {a["luid"]: a for a in src.win_adapters() or []}
            index = nvml_index_by_luid(src, src.nvml())
            procs = {p["pid"]: p for p in src.win_processes()}
            windowed = set(src.win_windowed())
            for pid_s, g in (gpu.get("processes") or {}).items():
                for luid, m in (g.get("by_luid") or {}).items():
                    a = adapters.get(normalise_luid(luid))
                    total = (a or {}).get("dedicated_video_memory") or 0
                    used = m.get("dedicated") or 0
                    if not total or used < frac * total:
                        continue
                    p = procs.get(int(pid_s)) or {}
                    notes = []
                    if not (p and has_window(p, procs, windowed)):
                        notes.append("no visible window")
                    if USER_WRITABLE.search(p.get("path") or ""):
                        notes.append("user-writable image path")
                    idx = index.get(normalise_luid(luid))
                    rows.append((int(pid_s), p.get("name") or "?",
                                 a["name"] + (" (NVML GPU %d)" % idx if idx is not None else ""), used, total, notes))
        else:
            nv = src.nvml()
            for d in nv.get("devices", []):
                total = (d.get("memory") or {}).get("total") if isinstance(d.get("memory"), dict) else None
                if not total:
                    continue
                for key in ("compute_processes", "graphics_processes", "mps_compute_processes"):
                    for p in d.get(key) or []:
                        used = p.get("used_memory") if isinstance(p, dict) else None
                        if used is not None and used >= frac * total:
                            proc = src.proc(p["pid"]) if src.is_linux else None
                            rows.append((p["pid"], (proc or {}).get("comm") or "?", d.get("name") or "?", used, total,
                                         []))

        def out():
            for pid, name, gpu, used, total, notes in sorted(rows, key=lambda r: -r[3]):
                sev = "high" if notes else "medium"
                yield 0, (pid, name, gpu, human_size(used), human_size(total), round(100.0 * used / total, 1), sev,
                          "holds %.0f%% of GPU memory%s" % (100.0 * used / total,
                                                            (" (" + ", ".join(notes) + ")") if notes else ""))
        return TreeGrid([("PID", int), ("Name", str), ("GPU", str), ("Holds", str), ("GPU memory", str),
                         ("Percent", float), ("Severity", str), ("Finding", str)], out())
