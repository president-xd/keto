"""Live detectors for GPU abuse that bypasses process accounting, the NVIDIA driver, or the GPU watchdog."""

from __future__ import annotations

import re

from keto.framework.plugin import Plugin, Requirement
from keto.framework.treegrid import TreeGrid, na
from keto.framework.util import human_size

GRAPHICS_DRIVERS_KEY = r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
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
              "usedGpuMemory over the compute, graphics and MPS process lists. Drivers that do not report "
              "per-process memory (WDDM) are shown as such rather than flagged.")
    ANALOG = "windows.malware.psxview (accounting cross-view)"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("threshold", "size", 1 << 30, "unaccounted memory that is flagged (default 1G)"),
                    Requirement("util_threshold", int, 20, "GPU utilisation % flagged when no process is listed")]

    def run(self):
        nv = self.ctx.live.nvml()

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
                findings = []
                unacc = None
                if used is not None and procs and unknown == len(procs):
                    note = "driver does not report per-process memory (WDDM): memory cross-view not possible"
                else:
                    note = ""
                    if used is not None:
                        unacc = used - total
                        if unacc >= self.opts["threshold"]:
                            findings.append("%s of used GPU memory belongs to no listed process" % human_size(unacc))
                if isinstance(util, int) and not procs and util >= self.opts["util_threshold"]:
                    findings.append("GPU %d%% busy with no process listed" % util)
                yield 0, (i, d.get("name") or na(""), human_size(used) if used is not None else na("?"),
                          human_size(total), len(procs), human_size(unacc) if unacc is not None else na(""),
                          util if isinstance(util, int) else na("?"), "; ".join(findings) or note or na(""))
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
        if not src.is_linux:
            from keto.framework.exceptions import UnsupportedError
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
