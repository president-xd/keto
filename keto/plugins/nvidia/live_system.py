"""Live (or snapshot) GPU, driver and kernel state."""

from __future__ import annotations

import datetime as _dt
import gzip
import re
from typing import List

from keto.framework.exceptions import RequirementError
from keto.framework.plugin import Plugin, Requirement, TimeLinerInterface
from keto.framework.treegrid import TreeGrid, na
from keto.framework.util import human_size
from keto.indicators import xid as xid_ind
from keto.plugins.nvidia.live_procs import (MODPROBE_DIRS, _na_of, modprobe_entries, nvml_devices, read_params,
                                                 require_linux)


def nvv(value):
    """Render an NVML collector value for a table cell."""
    if value is None:
        return na("unknown")
    bad = _na_of(value)
    if bad is not None:
        return bad
    if isinstance(value, dict):
        return ", ".join("%s=%s" % (k, nvv(v)) for k, v in value.items())
    if isinstance(value, list):
        return ", ".join(str(nvv(v)) for v in value) or "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _mem(v):
    if isinstance(v, dict) and "_na" not in v:
        return "total %s, used %s, free %s" % (human_size(v["total"]), human_size(v["used"]), human_size(v["free"]))
    return nvv(v)


DEVICE_FIELDS = [("name", "Name"), ("uuid", "UUID"), ("serial", "Serial"), ("board_part_number", "Board part"),
                 ("brand", "Brand"), ("architecture", "Architecture"), ("compute_capability", "Compute capability"),
                 ("vbios_version", "VBIOS"), ("inforom_image", "InfoROM image"), ("pci", "PCI"),
                 ("minor_number", "Device minor (/dev/nvidiaN)"), ("memory", "Framebuffer memory"),
                 ("bar1", "BAR1 aperture"), ("persistence_mode", "Persistence mode"), ("compute_mode", "Compute mode"),
                 ("driver_model", "Driver model (Windows)"), ("mig_mode", "MIG mode"), ("display_mode", "Display mode"),
                 ("display_active", "Display active"), ("pstate", "Performance state"),
                 ("temperature_c", "Temperature C"), ("power_mw", "Power mW"), ("power_limit_mw", "Power limit mW"),
                 ("fan_percent", "Fan %"), ("pcie_gen", "PCIe gen (current)"), ("pcie_width", "PCIe width (current)"),
                 ("pcie_max_gen", "PCIe gen (max)"), ("pcie_max_width", "PCIe width (max)"),
                 ("pcie_replay_counter", "PCIe replay counter"), ("accounting_mode", "Accounting mode")]


class Devices(Plugin):
    NAME = "nvidia.devices"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Shows every GPU's identity and configuration: name, UUID, serial, VBIOS/InfoROM, PCI location, "
                   "framebuffer and BAR1 memory, persistence/compute/MIG/driver modes, power, thermals and PCIe link.")
    METHOD = ("NVML: nvmlSystemGet{Driver,NVML,CudaDriver}Version and per device nvmlDeviceGet{Name,UUID,Serial,"
              "VbiosVersion,InforomImageVersion,PciInfo_v3,MemoryInfo,BAR1MemoryInfo,PersistenceMode,ComputeMode,"
              "DriverModel,MigMode,PowerUsage,Temperature,CurrPcieLink*}; unsupported queries are shown as N/A.")
    ANALOG = "windows.info"
    SOURCES = ("live",)

    def run(self):
        nv, devices = nvml_devices(self.ctx.live)

        def rows():
            for key, label in (("driver_version", "Driver version"), ("nvml_version", "NVML version"),
                               ("cuda_driver_version", "CUDA driver API version"), ("library", "NVML library")):
                yield 0, ("system", label, nvv(nv.get(key)))
            for d in devices:
                gpu = "GPU %s" % d.get("index")
                yield 0, (gpu, "Device", nvv(d.get("name")))
                for key, label in DEVICE_FIELDS[1:]:
                    v = d.get(key)
                    yield 1, (gpu, label, _mem(v) if key in ("memory", "bar1") else nvv(v))
        return TreeGrid([("GPU", str), ("Field", str), ("Value", str)], rows())


class Engines(Plugin):
    NAME = "nvidia.engines"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Shows per-engine activity of each GPU: graphics/compute, memory, video encode/decode, JPEG and "
                   "optical-flow utilisation, current vs. maximum clocks, PCIe throughput and throttle reasons.")
    METHOD = ("NVML nvmlDeviceGetUtilizationRates, nvmlDeviceGet{Encoder,Decoder,Jpg,Ofa}Utilization, "
              "nvmlDeviceGetClockInfo / MaxClockInfo per clock domain, nvmlDeviceGetPcieThroughput and "
              "nvmlDeviceGetCurrentClocksEventReasons (throttle bitmask decoded).")
    ANALOG = "windows.kpcrs (per-processor state)"
    SOURCES = ("live",)

    def run(self):
        _, devices = nvml_devices(self.ctx.live)

        def rows():
            for d in devices:
                g = d.get("index")
                util = d.get("utilization")
                if _na_of(util) is not None or not isinstance(util, dict):
                    yield 0, (g, "GR/compute", "utilization %", nvv(util))
                else:
                    yield 0, (g, "GR/compute", "utilization %", str(util.get("gpu")))
                    yield 0, (g, "memory", "utilization %", str(util.get("memory")))
                for eng, key in (("NVENC", "encoder_utilization"), ("NVDEC", "decoder_utilization"),
                                 ("NVJPG", "jpg_utilization"), ("OFA", "ofa_utilization")):
                    v = d.get(key)
                    yield 0, (g, eng, "utilization %", str(v["percent"]) if isinstance(v, dict) and "percent" in v
                              else nvv(v))
                cur, mx = d.get("clocks_mhz") or {}, d.get("max_clocks_mhz") or {}
                for dom in ("graphics", "sm", "memory", "video"):
                    yield 0, (g, dom, "clock MHz (current/max)", "%s / %s" % (nvv(cur.get(dom)), nvv(mx.get(dom))))
                yield 0, (g, "PCIe", "throughput KB/s (tx/rx)", "%s / %s" % (nvv(d.get("pcie_tx_kbps")),
                                                                          nvv(d.get("pcie_rx_kbps"))))
                tr = d.get("throttle_reasons")
                yield 0, (g, "clocks", "throttle reasons", ", ".join(tr["decoded"]) or "none"
                          if isinstance(tr, dict) and "decoded" in tr else nvv(tr))
                yield 0, (g, "power", "performance state", nvv(d.get("pstate")))
        return TreeGrid([("GPU", int), ("Engine", str), ("Metric", str), ("Value", str)], rows())


class Ecc(Plugin):
    NAME = "nvidia.ecc"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Shows VRAM health: ECC mode, corrected/uncorrected error counters (volatile and lifetime), "
                   "retired page addresses and row-remapping state.")
    METHOD = ("NVML nvmlDeviceGetEccMode, nvmlDeviceGetTotalEccErrors (corrected/uncorrected x volatile/aggregate), "
              "nvmlDeviceGetRetiredPages (multiple-SBE and DBE causes) and nvmlDeviceGetRemappedRows. Assessment: "
              "ECC switched off on an ECC-capable board, or a pending change to off, leaves GPU Rowhammer "
              "(GPUHammer) bit flips uncorrected; bursts of corrected errors and remap failures are flagged.")
    ANALOG = "(no direct analogue: memory-health evidence for VRAM)"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("corrected_burst", int, 100, "volatile corrected ECC errors flagged as a burst")]

    def run(self):
        _, devices = nvml_devices(self.ctx.live)

        def assess_mode(m):
            if not isinstance(m, dict):
                return na("")
            cur, pend = m.get("current"), m.get("pending")
            if cur in (0, False) and pend in (0, False):
                return "ECC disabled on an ECC-capable board: Rowhammer bit flips (GPUHammer) go uncorrected"
            if cur not in (0, False) and pend in (0, False):
                return "ECC will be DISABLED at next reset (pending change)"
            return na("")

        def rows():
            for d in devices:
                g = d.get("index")
                yield 0, (g, "ECC mode", nvv(d.get("ecc_mode")), assess_mode(d.get("ecc_mode")))
                errs = d.get("ecc_errors") or {}
                for k in sorted(errs):
                    v = errs[k]
                    burst = isinstance(v, int) and k == "volatile_corrected" and v >= self.opts["corrected_burst"]
                    yield 0, (g, "ECC errors " + k.replace("_", " "), nvv(v),
                              "burst of corrected errors since boot (possible Rowhammer)" if burst else na(""))
                for cause, pages in sorted((d.get("retired_pages") or {}).items()):
                    if isinstance(pages, list):
                        yield 0, (g, "retired pages (%s)" % cause, str(len(pages)), na(""))
                        for a in pages:
                            yield 1, (g, "retired page (%s)" % cause, "0x%x" % a, na(""))
                    else:
                        yield 0, (g, "retired pages (%s)" % cause, nvv(pages), na(""))
                rr = d.get("remapped_rows")
                bad = isinstance(rr, dict) and (rr.get("failure") or rr.get("pending"))
                yield 0, (g, "remapped rows", nvv(rr), "row remapping pending or failed" if bad else na(""))
        return TreeGrid([("GPU", int), ("Item", str), ("Value", str), ("Assessment", str)], rows())


PCI_CLASSES = {0x0300: "VGA controller", 0x0302: "3D controller", 0x0380: "display controller",
               0x0403: "audio device", 0x0c03: "USB controller", 0x0c80: "serial bus controller (USB-C UCSI)"}


def sysfs_bus_id(bus_id: str) -> str:
    parts = bus_id.lower().split(":")
    if len(parts) == 3 and len(parts[0]) == 8:
        parts[0] = parts[0][4:]
    return ":".join(parts)


class DeviceTree(Plugin):
    NAME = "nvidia.devicetree"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Shows each GPU's PCI device tree: every function in the GPU's slot (graphics, HD audio, USB-C), "
                   "bound kernel driver, IOMMU group, NUMA node and PCIe link, plus NVLink peers; under WSL2 the "
                   "paravirtualised /dev/dxg adapter.")
    METHOD = ("Joins NVML PCI info with /sys/bus/pci/devices/<domain:bus:dev.fn>/{vendor,device,class,driver,"
              "iommu_group,numa_node,current_link_speed,current_link_width,max_link_speed}; NVIDIA functions without "
              "an NVML device (vendor 0x10de) are listed too.")
    ANALOG = "windows.devicetree"
    SOURCES = ("live",)

    def _function(self, src, addr):
        base = "/sys/bus/pci/devices/" + addr

        def rd(name):
            v = src.read_text(base + "/" + name)
            return v.strip() if v is not None else None
        cls = rd("class")
        cls_name = PCI_CLASSES.get(int(cls, 16) >> 8, cls) if cls else "?"
        drv = src.readlink(base + "/driver")
        grp = src.readlink(base + "/iommu_group")
        details = "vendor %s device %s, %s, driver %s, iommu group %s, numa %s, link %s x%s (max %s)" % (
            rd("vendor"), rd("device"), cls_name, drv.rsplit("/", 1)[-1] if drv else "-",
            grp.rsplit("/", 1)[-1] if grp else "-", rd("numa_node") or "-", rd("current_link_speed") or "-",
            rd("current_link_width") or "-", rd("max_link_speed") or "-")
        return details

    def run(self):
        src = self.ctx.live
        nv = src.nvml()
        devices = nv.get("devices", []) if nv.get("available") else []
        pci_all = src.listdir("/sys/bus/pci/devices") or []
        nvidia_fns = [a for a in pci_all if (src.read_text("/sys/bus/pci/devices/%s/vendor" % a) or "").strip() == "0x10de"]

        def rows():
            seen_slots = set()
            for d in devices:
                pci = d.get("pci") if isinstance(d.get("pci"), dict) else {}
                bus = sysfs_bus_id(pci.get("bus_id", "")) if pci.get("bus_id") else ""
                yield 0, ("GPU %s %s" % (d.get("index"), nvv(d.get("name"))), "nvml-device", bus or na("no PCI info"),
                          "uuid %s" % nvv(d.get("uuid")))
                slot = bus.rsplit(".", 1)[0] if bus else None
                fns = [a for a in pci_all if slot and a.startswith(slot + ".")]
                if slot:
                    seen_slots.add(slot)
                for a in sorted(fns):
                    yield 1, (a, "pci-function", a, self._function(src, a))
                if bus and not fns:
                    yield 1, (bus, "pci-function", bus, "not visible in /sys/bus/pci (paravirtualised or no sysfs)")
                links = d.get("nvlink")
                if isinstance(links, list):
                    for l in links:
                        if l.get("active"):
                            yield 1, ("nvlink%d" % l["link"], "nvlink-peer", l.get("remote_bus_id", "?"),
                                      "NVLink v%s" % l.get("version", "?"))
            for a in sorted(nvidia_fns):
                if a.rsplit(".", 1)[0] not in seen_slots:
                    yield 0, (a, "pci-function (no NVML device)", a, self._function(src, a))
            st = src.stat("/dev/dxg")
            if st is not None:
                yield 0, ("/dev/dxg", "wsl-adapter", "-", "WSL2 GPU paravirtualisation node (char %s:%s); the physical "
                          "GPU is owned by the Windows host driver" % (st.get("rdev_major", "?"), st.get("rdev_minor", "?")))
        return TreeGrid([("Node", str), ("Kind", str), ("Address", str), ("Details", str)], rows())


class NvLink(Plugin):
    NAME = "nvidia.nvlink"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Shows the GPU interconnect: NVLink link states, versions and remote endpoints, and the "
                   "peer-to-peer capability matrix (read/write/atomics/NVLink) between GPUs.")
    METHOD = ("NVML nvmlDeviceGetNvLinkState / NvLinkVersion / NvLinkRemotePciInfo_v2 for links 0..17 and "
              "nvmlDeviceGetP2PStatus for every device pair.")
    ANALOG = "windows.netstat / windows.netscan"
    SOURCES = ("live",)

    def run(self):
        _, devices = nvml_devices(self.ctx.live)

        def rows():
            for d in devices:
                g = d.get("index")
                links = d.get("nvlink")
                if not isinstance(links, list):
                    yield 0, ("nvlink", g, "-", nvv(links), "")
                else:
                    for l in links:
                        yield 0, ("nvlink", g, "link %d" % l["link"], "active" if l.get("active") else "inactive",
                                  "v%s -> %s" % (l.get("version", "?"), l.get("remote_bus_id", "-")))
                for peer, caps in sorted((d.get("p2p") or {}).items()):
                    yield 0, ("p2p", g, "GPU %s" % peer, "",
                              ", ".join("%s=%s" % (k, nvv(v)) for k, v in sorted(caps.items())))
        return TreeGrid([("Kind", str), ("GPU", int), ("Link/Peer", str), ("Status", str), ("Details", str)], rows())


class Mig(Plugin):
    NAME = "nvidia.mig"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Shows Multi-Instance GPU partitioning: MIG mode (current/pending) per GPU and the GPU and "
                   "compute instances that exist.")
    METHOD = ("NVML nvmlDeviceGetMigMode; instances from /proc/driver/nvidia/capabilities/gpu<minor>/mig/gi<N>/"
              "ci<M>/access (capability files the driver creates per instance).")
    ANALOG = "vmscan (partitions / guests sharing one physical device)"
    SOURCES = ("live",)

    def run(self):
        src = self.ctx.live
        _, devices = nvml_devices(src)

        def rows():
            for d in devices:
                g = d.get("index")
                mode = d.get("mig_mode")
                if _na_of(mode) is not None:
                    yield 0, (g, nvv(mode), na(""), "-", "")
                    continue
                cur, pend = (mode.get("current"), mode.get("pending")) if isinstance(mode, dict) else (None, None)
                yield 0, (g, "enabled" if cur else "disabled", "enabled" if pend else "disabled", "-", "")
                minor = d.get("minor_number")
                base = "/proc/driver/nvidia/capabilities/gpu%s/mig" % minor
                for gi in sorted(n for n in (src.listdir(base) or []) if n.startswith("gi")):
                    acc = (src.read_text("%s/%s/access" % (base, gi)) or "").strip().replace("\n", "; ")
                    yield 1, (g, "", "", gi, acc)
                    for ci in sorted(n for n in (src.listdir("%s/%s" % (base, gi)) or []) if n.startswith("ci")):
                        acc = (src.read_text("%s/%s/%s/access" % (base, gi, ci)) or "").strip().replace("\n", "; ")
                        yield 2, (g, "", "", "%s/%s" % (gi, ci), acc)
        return TreeGrid([("GPU", int), ("MIG", str), ("Pending", str), ("Instance", str), ("Details", str)], rows())


class Driver(Plugin):
    NAME = "nvidia.driver"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Identifies the loaded NVIDIA driver and its firmware: kernel-module version/build, per-GPU "
                   "information (GSP firmware, VBIOS, bus), firmware images with SHA-256, and under WSL2 the "
                   "Windows driver-store libraries exposed in /usr/lib/wsl/lib with SHA-256.")
    METHOD = ("Reads /proc/driver/nvidia/version, /proc/driver/nvidia/gpus/*/information, /sys/module/nvidia/"
              "{version,srcversion}, hashes /lib/firmware/nvidia/<version>/* and /usr/lib/wsl/lib/*; NVML supplies "
              "driver and CUDA versions.")
    ANALOG = "windows.driverscan / windows.modules"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("no_hash", bool, False, "skip SHA-256 of firmware and driver-store files")]

    def run(self):
        src = self.ctx.live
        nv = src.nvml()

        def sha(path):
            return na("skipped") if self.opts["no_hash"] else (src.file_sha256(path) or na("unreadable"))

        def rows():
            ver = src.read_text("/proc/driver/nvidia/version")
            if ver:
                for line in ver.strip().splitlines():
                    yield 0, ("kernel module", line.strip(), na(""))
            else:
                yield 0, ("kernel module", na("/proc/driver/nvidia/version not present (no native NVIDIA kernel "
                                             "driver, e.g. WSL2)"), na(""))
            module_ver = (src.read_text("/sys/module/nvidia/version") or "").strip()
            if module_ver:
                yield 0, ("/sys/module/nvidia/version", module_ver, na(""))
                srcv = (src.read_text("/sys/module/nvidia/srcversion") or "").strip()
                if srcv:
                    yield 0, ("/sys/module/nvidia/srcversion", srcv, na(""))
            if nv.get("available"):
                yield 0, ("NVML driver version", str(nv.get("driver_version")), na(""))
                yield 0, ("CUDA driver API version", str(nv.get("cuda_driver_version")), na(""))
            for gpu in src.listdir("/proc/driver/nvidia/gpus") or []:
                info = src.read_text("/proc/driver/nvidia/gpus/%s/information" % gpu) or ""
                for line in info.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        if k.strip() in ("Model", "GPU UUID", "Video BIOS", "Bus Location", "GPU Firmware",
                                         "GPU Excluded", "Device Minor"):
                            yield 1, ("GPU %s %s" % (gpu, k.strip()), v.strip(), na(""))
            fwroot = "/lib/firmware/nvidia"
            for fver in src.listdir(fwroot) or []:
                note = "" if not module_ver or fver == module_ver else " (does NOT match loaded module %s)" % module_ver
                for f in src.listdir("%s/%s" % (fwroot, fver)) or []:
                    path = "%s/%s/%s" % (fwroot, fver, f)
                    st = src.stat(path)
                    if st and st.get("is_reg"):
                        yield 1, ("firmware" + note, "%s (%s)" % (path, human_size(st["size"])), sha(path))
            wsl = src.listdir("/usr/lib/wsl/lib")
            if wsl is not None:
                for f in wsl:
                    path = "/usr/lib/wsl/lib/" + f
                    st = src.stat(path)
                    if st and st.get("is_reg"):
                        yield 1, ("WSL driver store", "%s (%s)" % (path, human_size(st["size"])), sha(path))
        return TreeGrid([("Item", str), ("Value", str), ("SHA256", str)], rows())


KNOWN_DEPENDENTS = {"nvidia_uvm", "nvidia_modeset", "nvidia_drm", "nvidia_peermem", "nv_peer_mem", "nvidia_vgpu_vfio",
                    "nvidia_fs", "gdrdrv", "nvidia_cspmu", "nvidia_wmi_ec_backlight"}


class Modules(Plugin):
    NAME = "nvidia.modules"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Lists the NVIDIA kernel modules (nvidia, nvidia_uvm, nvidia_modeset, nvidia_drm, peermem; "
                   "nouveau; WSL dxgkrnl) with version, srcversion and taint, and flags non-NVIDIA modules that "
                   "depend on the NVIDIA driver (candidates for driver hooking).")
    METHOD = ("Parses /proc/modules (name, size, refcount, 'Used by', state, taint) and /sys/module/<name>/"
              "{version,srcversion,taint}; any dependent of an NVIDIA module not in the known NVIDIA set is "
              "flagged. Built-in modules are detected through /sys/module.")
    ANALOG = "windows.modules / linux.lsmod / linux.malware.check_modules"
    SOURCES = ("live",)

    def run(self):
        src = self.ctx.live
        require_linux(src, self.NAME)
        text = src.read_text("/proc/modules")

        def sysmod(name, attr):
            v = src.read_text("/sys/module/%s/%s" % (name, attr))
            return v.strip() if v is not None else na("-")

        def rows():
            mods = {}
            for line in (text or "").splitlines():
                f = line.split()
                if len(f) >= 5:
                    used = [u for u in f[3].split(",") if u and u != "-"]
                    mods[f[0]] = {"size": int(f[1]), "refs": int(f[2]), "used": used, "state": f[4],
                                  "taint": f[6].strip("()") if len(f) > 6 else ""}
            nvidia = {n for n in mods if n.startswith("nvidia") or n in ("nouveau", "nv_peer_mem", "dxgkrnl")}
            dependents = {u for n in nvidia if n.startswith("nvidia") for u in mods[n]["used"]}
            for n in sorted(nvidia | dependents):
                m = mods.get(n)
                if m is None:
                    continue
                sus = n in dependents and n not in KNOWN_DEPENDENTS and not n.startswith("nvidia")
                reason = ""
                if sus:
                    reason = "non-NVIDIA module depends on the NVIDIA driver (uses its exported symbols)"
                    if "E" in m["taint"]:
                        reason += "; unsigned (taint E)"
                    if "O" in m["taint"]:
                        reason += "; out-of-tree (taint O)"
                yield 0, (n, m["size"], m["refs"], ",".join(m["used"]) or "-", m["state"], m["taint"] or "-",
                          sysmod(n, "version"), sysmod(n, "srcversion"), sus, reason)
            if "nouveau" in mods and any(n.startswith("nvidia") for n in mods):
                yield 0, ("nouveau", mods["nouveau"]["size"], mods["nouveau"]["refs"], "-", "", "", na("-"), na("-"),
                          True, "nouveau loaded alongside the proprietary driver")
            for builtin in ("dxgkrnl", "nvidia"):
                if builtin not in mods and src.listdir("/sys/module/" + builtin) is not None:
                    yield 0, (builtin, na("built-in"), na(""), "-", "built-in", "-", sysmod(builtin, "version"),
                              sysmod(builtin, "srcversion"), False,
                              "built into the kernel" + (" (WSL2 GPU paravirtualisation)" if builtin == "dxgkrnl" else ""))
            if text is None:
                yield 0, ("/proc/modules", na("unreadable"), na(""), "-", "", "", na("-"), na("-"), False,
                          "kernel without loadable-module support or no access")
        return TreeGrid([("Module", str), ("Size", int), ("Refs", int), ("Used by", str), ("State", str),
                         ("Taint", str), ("Version", str), ("SrcVersion", str), ("Suspicious", bool),
                         ("Reason", str)], rows())


NODE_RE = re.compile(r"^(nvidia\S*|dxg)$")
MAJOR_195 = re.compile(r"^(nvidiactl|nvidia\d+|nvidia-modeset)$")


class DevNodes(Plugin):
    NAME = "nvidia.devnodes"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Checks the GPU device nodes (/dev/nvidia*, /dev/nvidia-caps/*, /dev/dxg): type, major/minor, "
                   "permissions and owner; flags fake (non character-device) nodes, unexpected majors and "
                   "capability nodes accessible to every user.")
    METHOD = ("lstat of every /dev entry named nvidia*/dxg and of /dev/nvidia-caps/*; nvidiactl, nvidiaN and "
              "nvidia-modeset must be character devices with major 195; nvidia-caps nodes should not be "
              "world-accessible.")
    ANALOG = "windows.driverirp / windows.devicetree (device objects)"
    SOURCES = ("live",)

    def run(self):
        src = self.ctx.live
        require_linux(src, self.NAME)
        paths = ["/dev/" + n for n in (src.listdir("/dev") or []) if NODE_RE.match(n)]
        paths += ["/dev/nvidia-caps/" + n for n in (src.listdir("/dev/nvidia-caps") or [])]

        def rows():
            for path in sorted(paths):
                st = src.stat(path)
                if st is None:
                    continue
                name = path[5:]
                if st["is_dir"]:
                    continue
                notes, sus = [], False
                kind = "char" if st["is_char"] else "symlink" if st["is_link"] else "regular" if st["is_reg"] else "other"
                mode = int(st["perm"], 8)
                if st["is_link"]:
                    tgt = src.readlink(path) or "?"
                    notes.append("-> " + tgt)
                    if tgt.startswith("/") and not tgt.startswith("/dev/"):
                        sus = True
                        notes.append("symlink leaves /dev")
                elif not st["is_char"]:
                    sus = True
                    notes.append("not a character device (fake or stale node)")
                if st["is_char"] and MAJOR_195.match(name) and st.get("rdev_major") != 195:
                    sus = True
                    notes.append("unexpected major %s (NVIDIA uses 195)" % st.get("rdev_major"))
                if name.startswith("nvidia-caps/") and mode & 0o006:
                    sus = True
                    notes.append("capability node accessible to all users")
                elif mode & 0o002 and st["is_char"]:
                    notes.append("world-accessible (driver default DeviceFileMode=0666)")
                yield 0, (path, kind, st.get("rdev_major", na("-")), st.get("rdev_minor", na("-")), st["perm"],
                          st["uid"], st["gid"], sus, "; ".join(notes))
        return TreeGrid([("Node", str), ("Type", str), ("Major", int), ("Minor", int), ("Mode", str), ("UID", int),
                         ("GID", int), ("Suspicious", bool), ("Notes", str)], rows())


PARAM_RULES = {
    "RmProfilingAdminOnly": lambda v: ("high", "GPU performance counters usable by non-admin users "
                                       "(CVE-2018-6260 side channel)") if v == "0" else ("info", "profiling restricted"),
    "NVreg_RestrictProfilingToAdminUsers": lambda v: ("high", "disables the profiling restriction (CVE-2018-6260)")
    if v == "0" else ("info", "profiling restricted"),
    "InitializeSystemMemoryAllocations": lambda v: ("medium", "system-memory allocations are not zeroed: residual "
                                                    "data can leak between processes") if v == "0" else ("info", ""),
    "NVreg_InitializeSystemMemoryAllocations": lambda v: ("medium", "system-memory allocations not zeroed")
    if v == "0" else ("info", ""),
    "DeviceFileMode": lambda v: ("low", "device nodes world-accessible (driver default 0666)")
    if v.isdigit() and int(v) & 0o002 else ("info", ""),
    "NVreg_DeviceFileMode": lambda v: ("low", "device nodes world-accessible") if v.isdigit() and int(v, 0) & 0o002
    else ("info", ""),
    "ModifyDeviceFiles": lambda v: ("info", "driver does not manage /dev nodes") if v == "0" else ("info", ""),
    "EnableGpuFirmware": lambda v: ("info", "GSP firmware disabled") if v == "0" else ("info", ""),
    "RegistryDwords": lambda v: ("info", "RM registry overrides present") if v.strip('"') else ("info", ""),
    "NVreg_RegistryDwords": lambda v: ("info", "RM registry overrides present") if v.strip('"') else ("info", ""),
}


class Params(Plugin):
    NAME = "nvidia.params"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Prints the NVIDIA driver's runtime parameters and NVreg_* module options from modprobe "
                   "configuration, flagging security-relevant settings (profiling restriction, memory zeroing, "
                   "device-node permissions, registry overrides).")
    METHOD = "Parses /proc/driver/nvidia/params ('Key: value') and 'options nvidia NVreg_*' lines in %s." % \
             ", ".join(MODPROBE_DIRS)
    ANALOG = "windows.registry.printkey"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("flagged_only", bool, False, "only parameters with a finding")]

    def run(self):
        src = self.ctx.live
        require_linux(src, self.NAME)
        params = read_params(src)

        def rows():
            if not params:
                yield 0, ("/proc/driver/nvidia/params", na("not present"), "", "info",
                          "no native NVIDIA kernel driver (e.g. WSL2) or no access")
            for k, v in params.items():
                sev, note = PARAM_RULES.get(k, lambda _v: ("info", ""))(v)
                if self.opts["flagged_only"] and not note:
                    continue
                yield 0, ("/proc/driver/nvidia/params", k, v, sev, note)
            for e in modprobe_entries(src):
                if e["kind"] != "options" or not e["module"].startswith("nvidia"):
                    continue
                sev, note = PARAM_RULES.get(e["key"], lambda _v: ("info", ""))(e["value"])
                if self.opts["flagged_only"] and not note:
                    continue
                yield 0, (e["file"], "%s %s" % (e["module"], e["key"]), e["value"], sev, note)
        return TreeGrid([("Source", str), ("Parameter", str), ("Value", str), ("Severity", str), ("Note", str)], rows())


def _open_log(path: str) -> List[str]:
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return raw.decode("utf-8", "replace").splitlines()


class Xid(Plugin, TimeLinerInterface):
    NAME = "nvidia.xid"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Decodes NVIDIA Xid error events from the kernel log (GPU page faults with faulting VA and "
                   "access type, engine exceptions, falling off the bus, ECC events...) with time, PID and process.")
    METHOD = ("Parses 'NVRM: Xid (PCI:...): <code>, pid=..., name=..., <message>' lines from journalctl -k "
              "(-o short-iso) or dmesg (boot-relative time converted with /proc/stat btime), or from --log-file "
              "(plain or .gz); codes are named from the built-in Xid catalogue.")
    ANALOG = "linux.kmsg / windows.crashinfo"
    SOURCES = ("file",)
    REQUIREMENTS = [Requirement("log_file", str, None, "kernel log / syslog / dmesg capture to parse instead of the "
                                                        "live system"),
                    Requirement("code", int, None, "only this Xid code")]

    def _events(self):
        if self.opts.get("log_file"):
            return xid_ind.parse_log(_open_log(self.opts["log_file"]), None, None), "file %s" % self.opts["log_file"]
        if not self.ctx.has_live():
            raise RequirementError("nvidia.xid needs --log-file or a live/snapshot source (--live)")
        src = self.ctx.live
        m = re.search(r"^btime (\d+)", src.read_text("/proc/stat") or "", re.M)
        boot = float(m.group(1)) if m else None
        now = src.now()
        year = _dt.datetime.fromtimestamp(now, tz=_dt.timezone.utc).year if now else None
        for argv in (["journalctl", "-k", "-o", "short-iso", "--no-pager"], ["dmesg"]):
            r = src.command(argv)
            if r and r.get("rc") == 0 and r.get("stdout"):
                return xid_ind.parse_log(r["stdout"].splitlines(), boot, year), " ".join(argv)
        return None, (r or {}).get("stderr", "kernel log unavailable").strip()

    def run(self):
        events, origin = self._events()

        def rows():
            if events is None:
                yield 0, (na(""), "", na(""), "kernel log unreadable", na(""), "", origin, "")
                return
            for e in events:
                if self.opts["code"] is not None and e["code"] != self.opts["code"]:
                    continue
                yield 0, (e["time"] or na("no timestamp"), e["pci"], e["code"],
                          e["name"] + ("" if e["certain"] else " (?)"), e["pid"] if e["pid"] is not None else na("-"),
                          e["process"], e["details"], e["forensic"])
        return TreeGrid([("Time", object), ("PCI", str), ("Xid", int), ("Name", str), ("PID", int), ("Process", str),
                         ("Details", str), ("Forensic note", str)], rows())

    def generate_timeline(self):
        events, _ = self._events()
        for e in events or []:
            if e["time"]:
                yield ("Xid %d %s (pid %s %s) %s" % (e["code"], e["name"], e["pid"], e["process"], e["details"]),
                       "Error", e["time"])


class BugReport(Plugin):
    NAME = "nvidia.bugreport"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Extracts forensic facts from an nvidia-bug-report.log(.gz): collection date, kernel, driver "
                   "and CUDA versions, every GPU (name, UUID, bus, VBIOS), Xid events and the list of captured "
                   "sections.")
    METHOD = ("Reads the (optionally gzip-compressed) report; parses 'NVRM version', 'uname', nvidia-smi -q "
              "'Product Name / GPU UUID / VBIOS Version' blocks, '*** <section>' headers and Xid lines with the "
              "Xid decoder.")
    ANALOG = "windows.crashinfo"
    SOURCES = ("file",)
    REQUIREMENTS = [Requirement("file", str, None, "path to nvidia-bug-report.log or .log.gz")]

    def run(self):
        if not self.opts.get("file"):
            raise RequirementError("nvidia.bugreport needs --file <nvidia-bug-report.log[.gz]>")
        lines = _open_log(self.opts["file"])
        text = "\n".join(lines)

        def first(rx):
            m = re.search(rx, text, re.M)
            return m.group(1).strip() if m else None

        def rows():
            for label, rx in (("report started", r"Start of NVIDIA bug report log file\.\s*(.*)$"),
                              ("script version", r"nvidia-bug-report\.sh Version:\s*(.*)$"),
                              ("uname", r"^uname:\s*(.*)$"), ("kernel module", r"NVRM version:\s*(.*)$"),
                              ("driver version", r"Driver Version\s*:\s*(.*)$"),
                              ("CUDA version", r"CUDA Version\s*:\s*(.*)$")):
                v = first(rx)
                yield 0, ("report", label, v if v else na("not found"))
            gpu = None
            for line in lines:
                m = re.match(r"^GPU ([0-9A-Fa-f]{4,8}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.\d)\s*$", line.strip())
                if m:
                    gpu = m.group(1)
                    yield 0, ("gpu", "bus", gpu)
                    continue
                m = re.match(r"^\s+(Product Name|GPU UUID|VBIOS Version|Serial Number|Board Part Number)\s*:\s*(.*)$",
                             line)
                if m and gpu:
                    yield 1, ("gpu", "%s %s" % (gpu, m.group(1)), m.group(2).strip())
            for e in xid_ind.parse_log(lines):
                yield 0, ("xid", "Xid %d %s" % (e["code"], e["name"]), "pid=%s %s %s" % (e["pid"], e["process"],
                                                                                        e["details"]))
            sections = [l[4:].strip() for l in lines if l.startswith("*** ")]
            yield 0, ("report", "sections", "%d: %s" % (len(sections), "; ".join(sections[:40])))
        return TreeGrid([("Category", str), ("Item", str), ("Value", str)], rows())


__all__ = ["Devices", "Engines", "Ecc", "DeviceTree", "NvLink", "Mig", "Driver", "Modules", "DevNodes", "Params",
           "Xid", "BugReport"]
