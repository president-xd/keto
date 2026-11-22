"""Live (or snapshot) GPU, driver and kernel state."""

from __future__ import annotations

import datetime as _dt
import gzip
import os
import re
import zlib
from typing import List

from keto.framework.exceptions import FormatError, RequirementError, UnsupportedError
from keto.framework.plugin import Plugin, Requirement, TimeLinerInterface
from keto.framework.treegrid import TreeGrid, na
from keto.framework.util import human_size
from keto.indicators import xid as xid_ind
from keto.plugins.nvidia.live_procs import (DISPLAY_CLASS, MODPROBE_DIRS, NVLDDMKM_KEY, SERVICES_KEY,
                                                 WIN_NVIDIA_DIRS_RE, _na_of, display_adapter_keys, modprobe_entries,
                                                 nvml_devices, read_params, require_linux, win_driver_files,
                                                 win_rm_profiling)
from keto.plugins.windows import gpu as wgpu

ENUM_PCI_KEY = r"HKLM\SYSTEM\CurrentControlSet\Enum\PCI"
GRAPHICS_DRIVERS_KEY = r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"


def win_kernel_drivers(src):
    """``[(loaded driver, version info)]`` of the loaded NVIDIA kernel drivers (driver store / NVIDIA company)
    and the Microsoft graphics kernel (dxgkrnl, dxgmms)."""
    out = []
    for drv in src.win_drivers() or []:
        name, path = (drv.get("name") or "").lower(), drv.get("path") or ""
        if name.startswith(("dxgkrnl", "dxgmms")) or WIN_NVIDIA_DIRS_RE.search(path) or name.startswith("nv"):
            ver = src.win_file_version(path) or {}
            if name.startswith(("dxgkrnl", "dxgmms")) or WIN_NVIDIA_DIRS_RE.search(path) or \
                    "nvidia" in (ver.get("company") or "").lower():
                out.append((drv, ver))
    return out


def _sig_text(sig):
    if not sig:
        return na("not checked")
    return "%s (%s, %s)" % (sig.get("status"), sig.get("signer") or "-", sig.get("kind") or "-")


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
        return "total %s, used %s, free %s%s" % (human_size(v["total"]), human_size(v["used"]), human_size(v["free"]),
                                                 ", reserved %s" % human_size(v["reserved"]) if "reserved" in v else "")
    return nvv(v)


#: NVML enable-state fields (nvmlEnableState_t 0/1), shown as nvidia-smi does
ENABLE_STATE_FIELDS = {"persistence_mode", "display_mode", "display_active", "accounting_mode"}


def _enabled(v):
    return {0: "Disabled", 1: "Enabled"}.get(v, nvv(v)) if isinstance(v, int) and not isinstance(v, bool) else nvv(v)


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
              "VbiosVersion,InforomImageVersion,PciInfo_v3,MemoryInfo_v2 (used excludes the reserved framebuffer; "
              "v1 where v2 is missing),BAR1MemoryInfo,PersistenceMode,ComputeMode,DriverModel,MigMode,PowerUsage,"
              "Temperature,CurrPcieLink*}; unsupported queries are shown as N/A.")
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
                    yield 1, (gpu, label, _mem(v) if key in ("memory", "bar1") else
                              _enabled(v) if key in ENABLE_STATE_FIELDS else nvv(v))
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
              "an NVML device (vendor 0x10de) are listed too. On Windows the NVIDIA PCI functions come from "
              "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_10DE* (DeviceDesc, LocationInformation, Service, "
              "Driver key, HardwareID) matched to NVML devices by bus/device, plus the DXGI adapters (LUID, PCI "
              "ids, memory).")
    ANALOG = "windows.devicetree"
    SOURCES = ("live",)

    def _windows(self, src, devices):
        functions = []
        for dev in (src.registry_key(ENUM_PCI_KEY) or {}).get("subkeys", []):
            if not dev.upper().startswith("VEN_10DE"):
                continue
            for inst in (src.registry_key(ENUM_PCI_KEY + "\\" + dev) or {}).get("subkeys", []):
                vals = (src.registry_key("%s\\%s\\%s" % (ENUM_PCI_KEY, dev, inst)) or {}).get("values") or {}
                loc = str(vals.get("LocationInformation") or "")
                m = re.search(r"\((\d+),(\d+),(\d+)\)\s*$", loc) or re.search(r"bus (\d+), device (\d+), function (\d+)",
                                                                             loc)
                functions.append((tuple(int(x) for x in m.groups()) if m else None, dev + "\\" + inst, vals))

        def details(vals):
            hw = vals.get("HardwareID")
            return "%s, service %s, driver key %s, hardware id %s" % (
                str(vals.get("DeviceDesc") or "?").rsplit(";", 1)[-1], vals.get("Service") or "-",
                vals.get("Driver") or "-", (hw[0] if isinstance(hw, list) and hw else hw) or "-")

        def addr(domain, loc):
            return "%04x:%02x:%02x.%x" % ((domain or 0,) + loc) if loc else na("no location")

        def rows():
            used = set()
            for d in devices:
                pci = d.get("pci") if isinstance(d.get("pci"), dict) else {}
                bus = sysfs_bus_id(pci.get("bus_id", "")) if pci.get("bus_id") else ""
                yield 0, ("GPU %s %s" % (d.get("index"), nvv(d.get("name"))), "nvml-device", bus or na("no PCI info"),
                          "uuid %s" % nvv(d.get("uuid")))
                for i, (loc, inst, vals) in enumerate(functions):
                    if loc and pci and loc[:2] == (pci.get("bus"), pci.get("device")):
                        used.add(i)
                        yield 1, (inst, "pci-function", addr(pci.get("domain"), loc), details(vals))
                for l in d.get("nvlink") if isinstance(d.get("nvlink"), list) else []:
                    if l.get("active"):
                        yield 1, ("nvlink%d" % l["link"], "nvlink-peer", l.get("remote_bus_id", "?"),
                                  "NVLink v%s" % l.get("version", "?"))
            for i, (loc, inst, vals) in enumerate(functions):
                if i not in used:
                    yield 0, (inst, "pci-function (no NVML device)", addr(0, loc), details(vals))
            for a in src.win_adapters() or []:
                yield 0, ("adapter %s" % a.get("name"), "dxgi-adapter", a.get("luid") or na(""),
                          "vendor 0x%04x device 0x%04x, dedicated video memory %s, shared system memory %s%s" % (
                              a.get("vendor_id") or 0, a.get("device_id") or 0,
                              human_size(a.get("dedicated_video_memory") or 0),
                              human_size(a.get("shared_system_memory") or 0),
                              ", software adapter" if a.get("software") else ""))
        return TreeGrid([("Node", str), ("Kind", str), ("Address", str), ("Details", str)], rows())

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
        if src.is_windows:
            return self._windows(src, devices)
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
              "driver and CUDA versions. On Windows: the NVIDIA display-class key (DriverDesc, DriverVersion, "
              "DriverDate, InfPath, MatchingDeviceId), then nvlddmkm.sys (service ImagePath, loaded or not), the "
              "other loaded NVIDIA kernel drivers (SystemModuleInformation) and the user-mode/API driver files the "
              "registry names, each with file version, Authenticode status and SHA-256.")
    ANALOG = "windows.driverscan / windows.modules"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("no_hash", bool, False, "skip SHA-256 of firmware and driver-store files")]

    def _windows(self, src, nv, sha):
        def describe(path):
            st = src.stat(path)
            if st is None:
                return na("%s: file not found" % path)
            ver = src.win_file_version(path) or {}
            return "%s (%s, version %s, %s; Authenticode %s)" % (
                path, human_size(st.get("size") or 0), ver.get("file_version") or "?", ver.get("company") or "?",
                _sig_text(src.win_signature(path)))

        def rows():
            if nv.get("available"):
                yield 0, ("NVML driver version", str(nv.get("driver_version")), na(""))
                yield 0, ("CUDA driver API version", str(nv.get("cuda_driver_version")), na(""))
            keys = display_adapter_keys(src, nvidia_only=True)
            if not keys:
                yield 0, ("display driver", na("no NVIDIA display adapter in %s" % DISPLAY_CLASS), na(""))
            for key, vals in keys:
                yield 0, ("display driver", "%s (%s)" % (vals.get("DriverDesc") or "?", key), na(""))
                for field in ("DriverVersion", "DriverDate", "ProviderName", "InfPath", "MatchingDeviceId"):
                    if vals.get(field) is not None:
                        yield 1, (field, str(vals[field]), na(""))
            loaded = {(d.get("path") or "").lower() for d in src.win_drivers() or []}
            files = win_driver_files(src)
            kmd = next((p for role, p in files if role == "kernel-mode driver"), "")
            if not kmd:
                yield 0, ("kernel-mode driver", na("nvlddmkm service not registered (%s)" % NVLDDMKM_KEY), na(""))
            for role, path in files:
                if role == "kernel-mode driver":
                    yield 0, ("kernel-mode driver (%s)" % ("loaded" if path.lower() in loaded else "NOT loaded"),
                              describe(path), sha(path) if src.stat(path) else na(""))
            for drv, _ver in win_kernel_drivers(src):
                if drv.get("path", "").lower() != kmd.lower() and not drv.get("name", "").lower().startswith("dxg"):
                    yield 0, ("kernel driver %s (loaded)" % drv.get("name"), describe(drv["path"]),
                              sha(drv["path"]) if src.stat(drv["path"]) else na(""))
            for role, path in files:
                if role != "kernel-mode driver" and src.stat(path) is not None:
                    yield 1, ("user-mode driver file (%s)" % role, describe(path), sha(path))
        return TreeGrid([("Item", str), ("Value", str), ("SHA256", str)], rows())

    def run(self):
        src = self.ctx.live
        nv = src.nvml()

        def sha(path):
            return na("skipped") if self.opts["no_hash"] else (src.file_sha256(path) or na("unreadable"))

        if src.is_windows:
            return self._windows(src, nv, sha)

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
              "flagged. Built-in modules are detected through /sys/module. On Windows: the loaded kernel drivers "
              "(NtQuerySystemInformation SystemModuleInformation) that are NVIDIA's (driver store / company "
              "NVIDIA) plus dxgkrnl/dxgmms, each with file version, Authenticode status and SHA-256 (flagged when "
              "not validly signed by NVIDIA/Microsoft or loaded from outside System32), and the UpperFilters/"
              "LowerFilters of the display adapter class and of the NVIDIA PCI devices (a filter driver sees the "
              "GPU driver's I/O requests: the hooking analogue).")
    ANALOG = "windows.modules / linux.lsmod / linux.malware.check_modules"
    SOURCES = ("live",)

    def _windows(self, src):
        root = wgpu.system_root(src).lower() + "\\system32\\"
        loaded = {(d.get("name") or "").lower(): d for d in src.win_drivers() or []}

        def judge(path, sig):
            why = []
            if sig and sig.get("status") != "valid":
                why.append("Authenticode: %s" % sig.get("status"))
            elif sig and not re.search(r"nvidia|microsoft", sig.get("signer") or "", re.I):
                why.append("signed by %r, not NVIDIA/Microsoft" % sig.get("signer"))
            if path and not path.lower().startswith(root):
                why.append("loaded from outside %s" % root.rstrip("\\"))
            return why

        def row(name, path, is_loaded, why):
            st = src.stat(path) if path else None
            ver = (src.win_file_version(path) or {}) if st else {}
            sig = src.win_signature(path) if st else None
            why = why + judge(path, sig) if st else why + ["driver file not found"]
            return (name, path or na("no ImagePath"), is_loaded, ver.get("file_version") or na(""),
                    ver.get("company") or na(""), _sig_text(sig), (src.file_sha256(path) or na("unreadable")) if st
                    else na(""), bool(why), "; ".join(why))

        def rows():
            for drv, _ver in win_kernel_drivers(src):
                yield 0, row(drv.get("name"), drv.get("path"), True, [])
            filters = []
            cls = (src.registry_key(DISPLAY_CLASS) or {}).get("values") or {}
            for kind in ("UpperFilters", "LowerFilters"):
                filters += [(f, "display adapter class %s" % kind) for f in cls.get(kind) or []]
            for dev in (src.registry_key(ENUM_PCI_KEY) or {}).get("subkeys", []):
                if dev.upper().startswith("VEN_10DE"):
                    for inst in (src.registry_key(ENUM_PCI_KEY + "\\" + dev) or {}).get("subkeys", []):
                        vals = (src.registry_key("%s\\%s\\%s" % (ENUM_PCI_KEY, dev, inst)) or {}).get("values") or {}
                        for kind in ("UpperFilters", "LowerFilters"):
                            filters += [(f, "NVIDIA device %s %s" % (dev, kind)) for f in vals.get(kind) or []]
            for name, where in filters:
                image = ((src.registry_key(SERVICES_KEY + "\\" + name) or {}).get("values") or {}).get("ImagePath")
                path = wgpu.win_path(src, str(image)) if image else ""
                yield 0, row(name, path, wgpu.basename(path).lower() in loaded,
                             ["%s filter driver: sees every I/O request to the GPU driver (driver hooking analogue)"
                              % where])
            if not filters:
                yield 0, ("display filters", DISPLAY_CLASS, False, na(""), na(""), na(""), na(""), False,
                          "no UpperFilters/LowerFilters on the display adapter class or the NVIDIA PCI devices")
        return TreeGrid([("Module", str), ("Path", str), ("Loaded", bool), ("Version", str), ("Company", str),
                         ("Signature", str), ("SHA256", str), ("Suspicious", bool), ("Reason", str)], rows())

    def run(self):
        src = self.ctx.live
        if src.is_windows:
            return self._windows(src)
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
        if src.is_windows:
            raise UnsupportedError(
                "nvidia.devnodes checks Linux /dev/nvidia* and /dev/dxg character-device nodes; Windows has no such "
                "nodes (applications reach the GPU through \\Device\\DxgKrnl and the display driver). Run "
                "nvidia.modules (NVIDIA kernel drivers, their signatures and display-class filter drivers) and "
                "nvidia.devicetree on Windows, and nvidia.devnodes inside WSL2/Linux")
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
                    notes.append("world-accessible (dxgkrnl default on WSL2)" if name == "dxg" else
                                 "world-accessible (driver default DeviceFileMode=0666)")
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
    # Windows: Microsoft "Timeout Detection and Recovery (TDR) registry keys"
    "TdrLevel": lambda v: ("high", "GPU timeout detection disabled (TdrLevelOff): kernels can run indefinitely")
    if v == "0" else ("info", ""),
    "TdrDebugMode": lambda v: ("high", "GPU timeouts ignored (TdrDebugMode=1)") if v == "1" else ("info", ""),
    "TdrDelay": lambda v: ("medium", "long GPU timeout (%s s)" % v) if v.isdigit() and int(v) > 10 else ("info", ""),
    "TdrDdiDelay": lambda v: ("medium", "long GPU timeout (%s s)" % v) if v.isdigit() and int(v) > 10 else ("info", ""),
}
TDR_VALUES = ("TdrLevel", "TdrDelay", "TdrDdiDelay", "TdrDebugMode", "TdrLimitTime", "TdrLimitCount")
WIN_PARAM_KEYS = (NVLDDMKM_KEY, NVLDDMKM_KEY + r"\Parameters", NVLDDMKM_KEY + r"\Global\NVTweak",
                  NVLDDMKM_KEY + r"\Parameters\Global\NVTweak")


def _reg_text(v) -> str:
    if isinstance(v, dict) and "binary" in v:
        return "binary (%d bytes)" % v.get("size", 0)
    if isinstance(v, list):
        return "; ".join(map(str, v))
    return str(v)


class Params(Plugin):
    NAME = "nvidia.params"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Prints the NVIDIA driver's runtime parameters and NVreg_* module options from modprobe "
                   "configuration, flagging security-relevant settings (profiling restriction, memory zeroing, "
                   "device-node permissions, registry overrides).")
    METHOD = ("Parses /proc/driver/nvidia/params ('Key: value') and 'options nvidia NVreg_*' lines in %s. On "
              "Windows: the values of the nvlddmkm service key, its Parameters and Global\\NVTweak subkeys, the "
              "RM* values of the NVIDIA display-class key (RmProfilingAdminOnly reported even when unset) and the "
              "TDR values under HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers." % ", ".join(MODPROBE_DIRS))
    ANALOG = "windows.registry.printkey"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("flagged_only", bool, False, "only parameters with a finding")]

    def _windows(self, src):
        def judge(name, value):
            return PARAM_RULES.get(name, lambda _v: ("info", ""))(_reg_text(value))

        def rows():
            if src.registry_key(NVLDDMKM_KEY) is None:
                yield 0, (NVLDDMKM_KEY, na("not present"), "", "info", "no NVIDIA display driver installed")
            entries = []
            for key in WIN_PARAM_KEYS:
                vals = (src.registry_key(key) or {}).get("values") or {}
                entries += [(key, k, vals[k]) for k in sorted(vals)]
            for key, vals in display_adapter_keys(src, nvidia_only=True):
                entries += [(key, k, vals[k]) for k in sorted(vals) if k.lower().startswith("rm")]
            if not win_rm_profiling(src):
                entries.append(("registry (default)", "RmProfilingAdminOnly", None))
            tdr = (src.registry_key(GRAPHICS_DRIVERS_KEY) or {}).get("values") or {}
            entries += [(GRAPHICS_DRIVERS_KEY, k, tdr.get(k)) for k in TDR_VALUES]
            for key, name, value in entries:
                if value is None:
                    sev, note = "info", ("not set: profiling restricted to administrators (driver default since "
                                         "R419.67)" if name == "RmProfilingAdminOnly" else "not set (default)")
                    if self.opts["flagged_only"]:
                        continue
                    yield 0, (key, name, na("not set"), sev, note)
                    continue
                sev, note = judge(name, value)
                if self.opts["flagged_only"] and not note:
                    continue
                yield 0, (key, name, _reg_text(value), sev, note)
        return TreeGrid([("Source", str), ("Parameter", str), ("Value", str), ("Severity", str), ("Note", str)], rows())

    def run(self):
        src = self.ctx.live
        if src.is_windows:
            return self._windows(src)
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


MAX_LOG = 256 << 20  # decompressed size accepted for a log file / bug report


def time_note(e) -> str:
    """Say how an Xid event's time was obtained when the log line did not fully specify it."""
    raw = e.get("raw", "")
    if not e.get("time"):
        return ""
    if xid_ind.SYSLOG_TS_RE.match(raw):
        return ("syslog time has no year or zone: year from the log's modification time / report date; shown as "
                "logged (the logging host's local time, zone unknown)")
    m = xid_ind.ISO_TS_RE.match(raw)
    if m and not m.group(3):
        return "log time has no UTC offset: shown as logged (the logging host's local time, zone unknown)"
    return ""


def event_time(e) -> str:
    """An Xid event's time as text: ISO UTC, or boot-relative when only the dmesg offset is known."""
    if e.get("time"):
        return e["time"].isoformat()
    m = xid_ind.DMESG_TS_RE.match(e.get("raw", ""))
    return "boot+%ss" % m.group(1) if m else "no timestamp"


def _open_log(path: str) -> List[str]:
    """Lines of a plain or gzip-compressed log, decompressed incrementally with a size limit (a gzip bomb stops at
    MAX_LOG). Missing/unreadable files raise RequirementError, damaged or oversized ones FormatError."""
    try:
        with open(path, "rb") as fh:
            gz = fh.read(2) == b"\x1f\x8b"
            fh.seek(0)
            if gz:
                with gzip.GzipFile(fileobj=fh) as g:
                    raw = g.read(MAX_LOG + 1)
            else:
                raw = fh.read(MAX_LOG + 1)
    except (EOFError, zlib.error, gzip.BadGzipFile) as exc:
        raise FormatError("%s is not a valid or complete gzip file (%s)" % (path, exc))
    except OSError as exc:
        raise RequirementError("cannot read %s: %s" % (path, exc.strerror or exc))
    if len(raw) > MAX_LOG:
        raise FormatError("%s is larger than %d MiB%s; split it or extract the relevant part"
                          % (path, MAX_LOG >> 20, " when decompressed" if gz else ""))
    return raw.decode("utf-8", "replace").splitlines()


class Xid(Plugin, TimeLinerInterface):
    NAME = "nvidia.xid"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Decodes NVIDIA Xid error events from the kernel log (GPU page faults with faulting VA and "
                   "access type, engine exceptions, falling off the bus, ECC events...) with time, PID and process.")
    METHOD = ("Parses 'NVRM: Xid (PCI:...): <code>, pid=..., name=..., <message>' lines from journalctl -k "
              "(-o short-iso) or dmesg (boot-relative time converted with /proc/stat btime), or from --log-file "
              "(plain or .gz, decompressed with a 256 MiB limit); codes are named from the built-in Xid catalogue. "
              "Syslog lines carry no year: it is taken from the log file's modification time (a date after it "
              "belongs to the previous year). Times without a UTC offset are taken as UTC and say so in the "
              "Forensic note.")
    ANALOG = "linux.kmsg / windows.crashinfo"
    SOURCES = ("file",)
    REQUIREMENTS = [Requirement("log_file", str, None, "kernel log / syslog / dmesg capture to parse instead of the "
                                                        "live system"),
                    Requirement("code", int, None, "only this Xid code")]

    @staticmethod
    def _file_events(path):
        lines = _open_log(path)
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            mtime = None
        year = _dt.datetime.fromtimestamp(mtime, tz=_dt.timezone.utc).year if mtime else None
        events = xid_ind.parse_log(lines, None, year)
        for e in events:
            if e["time"] and mtime and xid_ind.SYSLOG_TS_RE.match(e["raw"]) and e["time"].timestamp() > mtime + 86400:
                try:
                    e["time"] = e["time"].replace(year=e["time"].year - 1)  # Dec entries in a January-modified log
                except ValueError:
                    pass
        return events

    def _events(self):
        if self.opts.get("log_file"):
            return self._file_events(self.opts["log_file"]), "file %s" % self.opts["log_file"]
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
                note = "; ".join(x for x in (e["forensic"], time_note(e)) if x)
                yield 0, (e["time"] or na("no timestamp"), e["pci"], e["code"],
                          e["name"] + ("" if e["certain"] else " (?)"), e["pid"] if e["pid"] is not None else na("-"),
                          e["process"], e["details"], note)
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
    METHOD = ("Reads the (optionally gzip-compressed, 256 MiB limit) report; parses 'NVRM version', 'uname', "
              "nvidia-smi -q 'Product Name / GPU UUID / VBIOS Version' blocks, '*** <section>' headers and Xid lines "
              "with the Xid decoder (syslog dates take the year of the report's start line; dmesg times without "
              "the boot time are shown boot-relative).")
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
            started = first(r"Start of NVIDIA bug report log file\.\s*(.*)$") or ""
            year = re.search(r"\b(\d{4})\s*$", started)
            for e in xid_ind.parse_log(lines, None, int(year.group(1)) if year else None):
                yield 0, ("xid", "Xid %d %s" % (e["code"], e["name"]), "time=%s pid=%s %s %s" % (
                    event_time(e), e["pid"] if e["pid"] is not None else "-", e["process"], e["details"]))
            sections = [l[4:].strip() for l in lines if l.startswith("*** ")]
            yield 0, ("report", "sections", "%d: %s" % (len(sections), "; ".join(sections[:40])))
        return TreeGrid([("Category", str), ("Item", str), ("Value", str)], rows())


__all__ = ["Devices", "Engines", "Ecc", "DeviceTree", "NvLink", "Mig", "Driver", "Modules", "DevNodes", "Params",
           "Xid", "BugReport"]
