"""NVML (NVIDIA Management Library) through ctypes, plus a full state collector.

``collect()`` returns one JSON-serialisable dictionary describing every GPU:
identity, firmware, memory, clocks, power, ECC, retired pages, processes,
encoder / frame-buffer-capture sessions, accounting history, NVLink and P2P.
Every query is independent: an unsupported query (common under WDDM/WSL and on
consumer boards) is recorded as ``{"_na": "<reason>"}`` and collection goes on.
"""

from __future__ import annotations

import ctypes
import os
import sys
from typing import Any, Dict, List, Optional

NVML_SUCCESS = 0
NVML_ERROR_INSUFFICIENT_SIZE = 7
NVML_VALUE_NOT_AVAILABLE = 0xFFFFFFFFFFFFFFFF

ARCH_NAMES = {2: "Kepler", 3: "Maxwell", 4: "Pascal", 5: "Volta", 6: "Turing", 7: "Ampere", 8: "Ada",
              9: "Hopper", 10: "Blackwell"}
BRAND_NAMES = {0: "Unknown", 1: "Quadro", 2: "Tesla", 3: "NVS", 4: "GRID", 5: "GeForce", 6: "Titan",
               7: "vApps", 8: "vPC", 9: "vCS", 10: "vWS", 11: "Cloud Gaming", 12: "Quadro RTX", 13: "NVIDIA RTX",
               14: "NVIDIA", 15: "GeForce RTX", 16: "Titan RTX"}
COMPUTE_MODES = {0: "Default", 1: "Exclusive_Thread", 2: "Prohibited", 3: "Exclusive_Process"}
DRIVER_MODELS = {0: "WDDM", 1: "TCC", 2: "MCDM"}
CODECS = {0: "H264", 1: "HEVC", 2: "AV1"}
FBC_TYPES = {0: "UNKNOWN", 1: "TOSYS", 2: "CUDA", 3: "VID", 4: "HWENC"}
THROTTLE_REASONS = {0x1: "GpuIdle", 0x2: "ApplicationsClocksSetting", 0x4: "SwPowerCap", 0x8: "HwSlowdown",
                    0x10: "SyncBoost", 0x20: "SwThermalSlowdown", 0x40: "HwThermalSlowdown",
                    0x80: "HwPowerBrakeSlowdown", 0x100: "DisplayClockSetting"}
CLOCKS = {"graphics": 0, "sm": 1, "memory": 2, "video": 3}
P2P_CAPS = {"read": 0, "write": 1, "nvlink": 2, "atomics": 3}


class PciInfo(ctypes.Structure):
    _fields_ = [("busIdLegacy", ctypes.c_char * 16), ("domain", ctypes.c_uint), ("bus", ctypes.c_uint),
                ("device", ctypes.c_uint), ("pciDeviceId", ctypes.c_uint), ("pciSubSystemId", ctypes.c_uint),
                ("busId", ctypes.c_char * 32)]


class Memory(ctypes.Structure):
    _fields_ = [("total", ctypes.c_ulonglong), ("free", ctypes.c_ulonglong), ("used", ctypes.c_ulonglong)]


class Memory_v2(ctypes.Structure):
    """nvmlMemory_v2_t: ``used`` excludes the driver/firmware-reserved framebuffer, which v1 counts as used."""
    _fields_ = [("version", ctypes.c_uint), ("total", ctypes.c_ulonglong), ("reserved", ctypes.c_ulonglong),
                ("free", ctypes.c_ulonglong), ("used", ctypes.c_ulonglong)]


MEMORY_V2_VERSION = ctypes.sizeof(Memory_v2) | (2 << 24)  # NVML_STRUCT_VERSION(Memory, 2)


class Bar1Memory(ctypes.Structure):
    _fields_ = [("bar1Total", ctypes.c_ulonglong), ("bar1Free", ctypes.c_ulonglong), ("bar1Used", ctypes.c_ulonglong)]


class ProcessInfo(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint), ("usedGpuMemory", ctypes.c_ulonglong), ("gpuInstanceId", ctypes.c_uint),
                ("computeInstanceId", ctypes.c_uint)]


class Utilization(ctypes.Structure):
    _fields_ = [("gpu", ctypes.c_uint), ("memory", ctypes.c_uint)]


class EncoderSession(ctypes.Structure):
    _fields_ = [("sessionId", ctypes.c_uint), ("pid", ctypes.c_uint), ("vgpuInstance", ctypes.c_uint),
                ("codecType", ctypes.c_int), ("hResolution", ctypes.c_uint), ("vResolution", ctypes.c_uint),
                ("averageFps", ctypes.c_uint), ("averageLatency", ctypes.c_uint)]


class FBCSession(ctypes.Structure):
    _fields_ = [("sessionId", ctypes.c_uint), ("pid", ctypes.c_uint), ("vgpuInstance", ctypes.c_uint),
                ("displayOrdinal", ctypes.c_uint), ("sessionType", ctypes.c_int), ("sessionFlags", ctypes.c_uint),
                ("hMaxResolution", ctypes.c_uint), ("vMaxResolution", ctypes.c_uint), ("hResolution", ctypes.c_uint),
                ("vResolution", ctypes.c_uint), ("averageFPS", ctypes.c_uint), ("averageLatency", ctypes.c_uint)]


class FBCStats(ctypes.Structure):
    _fields_ = [("sessionsCount", ctypes.c_uint), ("averageFPS", ctypes.c_uint), ("averageLatency", ctypes.c_uint)]


class AccountingStats(ctypes.Structure):
    _fields_ = [("gpuUtilization", ctypes.c_uint), ("memoryUtilization", ctypes.c_uint),
                ("maxMemoryUsage", ctypes.c_ulonglong), ("time", ctypes.c_ulonglong),
                ("startTime", ctypes.c_ulonglong), ("isRunning", ctypes.c_uint), ("reserved", ctypes.c_uint * 5)]


class ProcessUtilSample(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint), ("timeStamp", ctypes.c_ulonglong), ("smUtil", ctypes.c_uint),
                ("memUtil", ctypes.c_uint), ("encUtil", ctypes.c_uint), ("decUtil", ctypes.c_uint)]


def na(reason: str) -> Dict[str, str]:
    return {"_na": reason}


def is_na(value) -> bool:
    return isinstance(value, dict) and "_na" in value


def _library_candidates() -> List[str]:
    if sys.platform.startswith("win"):
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        return [os.path.join(sysroot, "System32", "nvml.dll"),
                os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "NVIDIA Corporation", "NVSMI",
                             "nvml.dll")]
    return ["libnvidia-ml.so.1", "/usr/lib/wsl/lib/libnvidia-ml.so.1", "libnvidia-ml.so"]


class NVML:
    def __init__(self, lib_path: Optional[str] = None):
        self.lib = None
        self.error: Optional[str] = None
        for cand in ([lib_path] if lib_path else _library_candidates()):
            try:
                self.lib = ctypes.CDLL(cand)
                self.path = cand
                break
            except OSError as exc:
                self.error = "cannot load %s: %s" % (cand, exc)
        if self.lib is None:
            return
        rc = self._fn("nvmlInit_v2")() if hasattr(self.lib, "nvmlInit_v2") else self._fn("nvmlInit")()
        if rc != NVML_SUCCESS:
            self.error = "nvmlInit failed: %s" % self.err(rc)
            self.lib = None

    @property
    def available(self) -> bool:
        return self.lib is not None

    def _fn(self, name):
        return getattr(self.lib, name)

    def err(self, rc: int) -> str:
        try:
            f = self.lib.nvmlErrorString
            f.restype = ctypes.c_char_p
            return f(rc).decode()
        except Exception:
            return "NVML error %d" % rc

    def call(self, name: str, *args):
        """Call an NVML function; return None on success or an ``na`` dict."""
        if not hasattr(self.lib, name):
            return na("function %s not in this NVML" % name)
        rc = getattr(self.lib, name)(*args)
        return None if rc == NVML_SUCCESS else na(self.err(rc))

    def shutdown(self):
        if self.lib is not None:
            self.lib.nvmlShutdown()

    # -- typed helpers ------------------------------------------------------------
    def _str(self, name, *args, size=96):
        buf = ctypes.create_string_buffer(size)
        e = self.call(name, *args, buf, ctypes.c_uint(size))
        return e if e else buf.value.decode("utf-8", "replace")

    def _uint(self, name, *args):
        v = ctypes.c_uint()
        e = self.call(name, *args, ctypes.byref(v))
        return e if e else v.value

    def _ull(self, name, *args):
        v = ctypes.c_ulonglong()
        e = self.call(name, *args, ctypes.byref(v))
        return e if e else v.value

    def _pair(self, name, *args):
        a, b = ctypes.c_uint(), ctypes.c_uint()
        e = self.call(name, *args, ctypes.byref(a), ctypes.byref(b))
        return e if e else (a.value, b.value)


def _decode_bits(value, table):
    if is_na(value):
        return value
    return [n for bit, n in table.items() if value & bit]


def _processes(nv: NVML, h, kind: str):
    names = ["nvmlDevice%sRunningProcesses_v3" % kind, "nvmlDevice%sRunningProcesses_v2" % kind]
    fname = next((n for n in names if hasattr(nv.lib, n)), None)
    if fname is None:
        return na("not supported by this NVML")
    count = ctypes.c_uint(0)
    rc = getattr(nv.lib, fname)(h, ctypes.byref(count), None)
    if rc not in (NVML_SUCCESS, NVML_ERROR_INSUFFICIENT_SIZE):
        return na(nv.err(rc))
    n = max(count.value, 1) + 8
    arr = (ProcessInfo * n)()
    count = ctypes.c_uint(n)
    e = nv.call(fname, h, ctypes.byref(count), arr)
    if e:
        return e
    out = []
    for i in range(count.value):
        p = arr[i]
        mem = p.usedGpuMemory
        out.append({"pid": p.pid, "used_memory": None if mem == NVML_VALUE_NOT_AVAILABLE else mem,
                    "gpu_instance": None if p.gpuInstanceId == 0xFFFFFFFF else p.gpuInstanceId,
                    "compute_instance": None if p.computeInstanceId == 0xFFFFFFFF else p.computeInstanceId})
    return out


def _sessions(nv: NVML, h, fname, struct_t, conv):
    count = ctypes.c_uint(0)
    if not hasattr(nv.lib, fname):
        return na("not supported by this NVML")
    rc = getattr(nv.lib, fname)(h, ctypes.byref(count), None)
    if rc not in (NVML_SUCCESS, NVML_ERROR_INSUFFICIENT_SIZE):
        return na(nv.err(rc))
    if count.value == 0:
        return []
    arr = (struct_t * count.value)()
    e = nv.call(fname, h, ctypes.byref(count), arr)
    return e if e else [conv(arr[i]) for i in range(count.value)]


def _device(nv: NVML, index: int, h, all_handles) -> Dict[str, Any]:
    d: Dict[str, Any] = {"index": index}
    d["name"] = nv._str("nvmlDeviceGetName", h)
    d["uuid"] = nv._str("nvmlDeviceGetUUID", h)
    d["serial"] = nv._str("nvmlDeviceGetSerial", h)
    d["board_part_number"] = nv._str("nvmlDeviceGetBoardPartNumber", h)
    d["vbios_version"] = nv._str("nvmlDeviceGetVbiosVersion", h)
    d["inforom_image"] = nv._str("nvmlDeviceGetInforomImageVersion", h)
    d["minor_number"] = nv._uint("nvmlDeviceGetMinorNumber", h)
    arch = nv._uint("nvmlDeviceGetArchitecture", h)
    d["architecture"] = arch if is_na(arch) else {"id": arch, "name": ARCH_NAMES.get(arch, "arch%d" % arch)}
    brand = nv._uint("nvmlDeviceGetBrand", h)
    d["brand"] = brand if is_na(brand) else BRAND_NAMES.get(brand, str(brand))
    cc = nv._pair("nvmlDeviceGetCudaComputeCapability", h)
    d["compute_capability"] = cc if is_na(cc) else "%d.%d" % cc
    pci = PciInfo()
    e = nv.call("nvmlDeviceGetPciInfo_v3", h, ctypes.byref(pci))
    d["pci"] = e if e else {"bus_id": pci.busId.decode(), "domain": pci.domain, "bus": pci.bus, "device": pci.device,
                            "device_id": "0x%08x" % pci.pciDeviceId, "subsystem_id": "0x%08x" % pci.pciSubSystemId}
    m2 = Memory_v2()
    m2.version = MEMORY_V2_VERSION
    if hasattr(nv.lib, "nvmlDeviceGetMemoryInfo_v2") and not nv.call("nvmlDeviceGetMemoryInfo_v2", h, ctypes.byref(m2)):
        d["memory"] = {"total": m2.total, "free": m2.free, "used": m2.used, "reserved": m2.reserved}
    else:
        mem = Memory()
        e = nv.call("nvmlDeviceGetMemoryInfo", h, ctypes.byref(mem))
        d["memory"] = e if e else {"total": mem.total, "free": mem.free, "used": mem.used}
    bar1 = Bar1Memory()
    e = nv.call("nvmlDeviceGetBAR1MemoryInfo", h, ctypes.byref(bar1))
    d["bar1"] = e if e else {"total": bar1.bar1Total, "free": bar1.bar1Free, "used": bar1.bar1Used}
    for key, fn in (("persistence_mode", "nvmlDeviceGetPersistenceMode"), ("display_mode", "nvmlDeviceGetDisplayMode"),
                    ("display_active", "nvmlDeviceGetDisplayActive"), ("pstate", "nvmlDeviceGetPerformanceState"),
                    ("fan_percent", "nvmlDeviceGetFanSpeed"), ("power_mw", "nvmlDeviceGetPowerUsage"),
                    ("power_limit_mw", "nvmlDeviceGetEnforcedPowerLimit"),
                    ("accounting_mode", "nvmlDeviceGetAccountingMode"),
                    ("pcie_gen", "nvmlDeviceGetCurrPcieLinkGeneration"),
                    ("pcie_width", "nvmlDeviceGetCurrPcieLinkWidth"),
                    ("pcie_max_gen", "nvmlDeviceGetMaxPcieLinkGeneration"),
                    ("pcie_max_width", "nvmlDeviceGetMaxPcieLinkWidth"),
                    ("pcie_replay_counter", "nvmlDeviceGetPcieReplayCounter")):
        d[key] = nv._uint(fn, h)
    t = ctypes.c_uint()
    e = nv.call("nvmlDeviceGetTemperature", h, ctypes.c_int(0), ctypes.byref(t))
    d["temperature_c"] = e if e else t.value
    cm = nv._uint("nvmlDeviceGetComputeMode", h)
    d["compute_mode"] = cm if is_na(cm) else COMPUTE_MODES.get(cm, str(cm))
    dm = nv._pair("nvmlDeviceGetDriverModel", h)
    d["driver_model"] = dm if is_na(dm) else {"current": DRIVER_MODELS.get(dm[0], dm[0]),
                                                "pending": DRIVER_MODELS.get(dm[1], dm[1])}
    mig = nv._pair("nvmlDeviceGetMigMode", h)
    d["mig_mode"] = mig if is_na(mig) else {"current": mig[0], "pending": mig[1]}
    d["clocks_mhz"] = {}
    d["max_clocks_mhz"] = {}
    for name, cid in CLOCKS.items():
        d["clocks_mhz"][name] = nv._uint("nvmlDeviceGetClockInfo", h, ctypes.c_int(cid))
        d["max_clocks_mhz"][name] = nv._uint("nvmlDeviceGetMaxClockInfo", h, ctypes.c_int(cid))
    fn = "nvmlDeviceGetCurrentClocksEventReasons" if hasattr(nv.lib, "nvmlDeviceGetCurrentClocksEventReasons") \
        else "nvmlDeviceGetCurrentClocksThrottleReasons"
    reasons = nv._ull(fn, h)
    d["throttle_reasons"] = reasons if is_na(reasons) else {"mask": reasons,
                                                              "decoded": _decode_bits(reasons, THROTTLE_REASONS)}
    u = Utilization()
    e = nv.call("nvmlDeviceGetUtilizationRates", h, ctypes.byref(u))
    d["utilization"] = e if e else {"gpu": u.gpu, "memory": u.memory}
    for key, fn in (("encoder_utilization", "nvmlDeviceGetEncoderUtilization"),
                    ("decoder_utilization", "nvmlDeviceGetDecoderUtilization"),
                    ("jpg_utilization", "nvmlDeviceGetJpgUtilization"),
                    ("ofa_utilization", "nvmlDeviceGetOfaUtilization")):
        p = nv._pair(fn, h)
        d[key] = p if is_na(p) else {"percent": p[0], "sampling_us": p[1]}
    for key, counter in (("pcie_tx_kbps", 0), ("pcie_rx_kbps", 1)):
        v = ctypes.c_uint()
        e = nv.call("nvmlDeviceGetPcieThroughput", h, ctypes.c_int(counter), ctypes.byref(v))
        d[key] = e if e else v.value
    # ECC
    ecc = nv._pair("nvmlDeviceGetEccMode", h)
    d["ecc_mode"] = ecc if is_na(ecc) else {"current": ecc[0], "pending": ecc[1]}
    errs = {}
    for etype, ename in ((0, "corrected"), (1, "uncorrected")):
        for ctype, cname in ((0, "volatile"), (1, "aggregate")):
            v = ctypes.c_ulonglong()
            e = nv.call("nvmlDeviceGetTotalEccErrors", h, ctypes.c_int(etype), ctypes.c_int(ctype), ctypes.byref(v))
            errs["%s_%s" % (cname, ename)] = e if e else v.value
    d["ecc_errors"] = errs
    retired = {}
    for cause, cname in ((0, "multiple_sbe"), (1, "dbe")):
        cnt = ctypes.c_uint(0)
        rc = nv.lib.nvmlDeviceGetRetiredPages(h, ctypes.c_int(cause), ctypes.byref(cnt), None) \
            if hasattr(nv.lib, "nvmlDeviceGetRetiredPages") else -1
        if rc in (NVML_SUCCESS, NVML_ERROR_INSUFFICIENT_SIZE) and cnt.value:
            arr = (ctypes.c_ulonglong * cnt.value)()
            e = nv.call("nvmlDeviceGetRetiredPages", h, ctypes.c_int(cause), ctypes.byref(cnt), arr)
            retired[cname] = e if e else [arr[i] for i in range(cnt.value)]
        else:
            retired[cname] = [] if rc in (NVML_SUCCESS, NVML_ERROR_INSUFFICIENT_SIZE) else na(nv.err(rc) if rc >= 0
                                                                                              else "not supported")
    d["retired_pages"] = retired
    rr = [ctypes.c_uint() for _ in range(4)]
    e = nv.call("nvmlDeviceGetRemappedRows", h, *[ctypes.byref(x) for x in rr])
    d["remapped_rows"] = e if e else {"correctable": rr[0].value, "uncorrectable": rr[1].value,
                                      "pending": rr[2].value, "failure": rr[3].value}
    # processes and sessions
    d["compute_processes"] = _processes(nv, h, "GetCompute")
    d["graphics_processes"] = _processes(nv, h, "GetGraphics")
    d["mps_compute_processes"] = _processes(nv, h, "GetMPSCompute")
    d["encoder_sessions"] = _sessions(nv, h, "nvmlDeviceGetEncoderSessions", EncoderSession, lambda s: {
        "session_id": s.sessionId, "pid": s.pid, "codec": CODECS.get(s.codecType, s.codecType),
        "resolution": "%dx%d" % (s.hResolution, s.vResolution), "avg_fps": s.averageFps,
        "avg_latency_us": s.averageLatency})
    d["fbc_sessions"] = _sessions(nv, h, "nvmlDeviceGetFBCSessions", FBCSession, lambda s: {
        "session_id": s.sessionId, "pid": s.pid, "display": s.displayOrdinal,
        "type": FBC_TYPES.get(s.sessionType, s.sessionType), "flags": s.sessionFlags,
        "resolution": "%dx%d" % (s.hResolution, s.vResolution),
        "max_resolution": "%dx%d" % (s.hMaxResolution, s.vMaxResolution), "avg_fps": s.averageFPS,
        "avg_latency_us": s.averageLatency})
    fs = FBCStats()
    e = nv.call("nvmlDeviceGetFBCStats", h, ctypes.byref(fs))
    d["fbc_stats"] = e if e else {"sessions": fs.sessionsCount, "avg_fps": fs.averageFPS,
                                  "avg_latency_us": fs.averageLatency}
    a, b, c = ctypes.c_uint(), ctypes.c_uint(), ctypes.c_uint()
    e = nv.call("nvmlDeviceGetEncoderStats", h, ctypes.byref(a), ctypes.byref(b), ctypes.byref(c))
    d["encoder_stats"] = e if e else {"sessions": a.value, "avg_fps": b.value, "avg_latency_us": c.value}
    # accounting (per-process history, survives process exit while the buffer holds it)
    acc: Dict[str, Any] = {}
    cnt = ctypes.c_uint(0)
    rc = nv.lib.nvmlDeviceGetAccountingPids(h, ctypes.byref(cnt), None) \
        if hasattr(nv.lib, "nvmlDeviceGetAccountingPids") else -1
    if rc in (NVML_SUCCESS, NVML_ERROR_INSUFFICIENT_SIZE):
        pids = (ctypes.c_uint * max(cnt.value, 1))()
        e = nv.call("nvmlDeviceGetAccountingPids", h, ctypes.byref(cnt), pids)
        if e:
            acc = e
        else:
            for i in range(cnt.value):
                st = AccountingStats()
                e2 = nv.call("nvmlDeviceGetAccountingStats", h, ctypes.c_uint(pids[i]), ctypes.byref(st))
                acc[str(pids[i])] = e2 if e2 else {
                    "gpu_util": st.gpuUtilization, "mem_util": st.memoryUtilization,
                    "max_memory": None if st.maxMemoryUsage == NVML_VALUE_NOT_AVAILABLE else st.maxMemoryUsage,
                    "time_ms": st.time, "start_time_us": st.startTime, "running": bool(st.isRunning)}
    else:
        acc = na(nv.err(rc) if rc >= 0 else "not supported")
    d["accounting"] = acc
    # per-process utilisation samples
    cnt = ctypes.c_uint(0)
    rc = nv.lib.nvmlDeviceGetProcessUtilization(h, None, ctypes.byref(cnt), ctypes.c_ulonglong(0)) \
        if hasattr(nv.lib, "nvmlDeviceGetProcessUtilization") else -1
    if rc in (NVML_SUCCESS, NVML_ERROR_INSUFFICIENT_SIZE) and cnt.value:
        arr = (ProcessUtilSample * cnt.value)()
        e = nv.call("nvmlDeviceGetProcessUtilization", h, arr, ctypes.byref(cnt), ctypes.c_ulonglong(0))
        d["process_utilization"] = e if e else [
            {"pid": s.pid, "timestamp_us": s.timeStamp, "sm": s.smUtil, "mem": s.memUtil, "enc": s.encUtil,
             "dec": s.decUtil} for s in arr[:cnt.value]]
    else:
        d["process_utilization"] = [] if rc in (NVML_SUCCESS, NVML_ERROR_INSUFFICIENT_SIZE) else na(
            nv.err(rc) if rc >= 0 else "not supported")
    # NVLink
    links = []
    for link in range(18):
        st = ctypes.c_int()
        e = nv.call("nvmlDeviceGetNvLinkState", h, ctypes.c_uint(link), ctypes.byref(st))
        if e:
            if link == 0:
                links = e
            break
        info = {"link": link, "active": bool(st.value)}
        ver = ctypes.c_uint()
        if not nv.call("nvmlDeviceGetNvLinkVersion", h, ctypes.c_uint(link), ctypes.byref(ver)):
            info["version"] = ver.value
        rp = PciInfo()
        if not nv.call("nvmlDeviceGetNvLinkRemotePciInfo_v2", h, ctypes.c_uint(link), ctypes.byref(rp)):
            info["remote_bus_id"] = rp.busId.decode()
        links.append(info)
    d["nvlink"] = links
    p2p = {}
    for j, other in enumerate(all_handles):
        if j == index:
            continue
        caps = {}
        for cname, cidx in P2P_CAPS.items():
            st = ctypes.c_int()
            e = nv.call("nvmlDeviceGetP2PStatus", h, other, ctypes.c_int(cidx), ctypes.byref(st))
            caps[cname] = e if e else ("OK" if st.value == 0 else "status%d" % st.value)
        p2p[str(j)] = caps
    d["p2p"] = p2p
    return d


def collect(lib_path: Optional[str] = None) -> Dict[str, Any]:
    nv = NVML(lib_path)
    if not nv.available:
        return {"available": False, "error": nv.error, "devices": []}
    out: Dict[str, Any] = {"available": True, "library": nv.path}
    out["driver_version"] = nv._str("nvmlSystemGetDriverVersion")
    out["nvml_version"] = nv._str("nvmlSystemGetNVMLVersion")
    v = ctypes.c_int()
    fn = "nvmlSystemGetCudaDriverVersion_v2" if hasattr(nv.lib, "nvmlSystemGetCudaDriverVersion_v2") \
        else "nvmlSystemGetCudaDriverVersion"
    e = nv.call(fn, ctypes.byref(v))
    out["cuda_driver_version"] = e if e else "%d.%d" % (v.value // 1000, (v.value % 1000) // 10)
    count = ctypes.c_uint()
    e = nv.call("nvmlDeviceGetCount_v2", ctypes.byref(count))
    if e:
        out["devices"] = []
        out["error"] = e["_na"]
        nv.shutdown()
        return out
    handles = []
    for i in range(count.value):
        h = ctypes.c_void_p()
        nv.call("nvmlDeviceGetHandleByIndex_v2", ctypes.c_uint(i), ctypes.byref(h))
        handles.append(h)
    out["devices"] = []
    for i, h in enumerate(handles):
        try:
            out["devices"].append(_device(nv, i, h, handles))
        except Exception as exc:  # a broken query must not lose the other devices
            out["devices"].append({"index": i, "_error": repr(exc)})
    nv.shutdown()
    return out
