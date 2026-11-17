"""Windows live data through ctypes (stdlib only): processes, loaded modules, visible windows and per-process
GPU use from the performance counters the Windows graphics kernel publishes.

* Processes / modules: ``CreateToolhelp32Snapshot`` (TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE|SNAPMODULE32),
  ``QueryFullProcessImageNameW``.
* Windows: ``EnumWindows`` + ``GetWindowThreadProcessId`` + ``IsWindowVisible``.
* GPU use: PDH counters ``\\GPU Engine(*)\\Utilization Percentage`` (instances
  ``pid_<pid>_luid_<hi>_<lo>_phys_<n>_eng_<n>_engtype_<type>``) and
  ``\\GPU Process Memory(*)\\Dedicated Usage`` / ``Shared Usage`` (instances ``pid_<pid>_luid_..._phys_<n>``).

Everything is read-only. Functions return plain JSON-serialisable data so a RecordingSource can snapshot it.
"""

from __future__ import annotations

import ctypes
import re
import time
from ctypes import wintypes
from typing import Dict, List, Optional

TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32 = 0x2, 0x8, 0x10
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PDH_FMT_DOUBLE, PDH_FMT_LARGE = 0x200, 0x400
PDH_MORE_DATA = 0x800007D2
ENGINE_RE = re.compile(r"pid_(\d+)_luid_(0x[0-9A-Fa-f]+)_(0x[0-9A-Fa-f]+)_phys_(\d+)_eng_(\d+)_engtype_(.*)$")
PROCMEM_RE = re.compile(r"pid_(\d+)_luid_(0x[0-9A-Fa-f]+)_(0x[0-9A-Fa-f]+)_phys_(\d+)$")


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD), ("ProccntUsage", wintypes.DWORD),
                ("modBaseAddr", ctypes.c_void_p), ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HMODULE),
                ("szModule", ctypes.c_wchar * 256), ("szExePath", ctypes.c_wchar * 260)]


class PDH_FMT_COUNTERVALUE(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("longValue", ctypes.c_long), ("doubleValue", ctypes.c_double), ("largeValue", ctypes.c_longlong)]
    _fields_ = [("CStatus", wintypes.DWORD), ("u", _U)]


class PDH_FMT_COUNTERVALUE_ITEM_W(ctypes.Structure):
    _fields_ = [("szName", ctypes.c_wchar_p), ("FmtValue", PDH_FMT_COUNTERVALUE)]


def _k32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k.Process32FirstW.argtypes = k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.Module32FirstW.argtypes = k.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    k.OpenProcess.restype = wintypes.HANDLE
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                             ctypes.POINTER(wintypes.DWORD)]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    return k


def processes() -> List[dict]:
    """``[{pid, ppid, name, path, threads}]`` for every process."""
    k = _k32()
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (None, INVALID_HANDLE_VALUE):
        return []
    out = []
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        ok = k.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            out.append({"pid": e.th32ProcessID, "ppid": e.th32ParentProcessID, "name": e.szExeFile,
                        "threads": e.cntThreads, "path": image_path(k, e.th32ProcessID)})
            ok = k.Process32NextW(snap, ctypes.byref(e))
    finally:
        k.CloseHandle(snap)
    return out


def image_path(k, pid: int) -> Optional[str]:
    h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        n = wintypes.DWORD(len(buf))
        return buf.value if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else None
    finally:
        k.CloseHandle(h)


def modules(pid: int) -> Optional[List[dict]]:
    """Loaded modules of ``pid`` (None when access is denied, e.g. protected processes)."""
    k = _k32()
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap in (None, INVALID_HANDLE_VALUE):
        return None
    out = []
    try:
        e = MODULEENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        ok = k.Module32FirstW(snap, ctypes.byref(e))
        while ok:
            out.append({"name": e.szModule, "path": e.szExePath, "base": e.modBaseAddr or 0, "size": e.modBaseSize})
            ok = k.Module32NextW(snap, ctypes.byref(e))
    finally:
        k.CloseHandle(snap)
    return out


def windowed_pids() -> List[int]:
    """PIDs owning at least one visible top-level window."""
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    pids = set()
    proto = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.IsWindowVisible.argtypes = [wintypes.HWND]

    def cb(hwnd, _lp):
        if user32.IsWindowVisible(hwnd):
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pids.add(pid.value)
        return True

    user32.EnumWindows(proto(cb), 0)
    return sorted(pids)


def _pdh():
    pdh = ctypes.WinDLL("pdh")
    pdh.PdhOpenQueryW.argtypes = [wintypes.LPCWSTR, ctypes.c_size_t, ctypes.POINTER(wintypes.HANDLE)]
    pdh.PdhAddEnglishCounterW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_size_t,
                                          ctypes.POINTER(wintypes.HANDLE)]
    pdh.PdhCollectQueryData.argtypes = [wintypes.HANDLE]
    pdh.PdhGetFormattedCounterArrayW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                                 ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    pdh.PdhCloseQuery.argtypes = [wintypes.HANDLE]
    for fn in ("PdhOpenQueryW", "PdhAddEnglishCounterW", "PdhCollectQueryData", "PdhGetFormattedCounterArrayW",
               "PdhCloseQuery"):
        getattr(pdh, fn).restype = wintypes.DWORD
    return pdh


def _array(pdh, counter, fmt) -> Dict[str, float]:
    size, count = wintypes.DWORD(0), wintypes.DWORD(0)
    st = pdh.PdhGetFormattedCounterArrayW(counter, fmt, ctypes.byref(size), ctypes.byref(count), None)
    if st != PDH_MORE_DATA or not size.value:
        return {}
    buf = (ctypes.c_byte * size.value)()
    if pdh.PdhGetFormattedCounterArrayW(counter, fmt, ctypes.byref(size), ctypes.byref(count), buf):
        return {}
    items = ctypes.cast(buf, ctypes.POINTER(PDH_FMT_COUNTERVALUE_ITEM_W))
    out = {}
    for i in range(count.value):
        it = items[i]
        if it.FmtValue.CStatus in (0, 1):  # PDH_CSTATUS_VALID_DATA / NEW_DATA
            out[it.szName] = it.FmtValue.u.doubleValue if fmt == PDH_FMT_DOUBLE else it.FmtValue.u.largeValue
    return out


def gpu_counters(sample_seconds: float = 0.5) -> dict:
    """Per-process GPU engine utilisation and GPU memory from the Windows GPU performance counters."""
    pdh = _pdh()
    q = wintypes.HANDLE()
    if pdh.PdhOpenQueryW(None, 0, ctypes.byref(q)):
        return {"available": False, "error": "PdhOpenQuery failed", "processes": {}}
    try:
        counters = {}
        for key, path in (("util", r"\GPU Engine(*)\Utilization Percentage"),
                          ("dedicated", r"\GPU Process Memory(*)\Dedicated Usage"),
                          ("shared", r"\GPU Process Memory(*)\Shared Usage")):
            c = wintypes.HANDLE()
            if pdh.PdhAddEnglishCounterW(q, path, 0, ctypes.byref(c)) == 0:
                counters[key] = c
        if "util" not in counters:
            return {"available": False, "error": "GPU Engine counters not available", "processes": {}}
        pdh.PdhCollectQueryData(q)
        time.sleep(sample_seconds)  # utilisation is a rate counter: needs two samples
        pdh.PdhCollectQueryData(q)
        procs: Dict[str, dict] = {}
        for inst, val in _array(pdh, counters["util"], PDH_FMT_DOUBLE).items():
            m = ENGINE_RE.match(inst)
            if not m:
                continue
            p = procs.setdefault(m.group(1), {"engines": {}, "luids": [], "dedicated": 0, "shared": 0})
            luid = "%s_%s" % (m.group(2), m.group(3))
            if luid not in p["luids"]:
                p["luids"].append(luid)
            et = m.group(6) or "engine%s" % m.group(5)
            p["engines"][et] = round(max(p["engines"].get(et, 0.0), val), 2)
        for key in ("dedicated", "shared"):
            if key not in counters:
                continue
            for inst, val in _array(pdh, counters[key], PDH_FMT_LARGE).items():
                m = PROCMEM_RE.match(inst)
                if m:
                    p = procs.setdefault(m.group(1), {"engines": {}, "luids": [], "dedicated": 0, "shared": 0})
                    p[key] += int(val)
        return {"available": True, "sample_seconds": sample_seconds, "processes": procs}
    finally:
        pdh.PdhCloseQuery(q)
