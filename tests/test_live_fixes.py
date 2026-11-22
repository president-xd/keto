"""Regression tests for the live-plugin audit fixes (WIN-1..4, DET-2/3/6..10/15, NI-3/4, LNX-2..5, CLI-2/4, DOS-5,
section 11). Windows behaviour runs against keto.testing.fakesys, so it is tested on every platform."""

import copy
import datetime as _dt
import gzip
import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keto.formats.container import ContainerWriter  # noqa: E402
from keto.formats.cubin import build_cubin  # noqa: E402
from keto.framework.context import Context  # noqa: E402
from keto.framework.exceptions import FormatError, LiveSourceError, RequirementError, UnsupportedError  # noqa: E402
from keto.framework.plugin import PLUGINS, load_plugins  # noqa: E402
from keto.framework.treegrid import NotAvailableValue  # noqa: E402
from keto.live import procfs  # noqa: E402
from keto.live.source import NotRecordedError, RecordingSource, ReplaySource, check_command  # noqa: E402
from keto.plugins.nvidia import hostside, live_system  # noqa: E402
from keto.plugins.windows import gpu as wgpu  # noqa: E402
from keto.testing.fakesys import FakeSystemSource, default_scenario  # noqa: E402
from keto.testing.synth import sass_function  # noqa: E402
from tests.test_live_plugins import windows_scenario  # noqa: E402

load_plugins()

ROOT = "C:\\Windows"
SYS = ROOT + "\\System32\\"
STORE = SYS + "DriverStore\\FileRepository\\nvhm.inf_amd64_x\\"
TEMP = "C:\\Users\\u\\AppData\\Local\\Temp\\"
CLS = r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
SVC = r"HKLM\SYSTEM\CurrentControlSet\Services"
PCI = r"HKLM\SYSTEM\CurrentControlSet\Enum\PCI"


def run(name, source, **opts):
    ctx = Context()
    ctx.set_live_source(source)
    return PLUGINS[name](ctx, opts).run().as_dicts()


def nvcuda(path=SYS + "nvcuda.dll", base=0x7FF000000000):
    return {"name": path.rsplit("\\", 1)[-1], "path": path, "base": base, "size": 0x10000}


def win_scenario():
    """windows_scenario() plus everything the Windows code paths of the generic live plugins look at."""
    sc = windows_scenario()
    sc["platform"] = {"system": "Windows", "wsl": False, "self_pid": 4242, "system_root": ROOT}
    w = sc["windows"]
    w["processes"] = [dict(p, start_time=1000.0 + p["pid"]) for p in w["processes"]] + [
        {"pid": 4242, "ppid": 500, "name": "python.exe", "path": "C:\\Python\\python.exe", "start_time": 5000.0},
        {"pid": 1000, "ppid": 500, "name": "svchost.exe", "path": TEMP + "svchost.exe", "start_time": 5000.0},
        {"pid": 1100, "ppid": 500, "name": "nvcontainer.exe", "path": "C:\\Users\\u\\AppData\\Roaming\\nvcontainer.exe",
         "start_time": 5000.0},
        {"pid": 1300, "ppid": 500, "name": "pwsh.exe", "path": "C:\\pwsh\\pwsh.exe", "start_time": 5000.0},
        {"pid": 1200, "ppid": 1300, "name": "deviceQuery.exe", "path": "C:\\cuda\\deviceQuery.exe",
         "start_time": 6000.0},
        {"pid": 1400, "ppid": 500, "name": "raw.exe", "path": "C:\\tools\\raw.exe", "start_time": 5000.0},
        {"pid": 1500, "ppid": 500, "name": "ghost.exe", "path": "C:\\gone\\ghost.exe", "start_time": 5000.0}]
    w["windowed"] = [500, 600, 1300]
    mods = w["modules"]
    mods["4242"] = [nvcuda()]
    mods["1000"] = [nvcuda()]
    mods["1100"] = [nvcuda()]
    mods["1200"] = [nvcuda()]
    mods["1400"] = []
    mods["1500"] = [nvcuda("C:\\gone\\nvcuda.dll")]
    mods["700"].append({"name": "NvFBC64.dll", "path": SYS + "NvFBC64.dll", "base": 0x7FF100000000, "size": 0x1000})
    mods["800"] += [{"name": "cupti64_2024.dll", "path": TEMP + "cupti64_2024.dll", "base": 0x7FF200000000,
                     "size": 0x1000},
                    {"name": "cudart64_12.dll", "path": TEMP + "cudart64_12.dll", "base": 0x7FF300000000,
                     "size": 0x1000}]
    procs = w["gpu"]["processes"]
    for pid in ("4242", "1000", "1100", "1200", "1400", "1500"):
        procs[pid] = {"engines": {"Compute_0": 50.0}, "luids": ["0x0_0x1"], "dedicated": 1 << 20, "shared": 0,
                      "by_luid": {"0x0_0x1": {"dedicated": 1 << 20, "shared": 0}}}
    w["cmdlines"].update({"1200": "deviceQuery.exe", "1000": "svchost.exe -k x", "1100": "nvcontainer.exe",
                          "1400": "raw.exe", "1500": "ghost.exe"})
    w["process_info"] = {
        "600": {"environ": {"Path": SYS}, "image_path_name": ROOT + "\\explorer.exe", "debugged": False},
        "700": {"environ": {}, "image_path_name": TEMP + "ArmouryCrate.exe", "debugged": True},
        "800": {"environ": {"cuda_injection64_path": TEMP + "inj.dll", "SECRET": "x"},
                "image_path_name": "C:\\ProgramData\\xmrig.exe", "debugged": False}}
    w["drivers"] = [{"name": "nvlddmkm.sys", "path": STORE + "nvlddmkm.sys"},
                    {"name": "dxgkrnl.sys", "path": SYS + "drivers\\dxgkrnl.sys"},
                    {"name": "nvmedisk.sys", "path": SYS + "drivers\\nvmedisk.sys"}]
    w["versions"] = {(STORE + "nvlddmkm.sys").lower(): {"file_version": "32.0.16.1091", "company": "NVIDIA Corporation"},
                     (SYS + "drivers\\dxgkrnl.sys").lower(): {"file_version": "10.0", "company": "Microsoft Corporation"},
                     (SYS + "drivers\\nvmedisk.sys").lower(): {"file_version": "10.0", "company": "Microsoft Corporation"}}
    w["signatures"].update({
        (STORE + "nvlddmkm.sys").lower(): {"status": "valid", "signer": "NVIDIA Corporation", "kind": "embedded"},
        (STORE + "nvopencl64.dll").lower(): {"status": "BAD DIGEST (modified after signing)", "signer": None,
                                             "kind": "embedded"},
        (TEMP + "evilflt.sys").lower(): {"status": "unsigned", "signer": None, "kind": "embedded"}})
    w["registry_keys"] = {
        CLS: {"values": {"UpperFilters": ["evilflt"]}},
        CLS + "\\0000": {"values": {"DriverDesc": "NVIDIA GeForce RTX 4050", "ProviderName": "NVIDIA",
                                    "DriverVersion": "32.0.16.1091", "MatchingDeviceId": "pci\\ven_10de&dev_28a1",
                                    "OpenCLDriverName": STORE + "nvopencl64.dll",
                                    "VulkanDriverName": STORE + "nv-vk64.json",
                                    "UserModeDriverName": [STORE + "nvldumdx.dll"],
                                    "DriverSupportModules": ["nvcuda.dll"], "RmProfilingAdminOnly": 0}},
        CLS + "\\Properties": {"error": "access denied", "values": {}},
        SVC + "\\nvlddmkm": {"values": {"Type": 1, "ImagePath": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\"
                                                              "nvhm.inf_amd64_x\\nvlddmkm.sys"}},
        SVC + "\\NVDisplay.ContainerLocalSystem": {"values": {
            "Type": 16, "Start": 2, "ObjectName": "LocalSystem", "DisplayName": "NVIDIA Display Container LS",
            "ImagePath": STORE + "Display.NvContainer\\NVDisplay.Container.exe -s NVDisplay.ContainerLocalSystem"}},
        SVC + "\\nvdimm": {"values": {"Type": 1, "DisplayName": "Microsoft NVDIMM", "ImagePath": "System32\\nvdimm.sys"}},
        SVC + "\\evilflt": {"values": {"Type": 1, "ImagePath": "\\??\\" + TEMP + "evilflt.sys"}},
        r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers": {"values": {"TdrLevel": 0}},
        r"HKLM\SOFTWARE\Khronos\OpenCL\Vendors": {"values": {"C:\\Users\\u\\AppData\\Roaming\\evilcl.dll": 0}},
        r"HKCU\SOFTWARE\Khronos\Vulkan\ImplicitLayers": {"values": {TEMP + "layer.json": 0}},
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList": {"values": {"ProfilesDirectory": "C:\\Users"}},
        PCI + "\\VEN_10DE&DEV_28A1\\4&x&0&0008": {"values": {
            "DeviceDesc": "@oem44.inf,%nv%;NVIDIA GeForce RTX 4050",
            "LocationInformation": "@System32\\drivers\\pci.sys,#65536;PCI bus %1, device %2, function %3;(1,0,0)",
            "Service": "nvlddmkm", "Driver": "{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
            "HardwareID": ["PCI\\VEN_10DE&DEV_28A1"]}}}
    cache_ptx = b"//\n.version 8.5\n.target sm_89\n.address_size 64\n.visible .entry kawpow_hash(\n)\n{\n ret;\n}\n"
    sc["files"] = {
        STORE + "nvlddmkm.sys": b"MZ-kmd", STORE + "nvopencl64.dll": b"MZ-ocl", STORE + "nvldumdx.dll": b"MZ-umd",
        STORE + "nvoglv64.dll": b"MZ-ogl", SYS + "nvcuda.dll": b"MZ-cuda", SYS + "NvFBC64.dll": b"MZ-fbc",
        SYS + "drivers\\dxgkrnl.sys": b"MZ-dxg", TEMP + "evilflt.sys": b"MZ-evil", TEMP + "cupti64_2024.dll": b"MZ",
        TEMP + "cudart64_12.dll": b"MZ", TEMP + "ArmouryCrate.exe": b"MZ", TEMP + "svchost.exe": b"MZ",
        "C:\\Users\\u\\AppData\\Roaming\\nvcontainer.exe": b"MZ", SYS + "d3d12.dll": b"MZ", SYS + "OpenCL.dll": b"MZ",
        SYS + "nvopencl64.dll": b"MZ",
        STORE + "nv-vk64.json": json.dumps({"ICD": {"library_path": ".\\nvoglv64.dll"}}),
        TEMP + "layer.json": json.dumps({"layer": {"name": "VK_LAYER_evil", "library_path": "evil.dll"}}),
        "C:\\Users\\u\\AppData\\Roaming\\NVIDIA\\ComputeCache\\1\\a\\0001": b"CACHEHDR" + cache_ptx,
        "C:\\Users\\u\\AppData\\Local\\NVIDIA\\GLCache\\x\\s.bin": b"\x01" * 16}
    sc["dirs"] = ["C:\\gone"]
    sc["unreadable_dirs"] = ["C:\\Users\\locked"]
    sc["procs"], sc["links"], sc["stats"] = {}, {}, {}
    sc["cuda"] = {"available": True, "devices": [{"ordinal": 0, "pci_bus_id": "0000:41:00.0",
                                                  "luid": "0x00000000_0x00000001"}]}
    return sc


class LocalScenario:
    def setUp(self):
        self.sc = win_scenario()
        self.src = FakeSystemSource(self.sc)


class WindowsGenericPlugins(LocalScenario, unittest.TestCase):
    """WIN-1 / WIN-3: the generic live plugins have real Windows code paths."""

    def test_pslist_pstree_cmdline_use_windows_process_view(self):
        rows = {r["PID"]: r for r in run("nvidia.pslist", self.src)}
        self.assertNotIn(4242, rows)                                    # LNX-2/DET-9: Keto itself
        self.assertEqual(rows[800]["Name"], "xmrig.exe")
        self.assertEqual(rows[800]["PPID"], 500)
        self.assertEqual(rows[800]["Exe"], "C:\\ProgramData\\xmrig.exe")
        self.assertEqual(rows[800]["Started"].year, 1970)               # start_time 1800.0 from GetProcessTimes
        self.assertEqual(rows[800]["GPU Memory"], 3 << 30)              # PDH dedicated when NVML has none
        self.assertIn("dll:nvcuda.dll", rows[800]["Evidence"])
        tree = {r["PID"]: r for r in run("nvidia.pstree", self.src)}
        self.assertEqual(tree[1200]["__depth"], tree[1300]["__depth"] + 1)
        self.assertEqual(tree[800]["Cmdline"], "xmrig.exe -o stratum+tcp://pool:3333 --cuda")
        cmd = run("nvidia.cmdline", self.src, pid=800)
        self.assertEqual((cmd[0]["Name"], cmd[0]["Exe"]), ("xmrig.exe", "C:\\ProgramData\\xmrig.exe"))

    def test_pstree_ignores_reused_parent_pid(self):
        self.sc["windows"]["processes"][-4]["start_time"] = 9999.0  # "parent" pwsh started after deviceQuery
        tree = {r["PID"]: r for r in run("nvidia.pstree", FakeSystemSource(self.sc))}
        self.assertEqual(tree[1200]["__depth"], 0)

    def test_envars_from_peb_case_insensitive(self):
        rows = run("nvidia.envars", self.src, suspicious_only=True)
        self.assertEqual([(r["PID"], r["Variable"]) for r in rows], [(800, "cuda_injection64_path")])
        allrows = run("nvidia.envars", self.src, all=True)
        self.assertNotIn("SECRET", [r["Variable"] for r in allrows])  # privacy filter
        self.assertTrue(any(r["PID"] == 1000 and isinstance(r["Variable"], NotAvailableValue) for r in allrows))

    def test_libs_injection_masquerade_deletedexe_capture(self):
        libs = run("nvidia.libs", self.src)
        self.assertTrue(any(r["PID"] == 800 and r["Path"] == TEMP + "cudart64_12.dll" and r["Suspicious"]
                            for r in libs))
        inj = {(r["PID"], r["Technique"], r["Severity"]) for r in run("nvidia.malware.injection", self.src)}
        self.assertIn((800, "environment CUDA_INJECTION64_PATH", "high"), inj)
        self.assertIn((800, "instrumentation library loaded", "low"), inj)
        self.assertIn((800, "GPU runtime/driver DLL loaded from a user-writable location", "high"), inj)  # cupti
        mas = {(r["PID"], r["Finding"].split(" ")[0]) for r in run("nvidia.malware.masquerade", self.src)}
        self.assertIn((1000, "Windows"), mas)    # svchost.exe outside System32
        self.assertIn((1100, "NVIDIA"), mas)     # nvcontainer.exe outside Program Files / driver store
        self.assertIn((600, "PEB"), mas)         # PEB ImagePathName says explorer.exe
        dele = {(r["PID"], r["Object"]) for r in run("nvidia.malware.deletedexe", self.src)}
        self.assertEqual(dele, {(1500, "executable"), (1500, "module")})
        cap = run("nvidia.malware.capture", self.src)
        self.assertTrue(any(r["PID"] == 700 and r["Details"] == "NvFBC64.dll" and r["Severity"] == "medium"
                            for r in cap))

    def test_gpuxview_rawioctl_debugger_profiling_cryptojack(self):
        xv = {r["PID"]: r for r in run("nvidia.malware.gpuxview", self.src)}
        self.assertIn("raw D3DKMT", xv[1400]["Note"])
        self.assertFalse(xv[601]["Note"])
        self.assertEqual([r["PID"] for r in run("nvidia.malware.rawioctl", self.src)], [1400])
        dbg = {(r["PID"], r["Indicator"]) for r in run("nvidia.debugger", self.src)}
        self.assertIn((700, "debugger attached"), dbg)
        prof = run("nvidia.profiling", self.src)
        self.assertTrue(any(r["Indicator"] == "RmProfilingAdminOnly=0" and r["Risk"] == "high" for r in prof))
        self.assertTrue(any(r["PID"] == 800 and r["Indicator"] == "CUDA_INJECTION64_PATH" for r in prof))
        cj = run("nvidia.malware.cryptojack", self.src)
        self.assertTrue(any(r["PID"] == 800 and r["Category"] == "miner-software" for r in cj))


class WindowsHandles(LocalScenario, unittest.TestCase):
    """WIN-2: nvidia.handles on Windows lists open handles to GPU objects and files."""

    def setUp(self):
        super().setUp()
        vol = "\\Device\\HarddiskVolume3\\Windows\\System32\\DriverStore\\FileRepository\\nvhm.inf_amd64_x\\"
        self.sc["windows"]["handles"] = {
            "800": [(0x10, "\\Device\\DxgKrnl"), (0x14, vol + "nvcubins.bin"), (0x18, "\\Device\\NamedPipe\\x"),
                    (0x1C, "\\Device\\HarddiskVolume3\\Users\\u\\AppData\\Local\\NVIDIA\\DXCache\\a.nvph")],
            "4242": [(0x20, "\\Device\\DxgKrnl")]}
        self.sc["windows"]["handles_unreadable"] = [700]
        self.src = FakeSystemSource(self.sc)

    def test_rows_kinds_and_unreadable_processes(self):
        with self.assertLogs("keto.nvidia.handles", level="WARNING") as logs:
            rows = run("nvidia.handles", self.src)
        got = {(r["PID"], r["FD"], r["Kind"]) for r in rows}
        self.assertEqual(got, {(800, 0x10, "DirectX graphics kernel device (D3DKMT)"),
                               (800, 0x14, "CUDA driver kernel archive (opened at cuInit)"),
                               (800, 0x1C, "NVIDIA DirectX shader cache in use")})  # pipe dropped, Keto excluded
        self.assertIn("700", "\n".join(logs.output))
        self.assertEqual(run("nvidia.handles", self.src, pid=900), [])

    def test_snapshot_replay_is_identical(self):
        rec = RecordingSource(self.src)
        live = run("nvidia.handles", rec)
        rep = ReplaySource(json.loads(json.dumps(rec.snapshot())))
        self.assertEqual(run("nvidia.handles", rep), live)

    @unittest.skipUnless(os.name == "nt" and os.path.exists(os.path.join(os.environ.get("SystemRoot", "C:\\Windows"),
                                                                           "System32", "nvcuda.dll")),
                         "needs Windows with the NVIDIA CUDA driver")
    def test_live_cuda_process_holds_the_driver_kernel_archive(self):
        """Against a CUDA process this test starts itself: names are resolved only for that process."""
        import subprocess
        from keto.live.source import SystemSource
        child = subprocess.Popen([sys.executable, "-c", (
            "import ctypes, time\ncu = ctypes.WinDLL('nvcuda.dll')\nassert cu.cuInit(0) == 0\n"
            "d = ctypes.c_int(); cu.cuDeviceGet(ctypes.byref(d), 0)\nc = ctypes.c_void_p()\n"
            "assert cu.cuCtxCreate_v2(ctypes.byref(c), 0, d) == 0\nprint('ready', flush=True)\ntime.sleep(60)\n")],
            stdout=subprocess.PIPE, text=True)
        try:
            if child.stdout.readline().strip() != "ready":
                self.skipTest("no usable CUDA device")
            rows = run("nvidia.handles", SystemSource(), pid=child.pid)
        finally:
            child.kill()
            child.wait()
        self.assertTrue(any(r["Kind"] == "CUDA driver kernel archive (opened at cuInit)" for r in rows), rows)


class WindowsSystemPlugins(LocalScenario, unittest.TestCase):
    """WIN-2 / WIN-4."""

    def test_driver_and_modules(self):
        drv = run("nvidia.driver", self.src, no_hash=True)
        kmd = next(r for r in drv if r["Item"].startswith("kernel-mode driver"))
        self.assertIn("(loaded)", kmd["Item"])
        self.assertIn("nvlddmkm.sys", kmd["Value"])
        self.assertIn("valid (NVIDIA Corporation", kmd["Value"])
        self.assertTrue(any(r["Item"] == "display driver" and "RTX 4050" in r["Value"] for r in drv))
        self.assertFalse(any("/proc/driver" in str(r["Value"]) for r in drv))
        mods = {r["Module"]: r for r in run("nvidia.modules", self.src)}
        self.assertEqual(set(mods), {"nvlddmkm.sys", "dxgkrnl.sys", "evilflt"})   # Microsoft nvmedisk left out
        self.assertFalse(mods["nvlddmkm.sys"]["Suspicious"])
        self.assertEqual(len(mods["nvlddmkm.sys"]["SHA256"]), 64)
        self.assertTrue(mods["evilflt"]["Suspicious"])
        self.assertIn("filter driver", mods["evilflt"]["Reason"])
        self.assertIn("unsigned", mods["evilflt"]["Reason"])

    def test_devicetree(self):
        rows = run("nvidia.devicetree", self.src)
        fn = next(r for r in rows if r["Kind"] == "pci-function (no NVML device)" or r["Kind"] == "pci-function")
        self.assertEqual(fn["Address"], "0000:01:00.0")
        self.assertIn("service nvlddmkm", fn["Details"])
        self.assertTrue(any(r["Kind"] == "dxgi-adapter" for r in rows))
        self.assertFalse(any("/sys/bus/pci" in str(r["Details"]) for r in rows))

    def test_params_daemons_autostart_computecache_integrity(self):
        params = {r["Parameter"]: r for r in run("nvidia.params", self.src, flagged_only=True)}
        self.assertEqual(params["RmProfilingAdminOnly"]["Severity"], "high")
        self.assertEqual(params["TdrLevel"]["Severity"], "high")
        dmn = run("nvidia.daemons", self.src)
        self.assertEqual([r["Service"] for r in dmn if r["Registration"].startswith(SVC)],
                         ["NVDisplay.ContainerLocalSystem"])          # nvdimm is Microsoft's, nvlddmkm a driver
        self.assertTrue(any(r["Service"] == "nvcontainer.exe" and r["Expected path"] is False for r in dmn))
        auto = {(r["Kind"], r["Entry"]): r for r in run("nvidia.autostart", self.src, suspicious_only=True)}
        self.assertIn(("opencl-icd", "C:\\Users\\u\\AppData\\Roaming\\evilcl.dll"), auto)
        self.assertIn(("vulkan-implicit-layer (user)", "VK_LAYER_evil evil.dll"), auto)
        allauto = run("nvidia.autostart", self.src)
        self.assertTrue(any(r["Entry"] == STORE + "nvoglv64.dll" and not r["Suspicious"] for r in allauto))
        cache = {r["Path"]: r for r in run("nvidia.computecache", self.src)}
        entry = cache["C:\\Users\\u\\AppData\\Roaming\\NVIDIA\\ComputeCache\\1\\a\\0001"]
        self.assertIn("kawpow_hash", entry["Kernels"])
        self.assertIn("C:\\Users\\u\\AppData\\Local\\NVIDIA\\GLCache\\x\\s.bin", cache)
        self.assertIn("not readable", str(cache["C:\\Users\\locked"]["Content"]))
        integ = [r for r in run("nvidia.malware.integrity", self.src) if r["Check"] == "authenticode"]
        bad = [r for r in integ if str(r["Result"]).startswith("MODIFIED")]
        self.assertEqual([r["Object"] for r in bad], [STORE + "nvopencl64.dll"])

    def test_procscan_and_libhooks_windows(self):
        payload = build_cubin({"stage2_decrypt": sass_function(31)})
        self.sc["windows"]["regions"] = {"800": [{"start": 0x10000, "end": 0x10000 + 0x4000, "perms": "rw-p",
                                                   "path": "", "type": "private"}]}
        self.sc["memory"] = {"800": [[0x10000, payload + bytes(0x4000 - len(payload))]]}
        rows = run("nvidia.procscan", FakeSystemSource(self.sc), pid=800)
        cub = [r for r in rows if r["Kind"] == "cubin"]
        self.assertEqual((cub[0]["Mapping"], cub[0]["Severity"]), ("[anon]", "medium"))
        hooks = run("nvidia.malware.libhooks", FakeSystemSource(self.sc), pid=800)
        self.assertEqual([r["Status"] for r in hooks], ["n/a: on-disk file is not a PE image"])

    def test_precise_refusals(self):
        # nvidia.handles has a Windows implementation now (WindowsHandles); the Linux-only concepts still refuse
        for name, hint in (("nvidia.devnodes", "nvidia.modules"),
                           ("nvidia.containers", "inside the Linux guest"),
                           ("nvidia.malware.rawaccess", "nvidia.malware.rawioctl")):
            with self.subTest(plugin=name):
                with self.assertRaises(UnsupportedError) as cm:
                    run(name, self.src)
                self.assertIn(hint, str(cm.exception))


def build_pe(text: bytes, image_base=0x180000000, relocs=(0x10, 0x40), iat=(0x80, 0x10), timestamp=0x5EED):
    """A minimal PE32+ DLL: headers, .text at RVA 0x1000 (DIR64 relocations at the given .text offsets, IAT
    inside .text) and .reloc at RVA 0x2000."""
    relblock = struct.pack("<II", 0x1000, 8 + 2 * len(relocs)) + b"".join(struct.pack("<H", (10 << 12) | o)
                                                                           for o in relocs)
    dos = bytearray(0x80)
    dos[0:2], dos[0x3C:0x40] = b"MZ", struct.pack("<I", 0x80)
    opt = bytearray(240)
    struct.pack_into("<HBB", opt, 0, 0x20B, 14, 0)
    struct.pack_into("<Q", opt, 24, image_base)
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)
    struct.pack_into("<III", opt, 56, 0x3000, 0x400, 0x1234)  # SizeOfImage, SizeOfHeaders, CheckSum
    struct.pack_into("<I", opt, 108, 16)
    struct.pack_into("<II", opt, 112 + 8 * 5, 0x2000, len(relblock))
    struct.pack_into("<II", opt, 112 + 8 * 12, 0x1000 + iat[0], iat[1])
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 2, timestamp, 0, 0, 240, 0x2022)
    sec = lambda name, va, size, raw, chars: name.ljust(8, b"\x00") + struct.pack("<IIIIIIHHI", size, va, 0x200,  # noqa
                                                                                  raw, 0, 0, 0, 0, chars)
    head = bytes(dos) + coff + bytes(opt) + sec(b".text", 0x1000, len(text), 0x400, 0x60000020) + \
        sec(b".reloc", 0x2000, len(relblock), 0x600, 0x42000040)
    head = head.ljust(0x400, b"\x00")
    return head + text.ljust(0x200, b"\x00") + relblock.ljust(0x200, b"\x00")


class WindowsLibHooksPE(unittest.TestCase):
    """libhooks on Windows compares code with the on-disk file after applying PE base relocations."""

    BASE = 0x7FF000000000
    PATH = STORE + "nvcuda64.dll"

    def scenario(self, loaded_text, file_bytes):
        sc = win_scenario()
        sc["files"][self.PATH] = file_bytes
        sc["windows"]["modules"]["800"] = [{"name": "nvcuda64.dll", "path": self.PATH, "base": self.BASE,
                                            "size": 0x3000}]
        sc["memory"] = {"800": [[self.BASE, file_bytes[:0x400] + bytes(0xC00)], [self.BASE + 0x1000, loaded_text]]}
        return FakeSystemSource(sc)

    def loaded(self, text):
        delta = self.BASE - 0x180000000
        out = bytearray(text)
        for o in (0x10, 0x40):
            struct.pack_into("<Q", out, o, struct.unpack_from("<Q", out, o)[0] + delta)
        out[0x80:0x90] = b"\xAA" * 16  # the loader filled the IAT
        return bytes(out)

    def test_relocated_copy_is_clean_and_patch_is_found(self):
        text = bytearray(bytes(range(256)) * 2)
        struct.pack_into("<Q", text, 0x10, 0x180001234)
        struct.pack_into("<Q", text, 0x40, 0x180005678)
        pe = build_pe(bytes(text))
        rows = run("nvidia.malware.libhooks", self.scenario(self.loaded(text), pe), pid=800)
        self.assertEqual([r["Status"] for r in rows], ["clean"])
        patched = bytearray(self.loaded(text))
        patched[0x100] ^= 0xFF
        rows = run("nvidia.malware.libhooks", self.scenario(bytes(patched), pe), pid=800)
        self.assertEqual(rows[0]["Status"], "MODIFIED (1 range)")
        self.assertEqual((rows[0]["Modified bytes"], rows[0]["First diff VA"]), (1, self.BASE + 0x1100))
        other_build = build_pe(bytes(text), timestamp=0x1111)
        src = self.scenario(self.loaded(text), pe)
        src.files[self.PATH] = other_build
        self.assertTrue(run("nvidia.malware.libhooks", src, pid=800)[0]["Status"].startswith("skipped"))


class GpuProcsFixes(LocalScenario, unittest.TestCase):
    def test_self_runtime_paths_console_window_and_miner_label(self):
        rows = {r["PID"]: r for r in run("windows.gpuprocs", self.src)}
        self.assertNotIn(4242, rows)                                         # DET-9 / LNX-2
        self.assertTrue(rows[1200]["Window"])                                # console tool under a visible shell
        self.assertIn("miner-software indicator in process name (xmrig)", rows[800]["Attention"])
        self.assertIn("GPU runtime CUDA runtime loaded from a user-writable location: " + TEMP + "cudart64_12.dll",
                      rows[800]["Attention"])                                # DET-10, path shown
        self.assertIn(TEMP + "cudart64_12.dll", rows[800]["Runtime paths"])

    def test_busy_threshold(self):
        self.sc["windows"]["gpu"]["processes"]["900"] = {"engines": {"3D": 0.0}, "luids": [], "dedicated": 0,
                                                          "shared": 0}
        rows = {r["PID"]: r for r in run("windows.gpuprocs", FakeSystemSource(self.sc), busy=0.0)}
        self.assertIsInstance(rows[900]["Active engines"], NotAvailableValue)   # 0% is not activity
        with self.assertRaises(RequirementError):
            run("windows.gpuprocs", self.src, busy=-1.0)

    def test_has_window_rules(self):
        procs = {p["pid"]: p for p in self.sc["windows"]["processes"]}
        win = set(self.sc["windows"]["windowed"])
        self.assertTrue(wgpu.has_window(procs[1200], procs, win))   # deviceQuery -> pwsh (visible console)
        self.assertTrue(wgpu.has_window(procs[601], procs, win))    # chrome GPU process -> chrome
        self.assertFalse(wgpu.has_window(procs[700], procs, win))   # explorer's window is never inherited

    @unittest.skipUnless(os.name == "nt", "Windows API")
    def test_toolhelp_pid0_is_not_this_process(self):
        from keto.live import windows as w
        self.assertEqual(w.modules(0), [])


class GapFixes(unittest.TestCase):
    def test_unaccounted_gpu_index_from_luid(self):
        rows = run("nvidia.malware.unaccounted", FakeSystemSource(win_scenario()))
        self.assertEqual(rows[0]["GPU"], 1)          # CUDA LUID -> PCI 41:00.0 -> NVML index 1, not "0"

    def test_unaccounted_wsl_no_false_positive(self):
        sc = default_scenario()
        sc["platform"]["wsl"] = True
        dev = sc["nvml"]["devices"][0]
        for k in ("compute_processes", "graphics_processes", "mps_compute_processes"):
            dev[k] = []
        dev["memory"]["used"] = 3 << 30
        rows = run("nvidia.malware.unaccounted", FakeSystemSource(sc))
        self.assertIn("WSL2", rows[0]["Finding"])
        self.assertNotIn("no listed process", rows[0]["Finding"])
        self.assertNotIn("no process listed", rows[0]["Finding"])

    def test_scraper_window_inheritance_and_wsl_refusal(self):
        sc = win_scenario()
        sc["windows"]["gpu"]["processes"]["601"]["by_luid"]["0x0_0x1"]["dedicated"] = 5 << 30
        rows = {r["PID"]: r for r in run("nvidia.malware.scraper", FakeSystemSource(sc))}
        self.assertEqual(rows[601]["Severity"], "medium")               # inherits chrome's window (DET-8)
        lin = default_scenario()
        lin["platform"]["wsl"] = True
        with self.assertRaises(UnsupportedError):
            run("nvidia.malware.scraper", FakeSystemSource(lin))


class LinuxDetectorFixes(unittest.TestCase):
    def setUp(self):
        self.sc = default_scenario()

    def add(self, pid, comm, exe, argv):
        p = copy.deepcopy(self.sc["procs"]["1200"])
        p.update(pid=pid, comm=comm, exe=exe, cmdline=argv, environ={})
        self.sc["procs"][str(pid)] = p

    def test_masquerade_argv0_prctl_and_daemon_path(self):
        self.add(3001, "python3", "/usr/bin/python3.10", ["sshd", "x.py"])                       # exec -a sshd
        self.add(3002, "sshd", "/usr/bin/python3.10", ["sshd", "x.py"])                          # + prctl
        self.add(3003, "nvidia-persiste", "/usr/bin/python3.10", ["nvidia-persistenced", "x.py"])
        self.add(3004, "train.py", "/usr/bin/python3.10", ["/usr/bin/python3", "./train.py"])   # shebang script
        rows = run("nvidia.malware.masquerade", FakeSystemSource(self.sc))
        f = {(r["PID"], r["Finding"].split(" ")[0]) for r in rows}
        self.assertIn((3001, "argv[0]"), f)
        self.assertIn((3002, "comm"), f)
        self.assertIn((3003, "NVIDIA"), f)
        self.assertNotIn(3004, [r["PID"] for r in rows])
        self.assertNotIn(1200, [r["PID"] for r in rows])          # python3 -> python3.10 is fine

    def test_deletedexe_memfd_reasons(self):
        self.add(3010, "loader", "/memfd:stage (deleted)", ["loader"])
        self.sc["procs"]["3010"]["maps"].append({"start": 0x1000, "end": 0x2000, "perms": "r-xs", "offset": 0,
                                                 "dev": "00:01", "inode": 9, "path": "/memfd:code (deleted)"})
        rows = {(r["PID"], r["Path"]): r["Reason"] for r in run("nvidia.malware.deletedexe", FakeSystemSource(self.sc))}
        self.assertEqual(rows[(3010, "/memfd:stage (deleted)")], "fileless (memfd) executable")
        self.assertEqual(rows[(3010, "/memfd:code (deleted)")], "executable fileless mapping")
        self.assertEqual(rows[(1400, "/dev/shm/.k (deleted)")], "running image deleted from disk")

    def test_self_not_listed(self):
        self.sc["platform"]["self_pid"] = 1200
        src = FakeSystemSource(self.sc)
        self.assertNotIn(1200, procfs.gpu_processes(src))
        self.assertNotIn(1200, [r["PID"] for r in run("nvidia.pslist", src)])

    def test_gpuxview_raw_device_note(self):
        rows = {r["PID"]: r for r in run("nvidia.malware.gpuxview", FakeSystemSource(self.sc))}
        self.assertIn("raw ioctl", rows[1800]["Note"])           # /dev/nvidia* open, no user-mode driver
        self.assertFalse(rows[1300]["Note"])

    def test_cryptojack_wsl_host_pids(self):
        self.sc["platform"]["wsl"] = True
        rows = [r for r in run("nvidia.malware.cryptojack", FakeSystemSource(self.sc)) if r["Category"] == "utilization"]
        self.assertTrue(rows)
        for r in rows:
            self.assertIsInstance(r["PID"], NotAvailableValue)
            self.assertEqual(r["Name"], "(Windows host process)")

    def test_accounting_off_and_dxg_wording(self):
        dev = self.sc["nvml"]["devices"][0]
        dev["accounting_mode"], dev["accounting"] = 0, {}
        rows = run("nvidia.accounting", FakeSystemSource(self.sc))
        self.assertIn("accounting mode disabled", str(rows[0]["Started"]))
        self.sc["stats"]["/dev/dxg"] = {"mode": 0o020666, "uid": 0, "gid": 0, "size": 0, "rdev_major": 10,
                                        "rdev_minor": 258}
        nodes = {r["Node"]: r for r in run("nvidia.devnodes", FakeSystemSource(self.sc))}
        self.assertEqual(nodes["/dev/dxg"]["Notes"], "world-accessible (dxgkrnl default on WSL2)")

    def test_libhooks_statuses_follow_report_contract(self):
        self.sc["procs"]["1200"]["maps"].append({"start": 0x9000, "end": 0xA000, "perms": "r-xp", "offset": 0,
                                                 "dev": "08:01", "inode": 5,
                                                 "path": "/usr/lib/x86_64-linux-gnu/libnvidia-gone.so.1 (deleted)"})
        rows = run("nvidia.malware.libhooks", FakeSystemSource(self.sc), pid=1200)
        self.assertTrue(any(r["Status"].startswith("skipped") for r in rows))

    def test_suspicious_path_re_removed(self):
        self.assertFalse(hasattr(procfs, "SUSPICIOUS_PATH_RE"))


class SnapshotFixes(unittest.TestCase):
    """NI-3 / NI-4."""

    def replay(self, sc, plugins):
        rec = RecordingSource(FakeSystemSource(sc))
        for name in plugins:
            run(name, rec)
        return ReplaySource(json.loads(json.dumps(rec.snapshot())))

    def test_memory_plugins_refuse_replay(self):
        rep = self.replay(default_scenario(), ["nvidia.pslist"])
        for name in ("nvidia.procscan", "nvidia.malware.libhooks"):
            with self.subTest(plugin=name):
                with self.assertRaises(UnsupportedError) as cm:
                    run(name, rep)
                self.assertIn("snapshots do not record", str(cm.exception))

    def test_misses_are_surfaced(self):
        rep = self.replay(default_scenario(), ["nvidia.computecache"])
        with self.assertRaises(NotRecordedError):
            rep.read_text("/etc/never-recorded")
        self.assertTrue(rep.misses)
        rows = {r["Path"]: r for r in run("nvidia.computecache", rep, read_bytes=1 << 20)}
        self.assertIn("not recorded in snapshot", str(rows["/home/alice/.nv/ComputeCache/3/a/5c1e0f"]["Kernels"]))
        wrep = self.replay(win_scenario(), ["windows.gpuprocs"])
        rows = {r["PID"]: r for r in run("windows.gpuprocs", wrep, all=True)}
        self.assertEqual(str(rows[900]["CommandLine"]), "N/A (not recorded in snapshot)")

    def test_windows_replay_identical(self):
        names = ["nvidia.pslist", "nvidia.envars", "nvidia.libs", "nvidia.malware.injection", "nvidia.driver",
                 "nvidia.modules", "nvidia.autostart", "nvidia.malware.masquerade", "windows.gpuprocs"]
        rec = RecordingSource(FakeSystemSource(win_scenario()))
        live = {n: run(n, rec) for n in names}
        rep = ReplaySource(json.loads(json.dumps(rec.snapshot())))
        for n in names:
            with self.subTest(plugin=n):
                self.assertEqual(repr(run(n, rep)), repr(live[n]))
        self.assertEqual(rep.misses, [])


class CommandAllowList(unittest.TestCase):
    """LNX-5."""

    def test_current_callers_allowed(self):
        for argv in (["dpkg-query", "-W", "-f=${Package} ${Version}\n"], ["dpkg", "--verify", "nvidia-utils-565"],
                     ["rpm", "-qa", "--qf", "%{NAME}\n"], ["rpm", "-V", "cuda-drivers"],
                     ["rpm", "-q", "--qf", "%{VERSION}", "nvidia-container-toolkit"],
                     ["dpkg-query", "-W", "-f=${Version}", "nvidia-container-toolkit"],
                     ["journalctl", "-k", "-o", "short-iso", "--no-pager"], ["dmesg"], ["modinfo", "-F", "version", "nvidia"],
                     ["nvidia-smi", "-q", "-x"], ["systemctl", "status", "nvidia-persistenced.service"], ["lsmod"]):
            with self.subTest(argv=argv):
                self.assertEqual(check_command(argv), argv[0])

    def test_write_modes_and_paths_refused(self):
        for argv in (["dmesg", "-C"], ["dmesg", "--clear"], ["nvidia-smi", "-r"], ["nvidia-smi", "-pm", "1"],
                     ["systemctl", "stop", "nvidia-persistenced"], ["dpkg", "-i", "x.deb"], ["dpkg"],
                     ["rpm", "-e", "cuda"], ["rpm", "-i", "x.rpm"], ["journalctl", "--vacuum-size=1"],
                     ["debsums", "-g"], ["/tmp/dmesg"], ["./dmesg"], ["bash", "-c", "id"], []):
            with self.subTest(argv=argv):
                with self.assertRaises(LiveSourceError):
                    check_command(argv)


class LogFileFixes(unittest.TestCase):
    """CLI-2 / DOS-5 / section 11 (xid, bugreport)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def xid(self, **opts):
        return PLUGINS["nvidia.xid"](Context(), opts).run().as_dicts()

    def path(self, name, data):
        p = os.path.join(self.dir, name)
        with open(p, "wb") as fh:
            fh.write(data)
        return p

    def test_missing_truncated_and_bomb(self):
        with self.assertRaises(RequirementError):
            self.xid(log_file=os.path.join(self.dir, "missing.log"))
        with self.assertRaises(RequirementError):
            PLUGINS["nvidia.bugreport"](Context(), {"file": os.path.join(self.dir, "missing.gz")}).run()
        whole = gzip.compress(b"NVRM: Xid (PCI:0000:01:00): 79, pid=1, name=x, gone\n" * 100)
        with self.assertRaises(FormatError):
            self.xid(log_file=self.path("cut.gz", whole[:len(whole) // 2]))
        bomb = self.path("bomb.gz", gzip.compress(b"\x00" * 8192))
        old, live_system.MAX_LOG = live_system.MAX_LOG, 4096
        try:
            with self.assertRaises(FormatError):
                self.xid(log_file=bomb)
        finally:
            live_system.MAX_LOG = old

    def test_syslog_year_and_naive_iso(self):
        line = " host kernel: NVRM: Xid (PCI:0000:01:00): 79, pid='<unknown>', name=<unknown>, GPU has fallen off.\n"
        p = self.path("kern.log", ("Dec 30 23:00:00" + line).encode())
        jan = _dt.datetime(2027, 1, 2, tzinfo=_dt.timezone.utc).timestamp()
        os.utime(p, (jan, jan))
        rows = self.xid(log_file=p)
        self.assertEqual((rows[0]["Time"].year, rows[0]["Time"].month), (2026, 12))
        self.assertIn("syslog time has no year", rows[0]["Forensic note"])
        rows = self.xid(log_file=self.path("iso.log", ("2026-11-16T10:00:00" + line).encode()))
        self.assertIn("no UTC offset", rows[0]["Forensic note"])

    def test_bugreport_times_and_pids(self):
        text = ("Start of NVIDIA bug report log file.  Mon Nov 16 10:00:00 UTC 2026\n*** dmesg\n"
                "[ 7200.500000] NVRM: Xid (PCI:0000:01:00): 31, pid=1400, name=k, Ch 00000010\n"
                "Nov 16 09:00:00 host kernel: NVRM: Xid (PCI:0000:01:00): 79, pid='<unknown>', name=<unknown>, off\n")
        rows = PLUGINS["nvidia.bugreport"](Context(), {"file": self.path("r.log", text.encode())}).run().as_dicts()
        xids = {r["Item"]: r["Value"] for r in rows if r["Category"] == "xid"}
        self.assertTrue(xids["Xid 31 GPU memory page fault"].startswith("time=boot+7200.500000s pid=1400"))
        # a syslog line carries no zone: the time is shown as logged (naive), not declared UTC
        self.assertTrue(xids["Xid 79 GPU has fallen off the bus"].startswith("time=2026-11-16T09:00:00 pid=- "))


class DeviceFixes(unittest.TestCase):
    def test_reserved_memory_and_enable_states(self):
        sc = default_scenario()
        dev = sc["nvml"]["devices"][0]
        dev["memory"]["reserved"] = 221 << 20
        dev["display_mode"], dev["display_active"] = 0, 1
        vals = {(r["GPU"], r["Field"]): r["Value"] for r in run("nvidia.devices", FakeSystemSource(sc))}
        self.assertIn("reserved 221.0 MiB", vals[("GPU 0", "Framebuffer memory")])
        self.assertEqual(vals[("GPU 0", "Display mode")], "Disabled")
        self.assertEqual(vals[("GPU 0", "Display active")], "Enabled")


class DriverLibraryProvenance(unittest.TestCase):
    """DET-3: GPU code that also sits inside an NVIDIA driver library of the same capture is driver code."""

    KERNEL = build_cubin({"app_payload_kernel": sass_function(41)})

    def container(self, d, lib_path):
        blob = self.KERNEL + bytes(0x4000 - len(self.KERNEL))
        maps = [{"start": 0x7FF100000000, "end": 0x7FF100004000, "perms": "r-xp", "path": lib_path},
                {"start": 0x10000000, "end": 0x10004000, "perms": "rw-p", "path": "[anon]"}]
        path = os.path.join(d, "p.keto")
        w = ContainerWriter(path, {"process": {"pid": 1, "mappings": maps}})
        for m in maps:
            w.add_segment("process", m["start"], blob)
        w.close()
        with Context(image=path) as ctx:
            return PLUGINS["nvidia.artifactscan"](ctx, {}).run().as_dicts()

    def anon_cubin(self, rows):
        return next(r for r in rows if r["Kind"] == "cubin" and r["Offset"] == 0x10000000)

    def test_same_code_in_system_library_is_driver_code(self):
        with tempfile.TemporaryDirectory() as d:
            rows = self.container(d, STORE + "nvcuda64.dll")
            anon = self.anon_cubin(rows)
            self.assertEqual(anon["Provenance"], "NVIDIA driver library code (same code in nvcuda64.dll)")
            self.assertIsInstance(anon["Attention"], str)
            self.assertEqual(anon["Attention"], "")
            rows = self.container(d, TEMP + "nvcuda64.dll")
            anon = self.anon_cubin(rows)
            self.assertEqual(anon["Provenance"], "unknown")
            self.assertEqual(anon["Severity"], "medium")

    def test_raw_sass_copied_out_of_a_library_cubin_is_driver_code(self):
        """Raw SASS (no cubin around it) in anonymous memory whose function sits in a cubin of a trusted NVIDIA
        library mapping is attributed by SASS skeleton hash, not left as unattributed code."""
        from keto.formats.cubin import parse_cubin
        text = parse_cubin(self.KERNEL).kernels[0].text
        lib_blob = self.KERNEL + bytes(0x4000 - len(self.KERNEL))
        anon_blob = bytes(0x100) + text + bytes(0x4000 - 0x100 - len(text))
        maps = [{"start": 0x7FF100000000, "end": 0x7FF100004000, "perms": "r-xp", "path": STORE + "nvcuda64.dll"},
                {"start": 0x10000000, "end": 0x10004000, "perms": "rw-p", "path": "[anon]"}]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.keto")
            w = ContainerWriter(path, {"process": {"pid": 1, "mappings": maps}})
            w.add_segment("process", maps[0]["start"], lib_blob)
            w.add_segment("process", maps[1]["start"], anon_blob)
            w.close()
            with Context(image=path) as ctx:
                rows = PLUGINS["nvidia.artifactscan"](ctx, {}).run().as_dicts()
        raw = [r for r in rows if r["Kind"] == "sass" and 0x10000000 <= r["Offset"] < 0x10004000]
        self.assertTrue(raw, rows)
        for r in raw:
            self.assertEqual(r["Provenance"], "NVIDIA driver library code (same code in nvcuda64.dll)")
            self.assertEqual(r["Severity"], "info")

    def test_driver_kernel_archive_next_to_the_library_is_indexed(self):
        """nvcubins.bin (read, not mapped, at cuInit) vouches for SASS the driver copies into anonymous memory."""
        from keto.formats.cubin import parse_cubin
        from keto.gpu import sass
        sc = default_scenario()
        sc["files"] = dict(sc.get("files", {}), **{STORE + "nvcubins.bin": bytes(64) + self.KERNEL})
        ctx = Context()
        ctx.set_live_source(FakeSystemSource(sc))
        got = hostside.archive_hashes(ctx, ctx.live, [STORE + "nvcuda64.dll", TEMP + "nvcuda64.dll"])
        want = sass.function_skeletons(parse_cubin(self.KERNEL).kernels[0].text)
        self.assertTrue(want and want <= set(got))
        self.assertEqual(set(got.values()), {"nvcubins.bin"})
        self.assertEqual(hostside.archive_hashes(ctx, ctx.live, [TEMP + "nvcuda64.dll"]), {})  # untrusted dir

    def test_library_rules(self):
        self.assertTrue(hostside.trusted_library("/usr/lib/x86_64-linux-gnu/libcuda.so.565.57.01"))
        self.assertFalse(hostside.trusted_library("/tmp/libcuda.so.1"))
        self.assertFalse(hostside.trusted_library("/home/u/libcuda.so.1"))
        self.assertFalse(hostside.trusted_library(TEMP + "nvcuda64.dll"))
        self.assertFalse(hostside.trusted_library(SYS + "kernel32.dll"))


if __name__ == "__main__":
    unittest.main()
