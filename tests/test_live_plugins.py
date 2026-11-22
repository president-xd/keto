"""Live/snapshot plugins against the fake NVIDIA Linux host (keto.testing.fakesys)."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keto.framework.context import Context  # noqa: E402
from keto.framework.exceptions import RequirementError, UnsupportedError  # noqa: E402
from keto.framework.plugin import PLUGINS, load_plugins  # noqa: E402
from keto.framework.renderers import render_to_string  # noqa: E402
from keto.live.source import RecordingSource, ReplaySource  # noqa: E402
from keto.testing.fakesys import FakeSystemSource, default_scenario, write_bugreport  # noqa: E402

load_plugins()
LIVE = sorted(n for n, c in PLUGINS.items() if "live" in c.SOURCES)


def ctx_for(source):
    ctx = Context()
    ctx.set_live_source(source)
    return ctx


def run(name, source=None, **opts):
    grid = PLUGINS[name](ctx_for(source or FakeSystemSource(default_scenario())), opts).run()
    return grid, grid.as_dicts()


def col(rows, name):
    return [r[name] for r in rows]


class LivePluginSmoke(unittest.TestCase):
    def test_every_live_plugin_runs_and_renders(self):
        self.assertGreaterEqual(len(LIVE), 30)
        for name in LIVE:
            with self.subTest(plugin=name):
                grid, _ = run(name, FakeSystemSource(windows_scenario() if name.startswith("windows.")
                                                     else default_scenario()))
                for r in ("quick", "pretty", "csv", "json"):
                    render_to_string(grid, r)
                cls = PLUGINS[name]
                for attr in ("DESCRIPTION", "METHOD", "ANALOG", "CATEGORY"):
                    self.assertTrue(getattr(cls, attr), "%s.%s empty" % (name, attr))

    def test_plugins_degrade_on_windows_source(self):
        sc = default_scenario()
        sc["platform"] = {"system": "Windows", "wsl": False}
        sc["files"], sc["procs"], sc["stats"], sc["links"] = {}, {}, {}, {}
        for name in LIVE:
            with self.subTest(plugin=name):
                try:
                    grid, _ = run(name, FakeSystemSource(sc))
                    render_to_string(grid, "quick")
                except UnsupportedError:
                    pass


class ProcessPlugins(unittest.TestCase):
    def test_pslist(self):
        _, rows = run("nvidia.pslist")
        pids = col(rows, "PID")
        for pid in (1200, 1300, 1400, 1500, 1600, 1700, 1800, 1900, 2100, 2200, 900, 901):
            self.assertIn(pid, pids)
        self.assertNotIn(1, pids)
        r1300 = next(r for r in rows if r["PID"] == 1300)
        self.assertEqual(r1300["GPU Memory"], 1610612736)
        self.assertIn("nvml-compute:gpu0", r1300["Evidence"])
        r2100 = next(r for r in rows if r["PID"] == 2100)
        self.assertIn("not-in-procfs", r2100["Evidence"])

    def test_pstree_includes_ancestors(self):
        grid, rows = run("nvidia.pstree")
        bash = next(r for r in rows if r["PID"] == 1000)
        self.assertFalse(bash["GPU"])
        child = next(r for r in rows if r["PID"] == 1200)
        self.assertEqual(child["__depth"], bash["__depth"] + 1)

    def test_cmdline(self):
        _, rows = run("nvidia.cmdline", pid=1300)
        self.assertEqual(len(rows), 1)
        self.assertIn("stratum+tcp://", rows[0]["Args"])

    def test_envars(self):
        _, rows = run("nvidia.envars", suspicious_only=True)
        found = {(r["PID"], r["Variable"]) for r in rows}
        self.assertIn((1400, "LD_PRELOAD"), found)
        self.assertIn((1500, "CUDA_INJECTION64_PATH"), found)
        self.assertIn((1500, "NVTX_INJECTION64_PATH"), found)
        _, allrows = run("nvidia.envars")
        self.assertNotIn("SECRET_TOKEN", col(allrows, "Variable"))  # privacy filter at the source
        self.assertIn("CUDA_VISIBLE_DEVICES", col(allrows, "Variable"))

    def test_handles(self):
        _, rows = run("nvidia.handles", pid=1500)
        kinds = col(rows, "Kind")
        self.assertIn("UVM tools (profiling/debug event stream)", kinds)
        self.assertIn("control node (RM client handle)", kinds)

    def test_libs(self):
        _, rows = run("nvidia.libs")
        sus = {(r["PID"], r["Path"]) for r in rows if r["Suspicious"]}
        self.assertIn((1500, "/tmp/libinject.so"), sus)
        self.assertIn((1400, "/dev/shm/libprocesshider.so"), sus)
        self.assertTrue(any(r["PID"] == 1200 and "libcuda" in r["Path"] and r["GPU library"] for r in rows))
        self.assertFalse(any(r["PID"] == 1200 and r["Suspicious"] for r in rows))  # /dev/zero, data memfd: benign

    def test_sessions(self):
        _, rows = run("nvidia.sessions")
        kinds = {(r["Kind"], r["PID"]) for r in rows}
        self.assertIn(("NVENC", 1700), kinds)
        self.assertIn(("FBC", 1700), kinds)
        self.assertEqual(next(r for r in rows if r["Kind"] == "FBC" and r["PID"] == 1700)["Process"], "svchostd")

    def test_accounting_history_and_timeline(self):
        grid, rows = run("nvidia.accounting")
        exited = next(r for r in rows if r["PID"] == 2000)
        self.assertFalse(exited["Running"])
        self.assertEqual(exited["Process"], "(exited / not in /proc)")
        self.assertEqual(exited["Duration s"], 7200.0)
        plugin = PLUGINS["nvidia.accounting"](ctx_for(FakeSystemSource(default_scenario())), {})
        events = list(plugin.generate_timeline())
        self.assertTrue(any("finished" in e[0] and "2000" in e[0] for e in events))

    def test_debugger(self):
        _, rows = run("nvidia.debugger")
        ind = {(r["PID"], r["Indicator"]) for r in rows}
        self.assertIn((1600, "CUDA debugger backend loaded"), ind)
        self.assertIn((1600, "ptrace-attached"), ind)
        self.assertIn((1601, "GPU debugger/profiler tool running"), ind)

    def test_profiling(self):
        _, rows = run("nvidia.profiling")
        self.assertTrue(any(r["Indicator"] == "RmProfilingAdminOnly=0" and r["Risk"] == "high" for r in rows))
        self.assertTrue(any(r["Indicator"].startswith("NVreg_RestrictProfilingToAdminUsers") for r in rows))
        self.assertTrue(any(r["PID"] == 1500 and r["Indicator"] == "profiling library" for r in rows))
        self.assertTrue(any(r["PID"] == 1500 and r["Indicator"].startswith("UVM tools") for r in rows))

    def test_containers_and_toolkit_cves(self):
        _, rows = run("nvidia.containers")
        cves = {r["Name"]: r for r in rows if r["Kind"] == "cve"}
        self.assertIn("VULNERABLE", cves["CVE-2024-0132"]["Container/Status"])
        self.assertIn("VULNERABLE", cves["CVE-2025-23266"]["Container/Status"])
        proc = next(r for r in rows if r["Kind"] == "process" and r["PID"] == 1900)
        self.assertEqual(proc["Runtime/Version"], "docker")
        self.assertEqual(proc["Container/Status"], "0123456789ab")

    def test_daemons(self):
        _, rows = run("nvidia.daemons")
        pers = [r for r in rows if r["Daemon"] == "nvidia-persistenced"]
        self.assertEqual({r["PID"] for r in pers}, {900, 2200})
        self.assertTrue(next(r for r in pers if r["PID"] == 900)["Expected path"])
        self.assertFalse(next(r for r in pers if r["PID"] == 2200)["Expected path"])
        self.assertIn("nvidia-persistenced.service", next(r for r in pers if r["PID"] == 900)["Unit files"])

    def test_computecache(self):
        grid, rows = run("nvidia.computecache")
        by_path = {r["Path"]: r for r in rows}
        cub = by_path["/home/alice/.nv/ComputeCache/3/a/5c1e0f"]
        self.assertIn("cubin sm_89", cub["Content"])
        self.assertIn("train_step", cub["Kernels"])
        ptx = by_path["/home/alice/.nv/ComputeCache/7/2/99ab01"]
        self.assertIn("kawpow_hash", ptx["Kernels"])
        self.assertIn("miner-algorithm:kawpow", ptx["Indicators"])
        self.assertIn("/home/alice/.cache/nvidia/GLCache/0ab1/shader.bin", by_path)

    def test_autostart(self):
        _, rows = run("nvidia.autostart", suspicious_only=True)
        entries = {(r["Kind"], r["Entry"]) for r in rows}
        self.assertIn(("vulkan-implicit-layer", "VK_LAYER_capture /tmp/.vk/libVkLayer_capture.so"), entries)
        self.assertIn(("opencl-icd", "/tmp/.cache/libOpenCL-hook.so"), entries)
        self.assertIn(("ld.so.preload", "/usr/local/lib/libgpuhook.so"), entries)
        _, allrows = run("nvidia.autostart")
        self.assertTrue(any(r["Kind"] == "systemd" and "nvidia-persistenced" in r["Entry"] for r in allrows))
        self.assertTrue(any(r["Kind"] == "udev" for r in allrows))


class SystemPlugins(unittest.TestCase):
    def test_devices(self):
        _, rows = run("nvidia.devices")
        vals = {(r["GPU"], r["Field"]): r["Value"] for r in rows}
        self.assertEqual(vals[("GPU 0", "Device")], "NVIDIA GeForce RTX 4090")
        self.assertEqual(vals[("GPU 0", "VBIOS")], "95.02.18.80.5F")
        self.assertIn("N/A", str(vals[("GPU 0", "Serial")]))
        self.assertEqual(vals[("system", "Driver version")], "565.57.01")

    def test_engines(self):
        _, rows = run("nvidia.engines")
        self.assertTrue(any(r["GPU"] == 0 and r["Engine"] == "NVENC" and r["Value"] == "12" for r in rows))
        self.assertTrue(any(r["Metric"] == "throttle reasons" and r["Value"] == "SwPowerCap" for r in rows))

    def test_ecc(self):
        _, rows = run("nvidia.ecc")
        self.assertTrue(any(r["GPU"] == 1 and r["Value"] == "0x12340000" for r in rows))
        self.assertTrue(any(r["GPU"] == 1 and r["Item"] == "remapped rows" and "uncorrectable=1" in r["Value"]
                            for r in rows))

    def test_devicetree(self):
        _, rows = run("nvidia.devicetree")
        fn = next(r for r in rows if r["Address"] == "0000:01:00.1")
        self.assertIn("audio device", fn["Details"])
        gpu = next(r for r in rows if r["Address"] == "0000:01:00.0" and r["Kind"] == "pci-function")
        self.assertIn("driver nvidia", gpu["Details"])
        self.assertIn("iommu group 14", gpu["Details"])
        self.assertTrue(any(r["Kind"] == "nvlink-peer" for r in rows))

    def test_nvlink(self):
        _, rows = run("nvidia.nvlink")
        self.assertTrue(any(r["GPU"] == 1 and r["Link/Peer"] == "link 0" and r["Status"] == "active" for r in rows))
        self.assertTrue(any(r["Kind"] == "p2p" for r in rows))

    def test_mig(self):
        _, rows = run("nvidia.mig")
        self.assertTrue(any(r["GPU"] == 1 and r["MIG"] == "enabled" for r in rows))
        self.assertIn("gi1/ci0", col(rows, "Instance"))

    def test_driver(self):
        _, rows = run("nvidia.driver")
        items = col(rows, "Item")
        self.assertIn("GPU 0000:01:00.0 GPU Firmware", items)
        fw = [r for r in rows if r["Item"] == "firmware"]
        self.assertEqual(len(fw), 2)
        self.assertEqual(len(fw[0]["SHA256"]), 64)

    def test_modules(self):
        _, rows = run("nvidia.modules")
        snoop = next(r for r in rows if r["Module"] == "gpu_snoop")
        self.assertTrue(snoop["Suspicious"])
        self.assertIn("unsigned", snoop["Reason"])
        self.assertFalse(next(r for r in rows if r["Module"] == "nvidia_uvm")["Suspicious"])
        self.assertEqual(next(r for r in rows if r["Module"] == "nvidia")["Version"], "565.57.01")

    def test_devnodes(self):
        _, rows = run("nvidia.devnodes")
        by = {r["Node"]: r for r in rows}
        self.assertTrue(by["/dev/nvidia1"]["Suspicious"])
        self.assertIn("not a character device", by["/dev/nvidia1"]["Notes"])
        self.assertTrue(by["/dev/nvidia-caps/nvidia-cap2"]["Suspicious"])
        self.assertFalse(by["/dev/nvidia-caps/nvidia-cap1"]["Suspicious"])
        self.assertFalse(by["/dev/nvidia0"]["Suspicious"])
        self.assertEqual(by["/dev/nvidia0"]["Major"], 195)

    def test_params(self):
        _, rows = run("nvidia.params", flagged_only=True)
        sev = {r["Parameter"]: r["Severity"] for r in rows}
        self.assertEqual(sev["RmProfilingAdminOnly"], "high")
        self.assertEqual(sev["nvidia NVreg_RestrictProfilingToAdminUsers"], "high")

    def test_xid_live_and_timeline(self):
        grid, rows = run("nvidia.xid")
        codes = col(rows, "Xid")
        self.assertEqual(codes, [31, 13, 79])
        x31 = rows[0]
        self.assertEqual(x31["PID"], 1400)
        self.assertIn("fault VA 0x7f1234560000", x31["Details"])
        self.assertIn("FAULT_PDE", x31["Details"])
        self.assertEqual(x31["Time"].year, 2026)
        p = PLUGINS["nvidia.xid"](ctx_for(FakeSystemSource(default_scenario())), {})
        self.assertEqual(len(list(p.generate_timeline())), 3)

    def test_xid_log_file_without_live(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "kern.log")
            with open(path, "w") as fh:
                fh.write("2026-11-16T10:00:00+0000 host kernel: NVRM: Xid (PCI:0000:01:00): 79, pid='<unknown>', "
                         "name=<unknown>, GPU has fallen off the bus.\n")
            rows = PLUGINS["nvidia.xid"](Context(), {"log_file": path}).run().as_dicts()
            self.assertEqual(rows[0]["Xid"], 79)
            self.assertEqual(rows[0]["Name"], "GPU has fallen off the bus")
            self.assertEqual(rows[0]["Time"].hour, 10)
        with self.assertRaises(RequirementError):
            PLUGINS["nvidia.xid"](Context(), {}).run()

    def test_bugreport(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_bugreport(os.path.join(d, "nvidia-bug-report.log.gz"))
            rows = PLUGINS["nvidia.bugreport"](Context(), {"file": path}).run().as_dicts()
        vals = {r["Item"]: r["Value"] for r in rows}
        self.assertEqual(vals["driver version"], "565.57.01")
        self.assertEqual(vals["00000000:01:00.0 Product Name"], "NVIDIA GeForce RTX 4090")
        self.assertTrue(any(k.startswith("Xid 31") for k in vals))


class MalwarePlugins(unittest.TestCase):
    def test_gpuxview(self):
        _, rows = run("nvidia.malware.gpuxview")
        by = {r["PID"]: r for r in rows}
        self.assertTrue(by[1300]["NVML compute"] and by[1300]["Device fds"] and by[1300]["Runtime libs"])
        self.assertIn("not listed by NVML", by[1400]["Note"])
        self.assertFalse(by[2100]["In /proc"])
        self.assertTrue(by[1700]["NVML graphics"])

    def test_rawioctl(self):
        _, rows = run("nvidia.malware.rawioctl")
        self.assertEqual(col(rows, "PID"), [1800])

    def test_libhooks(self):
        _, rows = run("nvidia.malware.libhooks")
        hooked = [r for r in rows if r["Status"].startswith("MODIFIED")]
        self.assertEqual(len(hooked), 1)
        self.assertEqual(hooked[0]["PID"], 1200)
        self.assertEqual(hooked[0]["Modified bytes"], 5)
        self.assertIn("cuLaunchKernel+0x0", hooked[0]["Symbols"])
        self.assertTrue(any(r["PID"] == 1300 and r["Status"] == "clean" for r in rows))

    def test_injection(self):
        _, rows = run("nvidia.malware.injection")
        t = {(r["PID"], r["Technique"], r["Severity"]) for r in rows}
        self.assertIn((1500, "environment CUDA_INJECTION64_PATH", "high"), t)
        self.assertIn((1400, "environment LD_PRELOAD", "high"), t)
        self.assertIn((1500, "instrumentation library loaded", "low"), t)
        self.assertIn((1500, "executable mapping from temporary/fileless location", "high"), t)

    def test_masquerade(self):
        _, rows = run("nvidia.malware.masquerade")
        f = {(r["PID"], r["Finding"]) for r in rows}
        self.assertIn((1400, "kernel-thread style name [kworker/0:1] on a user-space process"), f)
        self.assertIn((2200, "NVIDIA daemon name nvidia-persistenced running from /home/bob/.local/bin/"
                             "nvidia-persistenced instead of its packaged path /usr/bin/nvidia-persistenced"), f)
        self.assertNotIn(1200, col(rows, "PID"))   # python3 vs python3.10 is fine
        self.assertNotIn(900, col(rows, "PID"))    # real persistenced

    def test_deletedexe(self):
        _, rows = run("nvidia.malware.deletedexe")
        self.assertIn((1400, "executable"), {(r["PID"], r["Object"]) for r in rows})

    def test_integrity(self):
        _, rows = run("nvidia.malware.integrity")
        mod = [r for r in rows if r["Result"].startswith("MODIFIED")]
        self.assertEqual(mod[0]["Object"], "/usr/bin/nvidia-smi")
        self.assertIn("content checksum differs", mod[0]["Result"])
        self.assertTrue(any(r["Check"] == "sha256" and r["Object"] == "/usr/lib/x86_64-linux-gnu/libcuda.so.1"
                            for r in rows))

    def test_capture(self):
        _, rows = run("nvidia.malware.capture")
        sev = {(r["PID"], r["Indicator"]): r["Severity"] for r in rows}
        self.assertEqual(sev[(1700, "NvFBC capture session")], "high")
        self.assertEqual(sev[(1700, "capture/encode library loaded")], "high")

    def test_cryptojack(self):
        _, rows = run("nvidia.malware.cryptojack")
        miner = [r for r in rows if r["PID"] == 1300]
        cats = {r["Category"] for r in miner}
        self.assertTrue({"miner-software", "mining-pool"} <= cats)
        self.assertTrue(all(r["Severity"] == "high" for r in miner
                            if r["Category"] not in ("utilization", "sustained load")))
        self.assertTrue(any(r["PID"] == 2000 and r["Category"] == "sustained load" for r in rows))
        self.assertFalse(any(r["PID"] == 1200 and r["Severity"] == "high" for r in rows))


class RecordReplay(unittest.TestCase):
    PLUGINS_TO_CHECK = ["nvidia.pslist", "nvidia.pstree", "nvidia.envars", "nvidia.libs", "nvidia.devices",
                        "nvidia.xid", "nvidia.computecache", "nvidia.autostart", "nvidia.modules", "nvidia.devnodes",
                        "nvidia.malware.gpuxview", "nvidia.malware.integrity",
                        "nvidia.malware.cryptojack", "nvidia.accounting"]

    def test_snapshot_replay_is_identical(self):
        rec = RecordingSource(FakeSystemSource(default_scenario()))
        live_out = {n: render_to_string(PLUGINS[n](ctx_for(rec), {}).run(), "json") for n in self.PLUGINS_TO_CHECK}
        snap = json.loads(json.dumps(rec.snapshot()))
        replay = ReplaySource(snap)
        for n in self.PLUGINS_TO_CHECK:
            with self.subTest(plugin=n):
                self.assertEqual(render_to_string(PLUGINS[n](ctx_for(replay), {}).run(), "json"), live_out[n])
        self.assertEqual(replay.misses, [])

    def test_context_uses_snapshot_from_container_metadata(self):
        rec = RecordingSource(FakeSystemSource(default_scenario()))
        PLUGINS["nvidia.pslist"](ctx_for(rec), {}).run().rows
        ctx = Context()
        ctx.metadata = {"live_snapshot": json.loads(json.dumps(rec.snapshot()))}
        self.assertTrue(ctx.has_live())
        rows = PLUGINS["nvidia.pslist"](ctx, {}).run().as_dicts()
        self.assertIn(1300, col(rows, "PID"))


class GapDetectors(unittest.TestCase):
    """Accounting cross-view, raw/VFIO access and watchdog tampering."""

    PROC_KEYS = ("compute_processes", "graphics_processes", "mps_compute_processes")

    def test_unaccounted_memory_and_idle_listing(self):
        sc = default_scenario()
        dev = sc["nvml"]["devices"][0]
        listed = sum(p["used_memory"] or 0 for k in self.PROC_KEYS for p in dev.get(k) or [])
        dev["memory"]["used"] = listed + (3 << 30)
        _, rows = run("nvidia.malware.unaccounted", FakeSystemSource(sc))
        self.assertIn("belongs to no listed process", rows[0]["Finding"])
        for k in self.PROC_KEYS:
            for p in dev.get(k) or []:
                p["used_memory"] = None  # WDDM: no per-process memory
        _, rows = run("nvidia.malware.unaccounted", FakeSystemSource(sc))
        self.assertIn("does not report per-process memory", rows[0]["Finding"])
        for k in self.PROC_KEYS:
            dev[k] = []
        dev["utilization"]["gpu"] = 97
        _, rows = run("nvidia.malware.unaccounted", FakeSystemSource(sc))
        self.assertIn("busy with no process listed", rows[0]["Finding"])

    def test_rawaccess_vfio(self):
        sc = default_scenario()
        base = "/sys/bus/pci/devices"
        nl = chr(10)
        sc["files"].update({base + "/0000:01:00.0/vendor": "0x10de" + nl, base + "/0000:01:00.0/class": "0x030000" + nl,
                            base + "/0000:02:00.0/vendor": "0x10de" + nl, base + "/0000:02:00.0/class": "0x030200" + nl,
                            base + "/0000:03:00.0/vendor": "0x8086" + nl})
        sc["links"].update({base + "/0000:01:00.0/driver": "../../../bus/pci/drivers/nvidia",
                            base + "/0000:02:00.0/driver": "../../../bus/pci/drivers/vfio-pci",
                            base + "/0000:02:00.0/iommu_group": "../../../kernel/iommu_groups/12"})
        template = sc["procs"][min(sc["procs"], key=int)]
        sc["procs"]["4242"] = dict(template, pid=4242, comm="tinynv", fds=[[5, "/dev/vfio/12"]],
                                   maps=[{"start": 0x7F0000000000, "end": 0x7F0001000000, "perms": "rw-s", "offset": 0,
                                          "dev": "00:00", "inode": 1, "path": base + "/0000:02:00.0/resource1"}])
        _, rows = run("nvidia.malware.rawaccess", FakeSystemSource(sc))
        by = {r["Object"]: r for r in rows}
        self.assertIn("vfio-pci", by["0000:02:00.0"]["Finding"])
        self.assertNotIsInstance(by["0000:01:00.0"]["Finding"], str)  # n/a: bound to nvidia, nothing to report
        self.assertNotIn("0000:03:00.0", by)
        self.assertIn("VFIO handle", by["4242 tinynv"]["Finding"])

    def test_watchdog_windows_and_linux(self):
        sc = default_scenario()
        sc["platform"] = {"system": "Windows", "wsl": False}
        key = r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
        sc["registry"] = {key + "\\TdrLevel": 0, key + "\\TdrDelay": 60}
        _, rows = run("nvidia.malware.watchdog", FakeSystemSource(sc))
        by = {r["Setting"].rsplit("\\", 1)[1]: r for r in rows}
        self.assertIn("disabled", by["TdrLevel"]["Finding"])
        self.assertIn("60 s", by["TdrDelay"]["Finding"])
        self.assertEqual(by["TdrDebugMode"]["Value"], "not set (default)")
        sc = default_scenario()
        sc["files"]["/sys/module/i915/parameters/enable_hangcheck"] = "N" + chr(10)
        _, rows = run("nvidia.malware.watchdog", FakeSystemSource(sc))
        self.assertIn("hang check disabled", {r["Setting"]: r for r in rows}["i915.enable_hangcheck"]["Finding"])


class ComputeModeAndEcc(unittest.TestCase):
    def test_exclusive_compute_mode_flagged(self):
        sc = default_scenario()
        sc["nvml"]["devices"][0]["compute_mode"] = "Exclusive_Process"
        _, rows = run("nvidia.malware.cryptojack", FakeSystemSource(sc))
        cm = [r for r in rows if r["Category"] == "compute mode"]
        self.assertEqual(len(cm), 1)
        self.assertIn("Exclusive_Process", cm[0]["Indicator"])
        self.assertIn("persistence mode on", cm[0]["Indicator"])

    def test_ecc_rowhammer_exposure(self):
        sc = default_scenario()
        dev = sc["nvml"]["devices"][0]
        dev["ecc_mode"] = {"current": 0, "pending": 0}
        dev["ecc_errors"] = {"volatile_corrected": 512, "aggregate_corrected": 900,
                             "volatile_uncorrected": 0, "aggregate_uncorrected": 0}
        _, rows = run("nvidia.ecc", FakeSystemSource(sc))
        by = {r["Item"]: r for r in rows if r["GPU"] == dev["index"]}
        self.assertIn("Rowhammer", by["ECC mode"]["Assessment"])
        self.assertIn("burst", by["ECC errors volatile corrected"]["Assessment"])


def windows_scenario():
    sc = default_scenario()
    sc["platform"] = {"system": "Windows", "wsl": False}
    appdata = "C:\\Users\\u\\AppData\\Local\\Temp\\"
    sc["windows"] = {
        "processes": [{"pid": 500, "ppid": 4, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe"},
                      {"pid": 600, "ppid": 500, "name": "chrome.exe", "path": "C:\\Program Files\\chrome.exe"},
                      {"pid": 601, "ppid": 600, "name": "chrome.exe", "path": "C:\\Program Files\\chrome.exe"},
                      {"pid": 700, "ppid": 500, "name": "ArmouryCrate.exe", "path": appdata + "ArmouryCrate.exe"},
                      {"pid": 800, "ppid": 500, "name": "xmrig.exe", "path": "C:\\ProgramData\\xmrig.exe"},
                      {"pid": 900, "ppid": 500, "name": "notepad.exe", "path": "C:\\Windows\\notepad.exe"}],
        "modules": {"600": [{"name": "d3d12.dll", "path": "C:\\Windows\\System32\\d3d12.dll"}],
                    "601": [{"name": "d3d12.dll", "path": "C:\\Windows\\System32\\d3d12.dll"}],
                    "700": [{"name": "OpenCL.dll", "path": "C:\\Windows\\System32\\OpenCL.dll"},
                            {"name": "nvopencl64.dll", "path": "C:\\Windows\\System32\\nvopencl64.dll"}],
                    "800": [{"name": "nvcuda.dll", "path": "C:\\Windows\\System32\\nvcuda.dll"}],
                    "900": []},
        "windowed": [500, 600],
        "gpu": {"available": True, "processes": {
            "601": {"engines": {"3D": 12.0}, "luids": ["0x0_0x1"], "dedicated": 1 << 26, "shared": 0,
                    "by_luid": {"0x0_0x1": {"dedicated": 1 << 26, "shared": 0}}},
            "700": {"engines": {"Compute_0": 35.0}, "luids": ["0x0_0x1"], "dedicated": 1 << 24, "shared": 0,
                    "by_luid": {"0x0_0x1": {"dedicated": 1 << 24, "shared": 0}}},
            "800": {"engines": {"Compute_0": 99.0}, "luids": ["0x0_0x1"], "dedicated": 3 << 30, "shared": 0,
                    "by_luid": {"0x0_0x1": {"dedicated": 3 << 30, "shared": 0}}}},
                "adapters": {"0x00000000_0x00000001": {"dedicated": (3 << 30) + (1 << 26) + (1 << 24), "shared": 0}}},
        "adapters": [{"luid": "0x00000000_0x00000001", "name": "NVIDIA GeForce RTX 4050 Laptop GPU",
                      "vendor_id": 0x10DE, "device_id": 0x28A1, "dedicated_video_memory": 6 << 30}],
        "cmdlines": {"600": "chrome.exe", "601": "chrome.exe --type=gpu-process",
                     "700": appdata + "ArmouryCrate.exe", "800": "xmrig.exe -o stratum+tcp://pool:3333 --cuda"},
        "signatures": {"c:\\program files\\chrome.exe": {"status": "valid", "signer": "Google LLC", "kind": "embedded"},
                       appdata.lower() + "armourycrate.exe": {"status": "unsigned", "signer": None, "kind": "embedded"},
                       "c:\\windows\\system32\\opencl.dll": {"status": "valid", "signer": "NVIDIA Corporation",
                                                            "kind": "embedded"},
                       "c:\\windows\\system32\\nvopencl64.dll": {"status": "BAD DIGEST (modified after signing)",
                                                                "signer": None, "kind": "embedded"}}}
    return sc


class WindowsTriage(unittest.TestCase):
    def test_gpuprocs(self):
        _, rows = run("windows.gpuprocs", FakeSystemSource(windows_scenario()))
        by = {r["PID"]: r for r in rows}
        self.assertNotIn(900, by)                       # no GPU use, no runtime
        self.assertTrue(by[601]["Window"])              # inherits chrome.exe's window
        self.assertEqual(by[601]["Severity"], "info")
        self.assertEqual(by[700]["Severity"], "high")   # OpenCL loader, no window, %TEMP% path
        self.assertIn("OpenCL", by[700]["GPU runtimes"])
        self.assertIn("user-writable", by[700]["Attention"])
        self.assertEqual(by[800]["Severity"], "high")   # miner name + CUDA + busy without a window
        self.assertIn("indicator", by[800]["Attention"])
        # command line, signatures and adapter names
        self.assertIn("indicator in command line", by[800]["Attention"])
        self.assertIn("stratum+tcp", by[800]["CommandLine"])
        self.assertIn("GPU-using image is unsigned", by[700]["Attention"])
        self.assertIn("BAD DIGEST", by[700]["Attention"])      # tampered OpenCL driver DLL
        self.assertEqual(by[601]["Signature"], "valid (Google LLC)")
        self.assertEqual(by[601]["Adapters"], "NVIDIA GeForce RTX 4050 Laptop GPU")

    def test_scraper_windows_and_nvml(self):
        sc = windows_scenario()
        g = sc["windows"]["gpu"]["processes"]["700"]
        g["by_luid"]["0x0_0x1"]["dedicated"] = 5 << 30  # 5 GiB of a 6 GiB card
        _, rows = run("nvidia.malware.scraper", FakeSystemSource(sc))
        self.assertEqual([(r["PID"], r["Severity"]) for r in rows], [(700, "high")])
        self.assertIn("no visible window", rows[0]["Finding"])
        lin = default_scenario()
        dev = lin["nvml"]["devices"][0]
        dev["compute_processes"][0]["used_memory"] = int(dev["memory"]["total"] * 0.9)
        _, rows = run("nvidia.malware.scraper", FakeSystemSource(lin))
        self.assertEqual([r["PID"] for r in rows], [dev["compute_processes"][0]["pid"]])

    def test_unaccounted_windows_counters(self):
        sc = windows_scenario()
        _, rows = run("nvidia.malware.unaccounted", FakeSystemSource(sc))
        self.assertEqual(rows[0]["Name"], "NVIDIA GeForce RTX 4050 Laptop GPU")
        self.assertEqual(rows[0]["Unaccounted"], "0 B")
        self.assertFalse(isinstance(rows[0]["Finding"], str))
        sc["windows"]["gpu"]["adapters"]["0x00000000_0x00000001"]["dedicated"] += 2 << 30  # hidden 2 GiB
        _, rows = run("nvidia.malware.unaccounted", FakeSystemSource(sc))
        self.assertIn("belongs to no process", rows[0]["Finding"])


@unittest.skipUnless(os.name == "nt", "Windows APIs")
class WindowsApiTests(unittest.TestCase):
    """The real Windows readers on this machine (no fakes)."""

    def test_signature_embedded_catalog_and_tampered(self):
        import shutil
        from keto.live import windows as w
        self.assertEqual(w.signature(os.path.join(os.environ["SystemRoot"], "explorer.exe"))["status"], "valid")
        cat = w.signature(os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"))
        self.assertEqual((cat["status"], cat["kind"]), ("valid", "catalog"))
        src = os.path.join(os.environ["SystemRoot"], "System32", "taskmgr.exe")
        with tempfile.TemporaryDirectory() as d:
            copy = os.path.join(d, "taskmgr.exe")
            shutil.copyfile(src, copy)
            self.assertEqual(w.signature(copy)["status"], "valid")
            with open(copy, "r+b") as fh:
                fh.seek(0x2000)
                b = fh.read(1)
                fh.seek(0x2000)
                fh.write(bytes([b[0] ^ 0xFF]))
            self.assertIn("BAD DIGEST", w.signature(copy)["status"])
            unsigned = os.path.join(d, "plain.exe")
            with open(unsigned, "wb") as fh:
                fh.write(b"MZ" + b"\x00" * 510)
            self.assertNotEqual(w.signature(unsigned)["status"], "valid")

    def test_command_line_adapters_regions(self):
        from keto.live import windows as w
        cmd = w.command_line(os.getpid())
        self.assertIn("python", (cmd or "").lower())
        ads = w.adapters()
        self.assertTrue(all(a["luid"].startswith("0x") for a in ads))
        h, regs = w.regions(os.getpid())
        try:
            img = [r for r in regs if r["type"] == "image" and r["path"].lower().endswith("python.exe")]
            self.assertTrue(img)
            data, bad = w.read_region(h, img[0]["start"], 2)
            self.assertEqual((data, bad), (b"MZ", 0))
        finally:
            w.close_handle(h)

    def test_gpuprocs_snapshot_replay(self):
        rec = RecordingSource(FakeSystemSource(windows_scenario()))
        live = PLUGINS["windows.gpuprocs"](ctx_for(rec), {}).run().as_dicts()
        replay = ReplaySource(json.loads(json.dumps(rec.snapshot())))
        again = PLUGINS["windows.gpuprocs"](ctx_for(replay), {}).run().as_dicts()
        self.assertEqual([r["Severity"] for r in live], [r["Severity"] for r in again])

    def test_gpuprocs_needs_windows(self):
        with self.assertRaises(UnsupportedError):
            run("windows.gpuprocs")


if __name__ == "__main__":
    unittest.main()
