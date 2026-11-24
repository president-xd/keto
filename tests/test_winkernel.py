"""Windows kernel engine (keto.winmem) and windows.kernel.* plugins on a synthetic x64 kernel image.

The image (keto.testing.synth_windows) has real page tables with deliberately non-contiguous frames, a low stub,
KUSER_SHARED_DATA, an ntoskrnl PE with RSDS, processes (one straddling two frames, one unlinked by DKOM, one
exited), handle tables, VADs, the object directory and a driver whose IRP_MJ_DEVICE_CONTROL is redirected."""

import glob
import io
import json
import os
import struct
import tempfile
import unittest

from keto import cli
from keto.framework.context import Context
from keto.framework.exceptions import RequirementError
from keto.framework.layers import BytesLayer
from keto.framework.plugin import PLUGINS, load_plugins
from keto.framework.treegrid import NotAvailableValue
from keto.testing import synth_windows as sw
from keto.winmem import kernel as kmod
from keto.winmem.paging import PageFault, X64Paging


def run_plugin(truth, name, image_flag="host_image", **opts):
    load_plugins()
    cls = PLUGINS[name]
    ctx = Context(**{image_flag: truth["image"]}, output_dir=opts.pop("output_dir", None))
    o = {r.name: r.default for r in cls.REQUIREMENTS}
    o["symbols_dir"] = truth["symbols_dir"]
    o.update(opts)
    try:
        grid = cls(ctx, o).run()
        cols = [c for c, _ in grid.columns]
        return [{c: (None if isinstance(v, NotAvailableValue) else v) for c, v in zip(cols, row)}
                for _depth, row in grid.rows]
    finally:
        ctx.close()


class SyntheticKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.truth = sw.build(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def rows(self, name, **opts):
        return run_plugin(self.truth, name, **opts)

    def test_info_locates_kernel_through_low_stub(self):
        info = {r["Property"]: r["Value"] for r in self.rows("windows.kernel.info")}
        self.assertEqual(info["DTB"], "0x%x" % self.truth["dtb"])
        self.assertEqual(info["kernel base"], "0x%x" % sw.KBASE)
        self.assertEqual(info["kernel PDB"], "ntkrnlmp.pdb " + sw.KEY)
        self.assertEqual(info["build"], "26100")
        self.assertEqual(info["image format"], "raw")
        self.assertIn("low stub", " ".join(r["Value"] for r in self.rows("windows.kernel.info")
                                           if r["Property"] == "note"))

    def test_raw_image_given_with_f_is_physical(self):
        info = {r["Property"]: r["Value"] for r in run_plugin(self.truth, "windows.kernel.info", image_flag="image")}
        self.assertEqual(info["layer"], "vram")
        self.assertEqual(info["kernel base"], "0x%x" % sw.KBASE)

    def test_self_reference_fallback_without_low_stub(self):
        with open(self.truth["image"], "rb") as fh:
            data = bytearray(fh.read())
        stub = self.truth["low_stub_pa"]
        data[stub:stub + 0x100] = bytes(0x100)
        loc = kmod.locate(BytesLayer("p", bytes(data)))
        self.assertEqual((loc.dtb, loc.base), (self.truth["dtb"], sw.KBASE))
        self.assertIn("self-referencing", " ".join(loc.notes))

    def test_overrides_and_refusals(self):
        with open(self.truth["image"], "rb") as fh:
            layer = BytesLayer("p", fh.read())
        loc = kmod.locate(layer, dtb=self.truth["dtb"], kernel_base=sw.KBASE)
        self.assertEqual(loc.codeview.key, sw.KEY)
        with self.assertRaises(RequirementError) as cm:
            kmod.locate(BytesLayer("p", os.urandom(1 << 20)))
        self.assertIn("could not locate a Windows x64 kernel", str(cm.exception))
        with self.assertRaises(RequirementError):
            kmod.locate(layer, dtb=self.truth["dtb"], kernel_base=sw.KBASE + 0x1000)

    def test_missing_symbols_and_wrong_symbols(self):
        with tempfile.TemporaryDirectory() as empty:
            info = run_plugin(dict(self.truth, symbols_dir=empty), "windows.kernel.info")
        notes = " ".join(r["Value"] for r in info if r["Property"] == "note")
        self.assertIn("self-profile", notes)
        self.assertIn("keto pdb fetch --name ntkrnlmp.pdb --key " + sw.KEY, notes)
        self.assertIn("self-profile", {r["Property"]: r["Value"] for r in info}["symbols"])
        doc = sw.isf_document()
        doc["metadata"]["windows"]["pdb"]["GUID"] = "0" * 32
        with tempfile.TemporaryDirectory() as d:
            wrong = os.path.join(d, "wrong.json")
            with open(wrong, "w") as fh:
                json.dump(doc, fh)
            with self.assertRaises(RequirementError) as cm:
                run_plugin(self.truth, "windows.kernel.pslist", isf=wrong)
        self.assertIn("does not match the image", str(cm.exception))

    def test_pslist(self):
        rows = {r["PID"]: r for r in self.rows("windows.kernel.pslist")}
        self.assertEqual(sorted(rows), [4, 1200, 5000])  # miner.exe is unlinked, gone.exe exited
        py = rows[5000]
        self.assertEqual((py["PPID"], py["Name"], py["Session"]), (1200, "python.exe", 1))  # straddling body
        self.assertEqual(py["Path"], "\\Device\\HarddiskVolume3\\Python\\python.exe")
        self.assertEqual(int(py["DxgProcess"]), 0xFFFF9A80BEEF0000)
        self.assertEqual(py["CreateTime"], "2026-11-20 00:00:00 UTC")
        only = self.rows("windows.kernel.pslist", pid=[1200])
        self.assertEqual([r["PID"] for r in only], [1200])
        with self.assertRaises(RequirementError):
            self.rows("windows.kernel.pslist", pid=[99999])

    def test_psscan_finds_hidden_and_exited(self):
        rows = {r["PID"]: r for r in self.rows("windows.kernel.psscan")}
        self.assertEqual(sorted(rows), [4, 1200, 3300, 5000, 6100])
        self.assertTrue(all(rows[p]["Listed"] is True for p in (4, 1200, 5000)))
        self.assertIs(rows[3300]["Listed"], False)
        self.assertIn("unlinked", rows[3300]["Note"])
        self.assertEqual(rows[6100]["Note"], "exited")

    def test_modules(self):
        rows = self.rows("windows.kernel.modules")
        self.assertEqual([r["Name"] for r in rows], ["ntoskrnl.exe", "dxgkrnl.sys", "nvlddmkm.sys", "evil.sys",
                                                     "Wdf01000.sys", "HidUsb.sys"])
        self.assertEqual(rows[0]["PDB"], "ntkrnlmp.pdb " + sw.KEY)
        self.assertEqual(rows[2]["GPU stack"], "NVIDIA kernel-mode driver")

    def test_handles_classify_gpu_objects(self):
        rows = self.rows("windows.kernel.handles", pid=[5000])
        names = {r["Name"]: r for r in rows}
        self.assertEqual(names["\\Device\\DxgKrnl"]["Type"], "File")
        self.assertIn("DirectX graphics kernel", names["\\Device\\DxgKrnl"]["GPU"])
        cubins = [r for r in rows if r["Name"].endswith("nvcubins.bin")]
        self.assertEqual(len(cubins), 1)
        self.assertIn("CUDA driver kernel archive", cubins[0]["GPU"])
        self.assertEqual(cubins[0]["Access"], "0x12019f")
        self.assertEqual(sorted(r["Handle"] for r in rows), [4, 8])

    def test_vads_and_envars(self):
        rows = self.rows("windows.kernel.vadinfo", pid=[5000])
        by_start = {int(r["Start"]): r for r in rows}
        self.assertEqual(by_start[0x7FFB00000000]["File"], "\\Windows\\System32\\nvcuda64.dll")
        self.assertEqual(by_start[0x7FFB00000000]["Protection"], "PAGE_EXECUTE_WRITECOPY")
        self.assertEqual(int(by_start[0x1F0000000]["End"]), 0x1F0003FFF)
        self.assertTrue(by_start[0x1F0000000]["Private"])
        env = self.rows("windows.kernel.envars", pid=[5000])
        self.assertEqual([(r["Variable"], r["Severity"]) for r in env], [("CUDA_INJECTION64_PATH", "high")])
        allenv = {r["Variable"] for r in self.rows("windows.kernel.envars", pid=[5000], all=True)}
        self.assertEqual(allenv, {"CUDA_INJECTION64_PATH", "PATH"})

    def test_driverirp_flags_redirected_dispatch(self):
        found = {(r["Driver"], r["IRP"]): r for r in self.rows("windows.kernel.driverirp") if r["Finding"]}
        self.assertEqual(sorted(found), [("\\Driver\\Null", "CREATE"), ("\\Driver\\nvlddmkm", "DEVICE_CONTROL")])
        self.assertIn("another driver (evil.sys)", found[("\\Driver\\nvlddmkm", "DEVICE_CONTROL")]["Finding"])
        self.assertIn("outside every loaded module", found[("\\Driver\\Null", "CREATE")]["Finding"])
        everything = self.rows("windows.kernel.driverirp", all=True)
        self.assertEqual(len(everything), 3 * 28)
        hid = [r for r in everything if r["Driver"] == "\\Driver\\HidUsb"]
        self.assertEqual({r["Owner"] for r in hid}, {"framework: KMDF"})  # KMDF owns its clients' dispatch

    def test_gpuprocs(self):
        rows = {r["PID"]: r for r in self.rows("windows.kernel.gpuprocs")}
        self.assertEqual(sorted(rows), [1200, 5000])
        self.assertTrue(rows[5000]["Compute"])
        self.assertEqual(rows[5000]["Runtimes"], "CUDA driver")
        hidden = {r["PID"]: r for r in self.rows("windows.kernel.gpuprocs", hidden=True)}
        self.assertIn(3300, hidden)
        self.assertIn("NOT on the active process list", hidden[3300]["Findings"])
        self.assertIn("user-writable path", hidden[3300]["Findings"])

    def test_procdump_feeds_artifactscan(self):
        with tempfile.TemporaryDirectory() as out:
            rows = self.rows("windows.kernel.procdump", pid=[5000], output_dir=out)
            self.assertEqual((rows[0]["Resident pages"], rows[0]["Not resident"]), (3, 65))
            dump = glob.glob(os.path.join(out, "*.keto"))[0]
            buf = os.path.join(out, "scan.txt")
            self.assertEqual(cli.main(["-f", dump, "-q", "-r", "json", "--output-file", buf, "nvidia.artifactscan"]), 0)
            with open(buf) as fh:
                hits = json.load(fh)
            ptx = [h for h in hits if h.get("Kind") == "ptx"]
            self.assertEqual(len(ptx), 1)
            self.assertIn("steal_kernel", ptx[0]["Kernels"])
            ctx = Context(image=dump)
            try:
                layer = ctx.layers["process"]
                self.assertEqual(layer.read(0x1F0001000, 16), b"TRANSITION-PAGE!")  # standby page kept
                self.assertEqual(ctx.metadata["process"]["pid"], 5000)
                self.assertEqual(len(ctx.metadata["process"]["mappings"]), 2)
            finally:
                ctx.close()
            with self.assertRaises(RequirementError):
                self.rows("windows.kernel.procdump", output_dir=out)  # --pid required

    def test_report_and_timeliner(self):
        from keto import report
        old = os.environ.get("KETO_SYMBOLS")
        os.environ["KETO_SYMBOLS"] = self.truth["symbols_dir"]
        try:
            ctx = Context(host_image=self.truth["image"])
            try:
                rep = report.build(ctx, include_live=False)
                titles = sorted((f["plugin"], f["severity"]) for f in rep["findings"]
                                if f["plugin"].startswith("windows."))
                self.assertEqual(titles, [("windows.kernel.driverirp", "high"), ("windows.kernel.driverirp", "medium"),
                                          ("windows.kernel.envars", "high"),
                                          ("windows.kernel.psscan", "high")])
                cov = {c["plugin"]: c["status"] for c in rep["coverage"] if c["plugin"].startswith("windows.")}
                self.assertEqual(set(cov.values()), {"ok"})
            finally:
                ctx.close()
            rows = run_plugin(self.truth, "timeliner", image_flag="image")
            created = [r for r in rows if "Windows process" in str(r.get("Description", ""))]
            self.assertEqual(len(created), 3)
        finally:
            if old is None:
                del os.environ["KETO_SYMBOLS"]
            else:
                os.environ["KETO_SYMBOLS"] = old

    def test_not_windows_is_cheap_and_clear(self):
        from keto.winmem.session import looks_windows
        with tempfile.TemporaryDirectory() as d:
            raw = os.path.join(d, "vram.bin")
            with open(raw, "wb") as fh:
                fh.write(os.urandom(4 << 20))
            ctx = Context(image=raw)
            try:
                self.assertFalse(looks_windows(ctx))
            finally:
                ctx.close()
            ctx = Context(image=self.truth["image"])
            try:
                self.assertTrue(looks_windows(ctx))
            finally:
                ctx.close()

    def test_pdb_command_identifies_image(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "o.txt")
            self.assertEqual(cli.main(["-f", self.truth["image"], "--output-file", out, "pdb", "info",
                                       "--symbols-dir", self.truth["symbols_dir"]]), 0)
            with open(out) as fh:
                text = fh.read()
        self.assertIn(sw.KEY, text)
        self.assertIn(".json", text)  # found in the Volatility-layout symbol directory


class SelfProfileTests(unittest.TestCase):
    """No PDB/ISF: types derived from the kernel image must equal the ground truth, and every plugin must give the
    same rows as with the symbol file."""

    PLUGINS = [("windows.kernel.pslist", {}), ("windows.kernel.psscan", {}), ("windows.kernel.modules", {}),
               ("windows.kernel.handles", {}), ("windows.kernel.vadinfo", {}), ("windows.kernel.envars", {"all": True}),
               ("windows.kernel.driverirp", {}), ("windows.kernel.gpuprocs", {"hidden": True})]

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.truth = sw.build(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_derived_layout_matches_ground_truth(self):
        from keto.winmem import selfprofile
        with open(self.truth["image"], "rb") as fh:
            layer = BytesLayer("p", fh.read())
        loc = kmod.locate(layer)
        table, notes = selfprofile.build(layer, loc)
        for member, (want, _t) in sw.STRUCTS["_EPROCESS"][1].items():
            if table.has_member("_EPROCESS", member):
                self.assertEqual(table.offsetof("_EPROCESS", member), want, member)
        for member in ("UniqueProcessId", "ActiveProcessLinks", "ImageFileName", "Peb", "CreateTime", "ExitTime",
                       "DxgProcess", "ObjectTable", "VadRoot", "SeAuditProcessCreationInfo", "Session", "Protection",
                       "InheritedFromUniqueProcessId", "WoW64Process", "Win32Process"):
            self.assertTrue(table.has_member("_EPROCESS", member), member)
        self.assertEqual(table.offsetof("_ETHREAD", "Cid"), 0x478)
        self.assertEqual(table.offsetof("_MM_SESSION_SPACE", "SessionId"), 8)
        self.assertEqual(table.values["ObHeaderCookie"], sw.COOKIE)
        self.assertEqual(table.rva("PsActiveProcessHead"), sw.SYMBOL_RVAS["PsActiveProcessHead"])
        self.assertEqual(table.rva("ObTypeIndexTable"), sw.SYMBOL_RVAS["ObTypeIndexTable"])
        root = struct.unpack("<Q", layer.read(self._pa(layer, loc, sw.KBASE + sw.SYMBOL_RVAS["ObpRootDirectoryObject"]), 8))[0]
        self.assertEqual(table.values["ObpRootDirectoryObject"], root)
        text = " ".join(notes)
        self.assertIn("accessor code", text)
        self.assertIn("type objects agree", text)
        self.assertIn("layout of 22H2 (build 26100)", text)

    @staticmethod
    def _pa(layer, loc, va):
        return X64Paging(layer.read).translate(loc.dtb, va)[0]

    def test_plugins_agree_with_symbol_file(self):
        def drop(rows, col="Threads"):  # ActiveThreads has no exported accessor: N/A without symbols
            return [{k: v for k, v in r.items() if k != col} for r in rows]

        for name, opts in self.PLUGINS:
            with_isf = run_plugin(self.truth, name, **opts)
            without = run_plugin(self.truth, name, self_profile=True, **opts)
            self.assertEqual(drop(without), drop(with_isf), name)
            self.assertTrue(with_isf, name)

    def test_vad_layout_choice(self):
        from keto.winmem.selfprofile import choose_vad_layout
        image_2004 = (2 << 4) | (7 << 7)       # VadImageMap, EXECUTE_WRITECOPY, not private
        image_1809 = 2 | (7 << 3)
        layout, why = choose_vad_layout([image_2004] * 3, 19041)
        self.assertEqual(layout["PrivateMemory"], (20, 1))
        self.assertNotIn("chosen from the data", why)
        layout, why = choose_vad_layout([image_1809] * 3, 18362)   # 1903: not in the table
        self.assertEqual(layout["VadType"], (0, 3))
        self.assertIn("chosen from the data", why)
        layout, why = choose_vad_layout([image_1809] * 3, 19041)   # data contradicts the table
        self.assertEqual(layout["Protection"], (3, 5))
        layout, why = choose_vad_layout([], 18362)
        self.assertEqual(layout, {})
        # build 26300 (newer than the table): image VADs cannot tell 2004 from 22H2 (they differ only in the
        # PrivateMemory bit), the private VADs can - as on a real 26300 kernel, where bit 21 is set on about half
        private_22h2 = (4 << 7) | (1 << 21)
        layout, why = choose_vad_layout([image_2004] * 4, 26300, [private_22h2, image_2004 | 0x80])
        self.assertEqual(layout["PrivateMemory"], (21, 1))
        self.assertIn("PrivateMemory set on 1 of 2", why)
        layout, _ = choose_vad_layout([image_2004] * 4, 26300)  # no private evidence: nearest listed build
        self.assertEqual(layout["PrivateMemory"], (21, 1))

    def test_decoder(self):
        from keto.winmem.selfprofile import mem_operands
        code = bytes.fromhex("488b81d0010000" "8b4008" "488d4c2420" "488b0511223344" "0fb681ba080000" "c3")
        self.assertEqual(mem_operands(code), [(1, 0x1D0), (0, 8), (1, 0x8BA)])  # SIB and RIP forms skipped
        self.assertEqual(mem_operands(bytes.fromhex("488b41f8c3")), [(1, -8)])


class DumpIntegrationTests(unittest.TestCase):
    """The synthetic kernel as a live-kernel bitmap dump (type 6, the format Task Manager and acquire --method
    livedump produce) without the first MiB, so the kernel must be located from the dump header; opened directly
    and after 'acquire --method import --space sysmem' (the conversion livedump uses)."""

    @classmethod
    def setUpClass(cls):
        from keto.testing import synth_winmem
        cls.tmp = tempfile.TemporaryDirectory()
        cls.truth = sw.build(cls.tmp.name)
        with open(cls.truth["image"], "rb") as fh:
            raw = fh.read()
        pages = {pa // 0x1000: raw[pa:pa + 0x1000] for pa in range(0x100000, len(raw), 0x1000)
                 if any(raw[pa:pa + 0x1000])}
        cls.dump = os.path.join(cls.tmp.name, "live.dmp")
        synth_winmem.write_crash_dump(cls.dump, pages, 6, fields={
            "dtb": cls.truth["dtb"], "ps_loaded_module_list": cls.truth["symbols"]["PsLoadedModuleList"],
            "ps_active_process_head": cls.truth["symbols"]["PsActiveProcessHead"], "bugcheck": 0x161})

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def rows(self, name, image, flag="image", **opts):
        return run_plugin(dict(self.truth, image=image), name, image_flag=flag, **opts)

    def test_dump_opened_directly(self):
        info = {r["Property"]: r["Value"] for r in self.rows("windows.kernel.info", self.dump)}
        self.assertEqual(info["image format"], "windump")
        self.assertEqual(info["layer"], "physical")
        self.assertEqual(info["kernel base"], "0x%x" % sw.KBASE)
        self.assertEqual(info["bugcheck code"], "0x161")
        notes = " ".join(r["Value"] for r in self.rows("windows.kernel.info", self.dump) if r["Property"] == "note")
        self.assertIn("windump header DirectoryTableBase", notes)
        self.assertIn("PsLoadedModuleList", notes)
        self.assertEqual(self.rows("windows.kernel.pslist", self.dump),
                         run_plugin(self.truth, "windows.kernel.pslist"))

    def test_import_converts_and_analyses(self):
        out = os.path.join(self.tmp.name, "imported.keto")
        rc = cli.main(["-q", "--output-file", os.path.join(self.tmp.name, "acq.txt"), "acquire", "--method", "import",
                       "--space", "sysmem", "--input", self.dump, "--out", out])
        self.assertEqual(rc, 0)
        ctx = Context(host_image=out)
        try:
            meta = ctx.host_metadata
            self.assertEqual(meta["memory_image"]["format"], "windump")
            self.assertEqual(meta["windows"]["kernel"]["key"], sw.KEY)
            self.assertEqual(meta["acquisition"]["status"], "complete")
            self.assertEqual(len(meta["acquisition"]["source_digest"]["sha256"]), 64)
        finally:
            ctx.close()
        for name in ("windows.kernel.pslist", "windows.kernel.handles", "windows.kernel.gpuprocs"):
            self.assertEqual(self.rows(name, out, flag="host_image"), run_plugin(self.truth, name), name)
        self.assertEqual(len(self.rows("windows.kernel.pslist", out, flag="host_image", self_profile=True)), 3)


def _local_kernel():
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "ntoskrnl.exe")
    return path if os.name == "nt" and os.path.isfile(path) else None


@unittest.skipUnless(_local_kernel(), "needs a Windows ntoskrnl.exe")
class RealKernelCodeTests(unittest.TestCase):
    """The accessor decoder on Microsoft's own code. On Windows 11 24H2 / 25H2 (builds 26100, 26200) the decoded
    offsets must equal the published layouts (Vergilius Project, _EPROCESS and _ETHREAD of 25H2)."""

    def test_accessors(self):
        from keto.winmem import pe, selfprofile
        img = pe.from_file(_local_kernel())
        exports = img.exports()
        got = selfprofile.accessor_offsets(img.read, exports)
        ep = got["eprocess"]
        for member in ("UniqueProcessId", "ImageFileName", "Peb", "InheritedFromUniqueProcessId", "CreateTime",
                       "DxgProcess", "Win32Process", "Session"):
            self.assertIn(member, ep, member)
        self.assertIsNotNone(got["cid"])
        self.assertIsNotNone(got["session_id"])
        build = struct.unpack("<I", img.read(exports["NtBuildNumber"], 4))[0] & 0xFFFF  # initialised data export
        if build in (26100, 26200):
            self.assertEqual({m: ep[m] for m in ("UniqueProcessId", "ImageFileName", "Peb", "DxgProcess", "Session")},
                             {"UniqueProcessId": 0x1D0, "ImageFileName": 0x338, "Peb": 0x2E0, "DxgProcess": 0x6E0,
                              "Session": 0x2E8})
            self.assertEqual(got["cid"], 0x508)


class PagingTests(unittest.TestCase):
    """Hand-built tables: 1 GiB and 2 MiB pages, transition / prototype / page-file / demand-zero entries."""

    def setUp(self):
        mem = bytearray(0x10000)
        pml4, pdpt, pd, pt = 0x1000, 0x2000, 0x3000, 0x4000

        def q(pa, v):
            struct.pack_into("<Q", mem, pa, v)

        q(pml4, pdpt | 3)
        q(pdpt + 8 * 1, 0x40000000 | 0x83)          # VA 1 GiB: 1 GiB page at PA 1 GiB
        q(pdpt, pd | 3)
        q(pd + 8 * 1, 0x200000 | 0x83)              # VA 2 MiB: 2 MiB page at PA 2 MiB
        q(pd, pt | 3)
        q(pt + 8 * 1, 0x5000 | 3)                   # VA 0x1000 present
        q(pt + 8 * 2, 0x6000 | 0x800)               # transition
        q(pt + 8 * 3, 0x7000 | 0x400)               # prototype
        q(pt + 8 * 4, (5 << 32) | 0x80)             # page file
        self.paging = X64Paging(BytesLayer("p", bytes(mem)).read)

    def test_translate(self):
        tr = self.paging.translate
        self.assertEqual(tr(0x1000, 0x1234)[0], 0x5234)
        self.assertEqual(tr(0x1000, 0x2010)[0], 0x6010)
        self.assertEqual(tr(0x1000 | 0x5, 0x1004)[0], 0x5004)  # PCID bits in CR3 ignored
        pa, size, _e = tr(0x1000, 0x200000 + 0x12345)
        self.assertEqual((pa, size), (0x212345, 1 << 21))
        pa, size, _e = tr(0x1000, 0x40000000 + 0x123456)
        self.assertEqual((pa, size), (0x40123456, 1 << 30))
        for va, reason in ((0x3000, "prototype"), (0x4000, "paged out"), (0x5000, "not mapped")):
            with self.assertRaises(PageFault) as cm:
                tr(0x1000, va)
            self.assertIn(reason, cm.exception.reason)

    def test_mappings(self):
        got = [(va, pa, size) for va, pa, size, _e in self.paging.mappings(0x1000)]
        self.assertEqual(got, [(0x1000, 0x5000, 0x1000), (0x2000, 0x6000, 0x1000), (0x200000, 0x200000, 1 << 21),
                               (0x40000000, 0x40000000, 1 << 30)])
        self.assertEqual([va for va, _p, _s, _e in self.paging.mappings(0x1000, 0x2000, 0x300000)], [0x2000, 0x200000])


if __name__ == "__main__":
    unittest.main()
