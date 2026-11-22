"""Host kernel memory: BTF, x86-64 translation, the WSL2 dxgkrnl walk and the host plugins.

Ground truth comes from keto.testing.synth_kernel; the live tests run only as root on a Linux kernel
with /proc/kcore and BTF (for example inside WSL2 with 'wsl -u root')."""

import os
import shutil
import tempfile
import unittest

from keto.formats.container import ContainerWriter
from keto.framework.context import Context
from keto.framework.layers import BytesLayer
from keto.framework.plugin import PLUGINS, load_plugins
from keto.hostmem import btf, dxg
from keto.hostmem.linux import KernelMemory, parse_kallsyms
from keto.testing import synth_kernel

IMG, BTF, KALLSYMS, TRUTH = synth_kernel.build_image()


def col(grid, name):
    i = grid.column_index(name)
    return [v[i] for _, v in grid.rows]


def km():
    return KernelMemory(btf.Btf(BTF), parse_kallsyms(KALLSYMS), phys=BytesLayer("sysmem", IMG))


class BtfTests(unittest.TestCase):
    def test_layouts_and_bitfields(self):
        b = btf.Btf(BTF)
        self.assertEqual(b.offsetof("dxgprocess", "handle_table.entry_table"), 48)
        self.assertEqual(b.offsetof("pid_namespace", "ns.inum"), 8)
        self.assertEqual(b.member(b.struct("hmgrentry"), "destroyed")[2], 1)  # 1-bit bitfield
        self.assertEqual(b.struct("task_struct").size, 64)
        with self.assertRaises(btf.BtfError):
            b.offsetof("dxgprocess", "no_such_member")

    @unittest.skipUnless(os.path.exists("/sys/kernel/btf/vmlinux"), "no kernel BTF on this system")
    def test_running_kernel_btf(self):
        b = btf.load("/sys/kernel/btf/vmlinux")
        self.assertGreater(b.offsetof("task_struct", "comm"), 0)
        self.assertGreater(b.struct("list_head").size, 0)


class TranslationTests(unittest.TestCase):
    def test_kaslr_phys_base_from_banner(self):
        k = km()
        self.assertEqual(k.phys_base, TRUTH["phys_base"])  # decoy banners rejected by the phys_base check
        self.assertEqual(k.page_offset_base, TRUTH["page_offset_base"])
        self.assertFalse(k.l5)

    def test_page_walk_and_large_page(self):
        k = km()
        self.assertEqual(k.v2p(TRUTH["vmalloc"]["va"]), TRUTH["vmalloc"]["pa"])
        self.assertEqual(k.read(TRUTH["large_page"]["va"] + 0x1234, 17), b"LARGE-PAGE-MARKER")
        self.assertFalse(k.readable(0xFFFFC90040000000))  # not mapped


class DxgWalkTests(unittest.TestCase):
    def test_cross_view(self):
        view = dxg.dxg_cross_view(km())
        self.assertEqual(view["errors"], [])
        procs = {p["va"]: p for p in view["processes"]}
        a = procs[TRUTH["processes"]["A"]["va"]]
        exp = TRUTH["processes"]["A"]
        self.assertEqual((a["pid"], a["tgid"], a["vpid"], a["pidns"], a["task_comm"]),
                         (exp["pid"], exp["tgid"], exp["vpid"], TRUTH["pidns"], exp["comm"]))
        for k in ("devices", "contexts", "hwqueues", "resources", "pagingqueues", "syncobjects"):
            self.assertEqual(a[k], exp[k], k)
        self.assertEqual(len(a["allocations"]), exp["allocations"])
        self.assertEqual(a["handles"], exp["handles"])
        self.assertEqual([x["description"] for x in a["adapters"]], [TRUTH["adapter"]])
        self.assertEqual([(pid, fd) for pid, _c, fd in a["dxg_fds"]], [(exp["tgid"], exp["fd"])])
        x = procs[TRUTH["processes"]["X"]["va"]]
        self.assertFalse(x["task_present"])
        self.assertEqual([u["dxgprocess"] for u in view["unlinked_handles"]], [TRUTH["unlinked"]["va"]])
        self.assertEqual(view["unlinked_handles"][0]["holders"][0][0], TRUTH["unlinked"]["holder_pid"])


class HostPluginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        load_plugins()
        cls.tmp = tempfile.mkdtemp(prefix="keto-host-")
        cls.raw = os.path.join(cls.tmp, "ram.raw")
        with open(cls.raw, "wb") as fh:
            fh.write(IMG)
        cls.btf = os.path.join(cls.tmp, "vmlinux.btf")
        with open(cls.btf, "wb") as fh:
            fh.write(BTF)
        cls.kallsyms = os.path.join(cls.tmp, "kallsyms")
        with open(cls.kallsyms, "w") as fh:
            fh.write(KALLSYMS)
        # a sparse container like 'acquire --method kcore' writes: zero pages omitted, BTF and symbols inside
        cls.keto = os.path.join(cls.tmp, "ram.keto")
        syms = parse_kallsyms(KALLSYMS)
        w = ContainerWriter(cls.keto, {"kernel": {"symbols": {k: "0x%x" % v for k, v in syms.items()},
                                                 "phys_base": "0x%x" % TRUTH["phys_base"], "zero_pages_omitted": True,
                                                 "banner": TRUTH["banner"]}})
        w.add_segment("kbtf", 0, BTF)
        page = 0
        while page < len(IMG):
            if any(IMG[page:page + 4096]):
                w.add_segment("sysmem", page, IMG[page:page + 4096])
            page += 4096
        w.close()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_plugin(self, name, ctx_kw, **opts):
        with Context(output_dir=os.path.join(self.tmp, "out"), **ctx_kw) as c:
            g = PLUGINS[name](c, opts).run()
            g.rows
            return g

    def sources(self):
        return [({"host_image": self.raw}, {"btf": self.btf, "kallsyms": self.kallsyms}),
                ({"image": self.keto}, {}), ({"host_image": self.keto}, {})]

    def test_dxgprocs_every_source(self):
        for ctx_kw, opts in self.sources():
            with self.subTest(source=ctx_kw):
                g = self.run_plugin("wsl.dxgprocs", ctx_kw, **opts)
                rows = {int(r["dxgprocess"]): r for r in g.as_dicts()}
                a = rows[TRUTH["processes"]["A"]["va"]]
                self.assertEqual((a["NsPID"], a["PidNS"], a["Comm"], a["HwQueues"]),
                                 (7, TRUTH["pidns"], "cudaapp", 2))
                self.assertIn("exited or hidden", rows[TRUTH["processes"]["X"]["va"]]["Attention"])
                self.assertIn("unlinked", rows[TRUTH["unlinked"]["va"]]["Attention"])

    def test_dxgallocs_reads_guest_pages(self):
        g = self.run_plugin("wsl.dxgallocs", {"image": self.keto}, dump=True)
        rows = {r["Handle"]: r for r in g.as_dicts()}
        hit = rows["0x%08x" % TRUTH["guest_page_alloc"]["handle"]]
        self.assertIn("cubin", hit["Artefacts"])
        path = hit["Notes"].split("dumped to ", 1)[1].split(";")[0]
        with open(path, "rb") as fh:
            self.assertTrue(fh.read().startswith(TRUTH["guest_page_alloc"]["cubin"]))
        self.assertIn("no guest pages", rows["0x40000140"]["Notes"])

    def test_pslist_and_kernel(self):
        g = self.run_plugin("host.pslist", {"image": self.keto}, gpu_only=True)
        self.assertEqual(sorted(col(g, "PID")), [100, 300])
        k = self.run_plugin("host.kernel", {"host_image": self.raw}, btf=self.btf, kallsyms=self.kallsyms)
        props = dict(zip(col(k, "Property"), col(k, "Value")))
        self.assertEqual(props["phys_base"], "0x%x" % TRUTH["phys_base"])
        self.assertTrue(props["banner"].startswith("Linux version 6.18.0-synthetic"))

    def test_report_includes_kernel_findings(self):
        from keto.report import build
        with Context(image=self.keto, output_dir=os.path.join(self.tmp, "rep")) as c:
            rep = build(c, include_live=False)
        plugins = {f["plugin"] for f in rep["findings"]}
        self.assertIn("wsl.dxgprocs", plugins)
        self.assertIn("wsl.dxgallocs", plugins)
        hidden = [f for f in rep["findings"] if f["plugin"] == "wsl.dxgprocs"]
        self.assertEqual(len(hidden), 2)  # exited/hidden process X + the unlinked dxgprocess

    def test_dxg_page_owners(self):
        po = TRUTH["page_owners"]
        g = self.run_plugin("wsl.dxgpageowners", {"image": self.keto})
        rows = {r["Allocation"]: r for r in g.as_dicts()}
        r = rows["0x%08x" % TRUTH["guest_page_alloc"]["handle"]]
        self.assertEqual((r["Pages"], r["MappedByOwner"], r["AtCpuAddress"], r["Foreign"], r["KernelImage"]),
                         (2, 2, 2, 1, 0))
        self.assertIn("hider(300)", r["Attention"])
        self.assertEqual(r["Severity"], "high")

    def test_vram_host_page_owners(self):
        """GPU system-memory PTEs in the synthetic VRAM image resolved against the synthetic kernel's RAM."""
        from keto.testing.synth import build_all
        vdir = os.path.join(self.tmp, "vram")
        truth = build_all(vdir)["truth"]
        g = self.run_plugin("nvidia.malware.hostpages", {"image": os.path.join(vdir, "synthetic.keto"),
                                                          "host_image": self.keto})
        rows = {int(r["Host PA"]): r for r in g.as_dicts()}
        hpo = truth["host_page_owners"]
        self.assertIn("bash(200)", rows[hpo["victim"]["host_pa"]]["Owner"])
        self.assertEqual(rows[hpo["victim"]["host_pa"]]["Owner VA"], "0x7ffe00000000")
        kt = rows[hpo["kernel_text"]["host_pa"]]
        self.assertEqual((kt["Owner"], kt["Severity"]), ("KERNEL IMAGE (text/data)", "high"))
        self.assertEqual(rows[truth["sysmem_mapping"]["host_pa"]]["Severity"], "medium")  # no process maps it

    @unittest.skipUnless(os.path.exists("/proc/kcore") and hasattr(os, "geteuid") and os.geteuid() == 0,
                         "needs root on Linux")
    def test_live_page_owner_walk(self):
        from keto.hostmem import pageowners
        from keto.hostmem.session import _live
        k = _live()
        with open("/proc/self/maps") as fh:
            lo = int(fh.readline().split("-")[0], 16)
        with open("/proc/self/pagemap", "rb") as fh:  # root sees PFNs
            fh.seek((lo >> 12) * 8)
            ent = int.from_bytes(fh.read(8), "little")
        if not ent >> 63:
            self.skipTest("first page of the executable not resident")
        pa = (ent & ((1 << 55) - 1)) << 12
        own = pageowners.owners(k, [pa])[pa]
        with open("/proc/self/comm") as fh:
            me = fh.read().strip()
        self.assertTrue(any(o.comm == me and o.va == lo for o in own), own)

    def test_missing_symbols_is_a_clean_error(self):
        from keto.framework.exceptions import RequirementError
        with self.assertRaises(RequirementError):
            self.run_plugin("wsl.dxgprocs", {"host_image": self.raw})


@unittest.skipUnless(os.path.exists("/proc/kcore") and hasattr(os, "geteuid") and os.geteuid() == 0
                     and os.path.exists("/sys/kernel/btf/vmlinux"), "needs root on Linux with /proc/kcore and BTF")
class LiveKcoreTests(unittest.TestCase):
    def test_live_walk(self):
        from keto.hostmem.session import _live
        k = _live()
        tasks = list(dxg.walk_tasks(k))
        pids = {t["pid"] for t in tasks}
        self.assertTrue({0, 1} <= pids)  # swapper and init (global PIDs; os.getpid() may be a namespace PID)
        with open("/proc/self/comm") as fh:
            me = fh.read().strip()
        self.assertTrue(any(t["comm"] == me for t in tasks))
        if "dxgdrv" in k.symbols:
            view = dxg.dxg_cross_view(k)
            self.assertEqual(view["errors"], [])


if __name__ == "__main__":
    unittest.main()
