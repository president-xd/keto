"""Regression tests for the host-memory fixes: NI-5 (kernel image in --kcore mode), ACQ-1 (kcore acquisition),
ACQ-2 (recorded phys_base), LNX-1 (host.pslist NsPID), CLI-3 (wsl.dxgallocs --scan/--no-scan) and the hostmem
review (truncated/corrupt BTF, module-space translation, padding outside RAM, broken task links).

Ground truth comes from keto.testing.synth_kernel. Tests that read a synthetic /proc/kcore-style ELF need os.pread
(Linux); the live tests run only as root on a Linux kernel with /proc/kcore and BTF (e.g. 'wsl -u root')."""

import argparse
import io
import os
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from keto.acquire import kcore
from keto.formats.container import Container, ContainerWriter
from keto.framework.context import Context
from keto.framework.exceptions import FormatError, InvalidAddressException, RequirementError
from keto.framework.layers import BytesLayer
from keto.framework.plugin import PLUGINS, load_plugins
from keto.hostmem import btf, dxg, linux, pageowners, session
from keto.hostmem.linux import KcoreReader, KernelMemory, parse_kallsyms
from keto.testing import synth_kernel

IMG, BTF, KALLSYMS, TRUTH = synth_kernel.build_image()
SYMS = parse_kallsyms(KALLSYMS)
PAGE = 4096
GUEST_ALLOC = "0x%08x" % TRUTH["guest_page_alloc"]["handle"]
HAS_PREAD = hasattr(os, "pread")
LIVE = (os.path.exists("/proc/kcore") and hasattr(os, "geteuid") and os.geteuid() == 0
        and os.path.exists("/sys/kernel/btf/vmlinux"))


def phys_km(image=IMG, **kw):
    return KernelMemory(btf.Btf(BTF), SYMS, phys=BytesLayer("sysmem", image), **kw)


def write_container(path, image=IMG, **kernel_meta):
    """A sparse host-RAM container like 'acquire --method kcore' writes (zero pages omitted)."""
    meta = {"symbols": {k: "0x%x" % v for k, v in SYMS.items()}, "zero_pages_omitted": True,
            "banner": TRUTH["banner"]}
    meta.update(kernel_meta)
    w = ContainerWriter(path, {"kernel": meta})
    w.add_segment("kbtf", 0, BTF)
    for page in range(0, len(image), PAGE):
        if any(image[page:page + PAGE]):
            w.add_segment("sysmem", page, image[page:page + PAGE])
    w.close()


def with_kernel_page(image=IMG):
    """``image`` with the second guest page of the GPU allocation replaced by a kernel-text page."""
    k = phys_km(image)
    a = next(a for p in dxg.walk_processes(k)["processes"] for a in p["allocations"]
             if a["handle"] == TRUTH["guest_page_alloc"]["handle"])
    out = bytearray(image)
    ktext = TRUTH["page_owners"]["kernel_text_pa"]
    struct.pack_into("<Q", out, k.v2p(a["pages"]) + 8, synth_kernel.VMEMMAP + (ktext >> 12) * 64)
    return bytes(out)


def with_broken_task_link(image=IMG):
    """``image`` with bash's tasks.next pointing at unmapped vmalloc space (a smeared live acquisition)."""
    out = bytearray(image)
    struct.pack_into("<Q", out, TRUTH["tasks"][200] - synth_kernel.POB, 0xFFFFC90040000000)
    return bytes(out)


class _Tmp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        load_plugins()
        cls.tmp = tempfile.mkdtemp(prefix="keto-hostfix-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.tmp, name)

    def run_plugin(self, name, ctx_kw, **opts):
        with Context(output_dir=self.path("out"), **ctx_kw) as c:
            g = PLUGINS[name](c, opts).run()
            g.rows
            return g


# -- NI-5: --kcore mode knows phys_base, so kernel-image pages are classified -----------------------------------
@unittest.skipUnless(HAS_PREAD, "KcoreReader needs os.pread (Linux)")
class KcorePhysBaseTests(_Tmp):
    def kcore_km(self, image=IMG, name="kcore"):
        path = self.path(name)
        synth_kernel.write_kcore(path, image, TRUTH)
        return KernelMemory(btf.Btf(BTF), SYMS, kcore=KcoreReader(path))

    def test_phys_base_from_kernel_text_segment(self):
        k = self.kcore_km()
        self.assertEqual(k.phys_base, TRUTH["phys_base"])
        self.assertEqual(pageowners.kernel_image_range(k), TRUTH["kernel_image"])
        self.assertEqual(pageowners.classify(k, TRUTH["page_owners"]["kernel_text_pa"], []), "KERNEL IMAGE (text/data)")
        self.assertTrue(any("kernel-text segment" in n for n in k.notes), k.notes)
        k.kcore.close()

    def test_dxgpageowners_kernel_image_in_kcore_mode(self):
        k = self.kcore_km(with_kernel_page(), "kcore-kpage")
        with mock.patch.object(session, "_live", return_value=k):
            g = self.run_plugin("wsl.dxgpageowners", {}, kcore=True)
        r = {x["Allocation"]: x for x in g.as_dicts()}[GUEST_ALLOC]
        self.assertEqual((r["Pages"], r["MappedByOwner"], r["Foreign"], r["NotMapped"], r["KernelImage"]),
                         (2, 1, 0, 0, 1))
        self.assertEqual(r["Severity"], "high")
        self.assertIn("KERNEL IMAGE", r["Attention"])
        k.kcore.close()

    def test_hostpages_kernel_image_in_kcore_mode(self):
        from keto.testing.synth import build_all
        vdir = self.path("vram")
        truth = build_all(vdir)["truth"]["host_page_owners"]
        k = self.kcore_km()
        with mock.patch.object(session, "_live", return_value=k):
            g = self.run_plugin("nvidia.malware.hostpages", {"image": os.path.join(vdir, "synthetic.keto")}, kcore=True)
        rows = {int(r["Host PA"]): r for r in g.as_dicts()}
        kt = rows[truth["kernel_text"]["host_pa"]]
        self.assertEqual((kt["Owner"], kt["Severity"]), ("KERNEL IMAGE (text/data)", "high"))
        self.assertIn("bash(200)", rows[truth["victim"]["host_pa"]]["Owner"])
        k.kcore.close()

    def test_module_space_through_kcore(self):
        k = self.kcore_km()
        self.assertEqual(k.read(TRUTH["module_page"]["va"], 18), b"MODULE-PAGE-MARKER")
        k.kcore.close()


# -- ACQ-2: the recorded phys_base is used when the image confirms it -------------------------------------------
class RecordedPhysBaseTests(_Tmp):
    def test_confirmed_hint_skips_the_scan(self):
        with mock.patch.object(linux, "scan", side_effect=AssertionError("whole-image banner scan")):
            k = phys_km(phys_base_hint=TRUTH["phys_base"])
        self.assertEqual(k.phys_base, TRUTH["phys_base"])
        self.assertTrue(any("recorded at acquisition, confirmed" in n for n in k.notes), k.notes)

    def test_wrong_hint_falls_back_to_the_scan(self):
        k = phys_km(phys_base_hint=TRUTH["phys_base"] + 0x200000)
        self.assertEqual(k.phys_base, TRUTH["phys_base"])
        self.assertTrue(any(n.startswith("WARNING") for n in k.notes), k.notes)

    def test_container_plugins_do_not_scan(self):
        path = self.path("recorded.keto")
        write_container(path, phys_base="0x%x" % TRUTH["phys_base"])
        with mock.patch.object(linux, "scan", side_effect=AssertionError("whole-image banner scan")):
            g = self.run_plugin("wsl.dxgprocs", {"image": path})
            k = self.run_plugin("host.kernel", {"image": path})
        self.assertIn(TRUTH["processes"]["A"]["va"], [int(r["dxgprocess"]) for r in g.as_dicts()])
        props = dict((r["Property"], r["Value"]) for r in k.as_dicts())
        self.assertEqual(props["phys_base"], "0x%x" % TRUTH["phys_base"])
        self.assertNotIn("WARNING", " ".join(r["Value"] for r in k.as_dicts() if r["Property"] == "note"))


# -- ACQ-1: bounded segments, page-cache drop, limits -----------------------------------------------------------
class _FakeKcore:
    def __init__(self, data):
        self.data = data

    def read(self, va, n):
        return self.data[va:va + n]


def _pages(*marks):
    """One page per mark: 0 = zero page, anything else = a page filled with that byte."""
    return b"".join(bytes([m]) * PAGE for m in marks)


class RunsTests(unittest.TestCase):
    def test_long_run_is_split_into_bounded_segments(self):
        data = _pages(*([7] * 40))
        runs = list(kcore._runs(_FakeKcore(data), 0, len(data), 16 * PAGE))
        self.assertEqual([(o // PAGE, len(d) // PAGE) for o, d in runs], [(0, 16), (16, 16), (32, 8)])
        self.assertEqual(b"".join(d for _o, d in runs), data)

    def test_short_gaps_kept_long_gaps_split(self):
        data = _pages(1, 0, 0, 0, 2, *([0] * (kcore.GAP_PAGES + 1)), 3, 0, 0)
        runs = list(kcore._runs(_FakeKcore(data), 0, len(data)))
        start3 = 5 + kcore.GAP_PAGES + 1
        self.assertEqual(runs, [(0, data[:5 * PAGE]), (start3 * PAGE, data[start3 * PAGE:(start3 + 1) * PAGE])])

    def test_own_output_pages(self):
        a, b, c = (bytes([i]) * 2000 + bytes(range(256)) * 8 + bytes([i]) * 48 for i in (1, 2, 3))
        own = kcore._OwnPages()
        own.feed(bytes(64))  # header: the RAM data sits 64 bytes into each file page
        own.feed(a + b + c + b"\xee" * (2 * PAGE), ram=True)
        self.assertTrue(own.omit(a[PAGE - 64:] + b[:PAGE - 64]))  # a page of the output file, imaged back
        for page in (a, b, c, b"\xee" * PAGE):  # RAM pages themselves and uniform fills are not "own" pages
            self.assertFalse(own.omit(page))
        self.assertEqual(own.omitted, 1)
        aligned = kcore._OwnPages()
        aligned.feed(bytes(PAGE))
        aligned.feed(a + b, ram=True)  # page-aligned data: file pages are RAM pages, duplicates stay genuine
        self.assertEqual(aligned.hashes, set())
        data = _pages(1, 0, 2, 3)
        omitting = kcore._OwnPages()
        omitting.hashes.add(hash(data[2 * PAGE:3 * PAGE]))
        runs = list(kcore._runs(_FakeKcore(data), 0, len(data), own=omitting))
        self.assertEqual(runs, [(0, data[:2 * PAGE] + bytes(PAGE) + data[3 * PAGE:])])

    def test_parse_ranges(self):
        self.assertEqual(kcore.parse_ranges(["2G-6G", "0-4G", "0x1800-0x1900"]), [(0, 6 << 30)])
        self.assertEqual(kcore.parse_ranges(["0x1800-0x1900", "0x1900-0x2800"]), [(0x1000, 0x3000)])
        for bad in ("abc", "0x2000-0x1000", "5"):
            with self.assertRaises(RequirementError):
                kcore.parse_ranges([bad])


@unittest.skipUnless(HAS_PREAD and hasattr(os, "posix_fadvise"), "synthetic kcore acquisition needs Linux")
class KcoreAcquisitionTests(_Tmp):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        files = {"KCORE": "kcore", "KALLSYMS": "kallsyms", "BTF": "vmlinux.btf", "VERSION": "version"}
        cls.files = {k: os.path.join(cls.tmp, v) for k, v in files.items()}
        synth_kernel.write_kcore(cls.files["KCORE"], IMG, TRUTH)
        for key, data in (("KALLSYMS", KALLSYMS.encode()), ("BTF", BTF), ("VERSION", TRUTH["banner"].encode())):
            with open(cls.files[key], "wb") as fh:
                fh.write(data)

    def acquire(self, name, **opts):
        args = argparse.Namespace(out=self.path(name), phys_range=None, max_bytes=None, force=False)
        for k, v in opts.items():
            setattr(args, k, v)
        with mock.patch.multiple(kcore, **self.files):
            kcore.acquire_kcore(args, io.StringIO(), {"acquisition": {"method": "kcore"}})
        return Container(args.out)

    @staticmethod
    def sysmem(c):
        return sorted((s for s in c.segments if s.space_name == "sysmem"), key=lambda s: s.address)

    def test_full_acquisition(self):
        calls = []
        real = os.posix_fadvise
        with mock.patch.object(kcore, "SEGMENT_MAX", 2 * PAGE), mock.patch.object(kcore, "DROP_EVERY", 4 * PAGE), \
                mock.patch.object(os, "posix_fadvise", side_effect=lambda *a: calls.append(a) or real(*a)):
            c = self.acquire("full.keto")
        meta = c.metadata["kernel"]
        self.assertEqual(meta["phys_base"], "0x%x" % TRUTH["phys_base"])
        self.assertNotIn("acquired_ranges", meta)
        self.assertEqual(c.metadata["acquisition"]["status"], "complete")
        segs = self.sysmem(c)
        self.assertLessEqual(max(s.length for s in segs), 2 * PAGE + kcore.GAP_PAGES * PAGE)
        # runs longer than SEGMENT_MAX continue in an adjacent segment (unsplit runs are separated by zero pages)
        self.assertTrue(any(a.address + a.length == b.address for a, b in zip(segs, segs[1:])))
        layer = c.layers()["sysmem"]
        for s in segs:  # stored bytes are the RAM bytes
            self.assertEqual(layer.read(s.address, s.length), IMG[s.address:s.address + s.length])
        stored = {s.address // PAGE + i for s in segs for i in range(s.length // PAGE)}
        nonzero = {p // PAGE for p in range(0x1000, len(IMG), PAGE) if any(IMG[p:p + PAGE])}
        self.assertEqual(nonzero - stored, set())
        # the written file was dropped from the page cache in contiguous pieces up to the end of the data
        self.assertGreater(len(calls), 2)
        pos = 0
        for _fd, off, length, advice in calls:
            self.assertEqual((off, advice), (pos, os.POSIX_FADV_DONTNEED))
            pos = off + length
        self.assertGreaterEqual(pos, max(s.file_offset + s.length for s in c.segments))
        c.close()

    def test_own_output_imaged_back_is_not_stored(self):
        first = self.acquire("own1.keto")
        seg = self.sysmem(first)[0]
        f = -(-seg.file_offset // PAGE) * PAGE  # first whole file page holding RAM data
        with open(first.path, "rb") as fh:
            fh.seek(f)
            file_page = fh.read(PAGE)
        first.close()
        self.assertNotEqual(seg.file_offset % PAGE, 0)
        planted = 0x1FF0000  # read long after that file page was written
        image = bytearray(IMG)
        image[planted:planted + PAGE] = file_page
        files = dict(self.files, KCORE=self.path("kcore-planted"))
        synth_kernel.write_kcore(files["KCORE"], bytes(image), TRUTH)
        args = argparse.Namespace(out=self.path("own2.keto"), phys_range=None, max_bytes=None, force=False)
        with mock.patch.multiple(kcore, **files):
            kcore.acquire_kcore(args, io.StringIO(), {"acquisition": {"method": "kcore"}})
        c = Container(args.out)
        self.assertEqual(c.metadata["kernel"]["own_pages_omitted"], 1)
        self.assertIn("identical to pages of this output file", c.metadata["acquisition"]["notes"])
        self.assertFalse(any(s.address <= planted < s.address + s.length for s in self.sysmem(c)))
        c.close()

    def test_acquired_container_analyses_without_scanning(self):
        path = self.acquire("analyse.keto").path
        with mock.patch.object(linux, "scan", side_effect=AssertionError("whole-image banner scan")):
            g = self.run_plugin("wsl.dxgprocs", {"image": path})
            ps = self.run_plugin("host.pslist", {"image": path})
        a = {int(r["dxgprocess"]): r for r in g.as_dicts()}[TRUTH["processes"]["A"]["va"]]
        self.assertEqual((a["NsPID"], a["Comm"], a["HwQueues"]), (7, "cudaapp", 2))
        self.assertEqual({r["PID"]: r["NsPID"] for r in ps.as_dicts() if r["PID"] in TRUTH["nspids"]},
                         TRUTH["nspids"])

    def test_phys_range_limit_is_recorded_and_enforced(self):
        c = self.acquire("range.keto", phys_range=["0x100000-0x1000000"])
        meta = c.metadata["kernel"]
        self.assertEqual(meta["acquired_ranges"], [{"start": "0x100000", "size": 0xF00000}])
        self.assertIn("acquired only 0x100000-0x1000000", c.metadata["acquisition"]["notes"])
        self.assertTrue(all(0x100000 <= s.address and s.address + s.length <= 0x1000000 for s in self.sysmem(c)))
        k = KernelMemory(btf.Btf(BTF), SYMS, phys=c.layers()["sysmem"], phys_base=TRUTH["phys_base"],
                         page_offset_base=synth_kernel.POB, l5=False, pad_gaps=session._pad_gaps(meta))
        self.assertEqual(k.read_phys(0x200000, 8), bytes(8))  # omitted zero page inside the acquired range
        with self.assertRaises(InvalidAddressException):
            k.read_phys(TRUTH["vmalloc"]["pa"], 8)  # RAM that was not acquired is not zeros
        c.close()
        with self.assertRaises(RequirementError):  # kernel image left out: located nowhere, no garbage
            self.run_plugin("host.kernel", {"image": self.path("range.keto")})

    def test_max_bytes_stops_and_records_coverage(self):
        c = self.acquire("max.keto", max_bytes=3 * PAGE + 100)
        segs = self.sysmem(c)
        self.assertEqual(sum(s.length for s in segs), 3 * PAGE)
        acquired = c.metadata["kernel"]["acquired_ranges"]
        end = int(acquired[-1]["start"], 16) + acquired[-1]["size"]
        last = segs[-1].address + segs[-1].length
        self.assertLess(end, len(IMG))  # stopped early...
        self.assertGreaterEqual(end, last)
        self.assertFalse(any(IMG[last:end]))  # ...and claims only RAM whose omitted pages really are zero
        self.assertIn("--max-bytes %d reached" % (3 * PAGE + 100), c.metadata["acquisition"]["notes"])
        c.close()

    def test_interrupted_acquisition_records_what_it_covered(self):
        real = kcore._runs

        def interrupted(*a):
            for item in real(*a):
                yield item
                raise KeyboardInterrupt

        with mock.patch.object(kcore, "_runs", interrupted), self.assertRaises(KeyboardInterrupt):
            self.acquire("cut.keto")
        c = Container(self.path("cut.keto"))
        segs = self.sysmem(c)
        acquired = c.metadata["kernel"]["acquired_ranges"]
        self.assertEqual(int(acquired[-1]["start"], 16) + acquired[-1]["size"], segs[-1].address + segs[-1].length)
        self.assertIn("interrupted: KeyboardInterrupt", c.metadata["acquisition"]["notes"])
        c.close()

    def test_existing_output_is_not_overwritten(self):
        self.acquire("once.keto").close()
        with self.assertRaises(FormatError):
            self.acquire("once.keto")
        self.acquire("once.keto", force=True).close()


# -- LNX-1: host.pslist shows the PID inside the task's own PID namespace ---------------------------------------
class PsListNsPidTests(_Tmp):
    def test_nspid_column(self):
        path = self.path("ps.keto")
        write_container(path)
        g = self.run_plugin("host.pslist", {"image": path})
        rows = {r["PID"]: r for r in g.as_dicts()}
        self.assertEqual({p: rows[p]["NsPID"] for p in TRUTH["nspids"]}, TRUTH["nspids"])
        self.assertEqual(str(rows[0]["NsPID"]), "N/A (?)")  # init_task here has no thread_pid

    def test_task_nspid_without_btf_support(self):
        b = btf.BtfBuilder()
        b.struct("task_struct", 64, [("pid", b.int("int", 4, signed=True), 16)])
        k = KernelMemory(btf.Btf(b.build()), SYMS, phys=BytesLayer("sysmem", IMG))
        self.assertIsNone(dxg.task_nspid(k, TRUTH["tasks"][100]))


# -- CLI-3: wsl.dxgallocs scans by default and --no-scan turns it off -------------------------------------------
class DxgAllocsScanOptionTests(_Tmp):
    def opts(self, *flags):
        from keto.cli import build_parser
        args = build_parser().parse_args(["--host-image", "x.keto", "wsl.dxgallocs"] + list(flags))
        cls = PLUGINS["wsl.dxgallocs"]
        return cls(Context(), {r.name: getattr(args, r.name, None) for r in cls.REQUIREMENTS}).opts

    def test_scan_default_and_no_scan(self):
        self.assertTrue(self.opts()["scan"])
        self.assertTrue(self.opts("--scan")["scan"])
        self.assertFalse(self.opts("--no-scan")["scan"])

    def test_no_scan_skips_the_artefact_sweep(self):
        path = self.path("allocs.keto")
        write_container(path)
        rows = {r["Handle"]: r for r in self.run_plugin("wsl.dxgallocs", {"image": path}, scan=False).as_dicts()}
        self.assertEqual(str(rows[GUEST_ALLOC]["Artefacts"]), "-")
        rows = {r["Handle"]: r for r in self.run_plugin("wsl.dxgallocs", {"image": path}).as_dicts()}
        self.assertIn("cubin", rows[GUEST_ALLOC]["Artefacts"])


# -- hostmem review ---------------------------------------------------------------------------------------------
class BtfRobustnessTests(unittest.TestCase):
    def test_truncated_blob_is_an_error(self):
        for cut in (30, len(BTF) // 2, len(BTF) - 5):
            with self.assertRaisesRegex(btf.BtfError, "truncated"):
                btf.Btf(BTF[:cut])

    def test_truncated_type_record_is_an_error(self):
        b = btf.BtfBuilder()
        b.struct("s", 8, [("a", b.int("int", 4), 0), ("b", 1, 4)])
        blob = bytearray(b.build())
        type_len = struct.unpack_from("<I", blob, 12)[0]
        struct.pack_into("<I", blob, 12, type_len - 8)  # header now cuts the struct's member list short
        with self.assertRaisesRegex(btf.BtfError, "truncated inside type"):
            btf.Btf(bytes(blob))

    def test_typedef_cycle_and_bad_type_id(self):
        b = btf.BtfBuilder()
        b._add("loop", btf.TYPEDEF, 0, 1)  # typedef 1 -> 1
        b.struct("s", 8, [("x", 1, 0), ("y", 99, 4)])
        t = btf.Btf(b.build())
        with self.assertRaisesRegex(btf.BtfError, "does not end"):
            t.resolve(1)
        with self.assertRaisesRegex(btf.BtfError, "out of range"):
            t.sizeof(99)


class TranslationReviewTests(_Tmp):
    def test_module_space_goes_through_the_page_tables(self):
        k = phys_km()
        self.assertEqual(k.v2p(TRUTH["module_page"]["va"]), TRUTH["module_page"]["pa"])
        self.assertEqual(k.read(TRUTH["module_page"]["va"], 18), b"MODULE-PAGE-MARKER")

    def test_padding_only_inside_ram(self):
        path = self.path("ram-ranges.keto")
        ram = [{"start": "0x1000", "size": len(IMG) - 0x1000}]
        write_container(path, ram_ranges=ram)
        with Context(image=path) as c:
            meta = c.metadata["kernel"]
            k = KernelMemory(btf.Btf(BTF), SYMS, phys=c.layers["sysmem"], pad_gaps=session._pad_gaps(meta))
            self.assertEqual(k.read_phys(len(IMG) - PAGE, 8), bytes(8))  # omitted zero page inside RAM
            for pa in (0, len(IMG), 0x7FFF00000000):  # not RAM: an error, not zeros
                with self.assertRaises(InvalidAddressException):
                    k.read_phys(pa, 8)
        self.assertIs(session._pad_gaps({"zero_pages_omitted": True}), True)  # older containers: as before
        self.assertIs(session._pad_gaps({}), False)


class BrokenTaskListTests(_Tmp):
    def test_cross_view_and_pslist_survive_a_broken_link(self):
        image = with_broken_task_link()
        view = dxg.dxg_cross_view(phys_km(image))
        self.assertTrue(any(e.startswith("init_task.tasks: walk stopped") for e in view["errors"]), view["errors"])
        self.assertIn(TRUTH["processes"]["A"]["va"], [p["va"] for p in view["processes"]])
        path = self.path("broken.keto")
        write_container(path, image)
        rows = self.run_plugin("host.pslist", {"image": path}).as_dicts()
        self.assertEqual([r["PID"] for r in rows if str(r["Comm"]) != "N/A (walk error)"], [0, 100, 200])
        self.assertIn("walk stopped", rows[-1]["GPU handles"])
        rows = self.run_plugin("wsl.dxgpageowners", {"image": path}).as_dicts()
        self.assertEqual(rows[0]["MappedByOwner"], 2)  # cudaapp was reached; hider (after the break) was not
        self.assertEqual(str(rows[-1]["Comm"]), "N/A (walk error)")
        self.assertIn("not counted", rows[-1]["Attention"])
        with self.assertRaises(InvalidAddressException):  # without an error list the caller sees the failure
            pageowners.owners(phys_km(image), [TRUTH["page_owners"]["victim_pa"]])


# -- live (root, Linux with /proc/kcore and BTF) ----------------------------------------------------------------
@unittest.skipUnless(LIVE, "needs root on Linux with /proc/kcore and BTF")
class LiveHostFixTests(_Tmp):
    def test_live_phys_base_and_kernel_image(self):
        k = session._live()
        self.assertIsNotNone(k.phys_base)
        self.assertEqual(k.u64(k.sym("phys_base")), k.phys_base)  # the kernel's own variable agrees
        lo, _hi = pageowners.kernel_image_range(k)
        self.assertEqual(k.read_phys(lo, 64), k.read(k.sym("_text"), 64))

    def test_live_pslist_nspid(self):
        with open("/proc/self/status") as fh:  # NSpid as seen from this /proc's namespace down to our own
            nspid = [int(x) for x in next(ln for ln in fh if ln.startswith("NSpid:")).split()[1:]]
        with open("/proc/self/comm") as fh:
            comm = fh.read().strip()
        rows = self.run_plugin("host.pslist", {}, kcore=True).as_dicts()
        self.assertTrue([r for r in rows if r["NsPID"] == nspid[-1] and r["Comm"] == comm], nspid)


if __name__ == "__main__":
    unittest.main()
