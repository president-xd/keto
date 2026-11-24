"""Regression tests for the audit findings fixed in the framework, container, acquisition, decompressors,
indicators, CLI and report (the 2026-11-23 audit's finding IDs are given in the test docstrings)."""

import contextlib
import io
import json
import logging
import os
import random
import shutil
import struct
import tempfile
import unittest
import zlib

from keto.cli import main
from keto.formats import compression, fatbin as fb, gpucode, lz4
from keto.formats.container import Container, ContainerWriter, open_lime, write_lime
from keto.framework import parallel
from keto.framework import scanners as sc
from keto.framework.context import Context
from keto.framework.exceptions import FormatError, KetoError, RequirementError
from keto.framework.layers import DataLayer, FileLayer
from keto.framework.plugin import PLUGINS, load_plugins
from keto.framework.renderers import render_to_string
from keto.testing.synth import build_all

TMP = None


def setUpModule():
    global TMP
    load_plugins()
    TMP = tempfile.mkdtemp(prefix="keto-fixes-")
    build_all(os.path.join(TMP, "synth"))


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def synth(name="synthetic.keto"):
    return os.path.join(TMP, "synth", name)


def cli(*argv):
    """Run the CLI; return (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(list(argv))
    return rc, out.getvalue(), err.getvalue()


def rb(path):
    with open(path, "rb") as fh:
        return fh.read()


def wb(path, data):
    with open(path, "wb") as fh:
        fh.write(data)


def small_container(path, data=b"abc" * 100, meta=None):
    w = ContainerWriter(path, dict(meta or {"device": {"name": "t", "chipset": "0x197"}}))
    w.add_segment("vram", 0, data)
    w.close()
    return w


class ContainerIntegrityTests(unittest.TestCase):
    """EVD-2: metadata and segment table are protected; verify reports every check; snapshot containers verify."""

    def setUp(self):
        self.d = tempfile.mkdtemp(dir=TMP)

    def patched(self, src, find, repl):
        data = rb(src)
        assert find in data, find
        out = src + ".tampered"
        with open(out, "wb") as fh:
            fh.write(data.replace(find, repl, 1))
        return out

    def test_good_container_verifies_and_fingerprint_is_stable(self):
        p = os.path.join(self.d, "c.keto")
        w = small_container(p)
        with Container(p) as c:
            self.assertTrue(c.digest_ok)
            self.assertEqual(c.problems, [])
            self.assertEqual(c.fingerprint, w.fingerprint)
            rows = c.verify()
            self.assertTrue(all(r["ok"] for r in rows), rows)
            self.assertEqual({r["space"] for r in rows if r["segment"] < 0}, {"metadata", "data"})

    def test_metadata_tamper_is_detected(self):
        p = os.path.join(self.d, "c.keto")
        small_container(p)
        bad = self.patched(p, b'"0x197"', b'"0x164"')  # same length: switches the profile to Turing
        with Container(bad) as c:
            self.assertFalse(c.digest_ok)
            self.assertTrue(c.problems)
            meta_row = [r for r in c.verify() if r["space"] == "metadata"][0]
            self.assertIs(meta_row["ok"], False)
        with self.assertLogs("keto.context", level="WARNING") as logs:
            Context(image=bad).close()
        self.assertIn("modified after acquisition", "\n".join(logs.output))

    def test_segment_table_tamper_is_detected(self):
        p = os.path.join(self.d, "c.keto")
        small_container(p)
        c = Container(p)
        c.close()
        data = bytearray(rb(p))
        seg_off = struct.unpack_from("<Q", data, 16)[0]
        struct.pack_into("<Q", data, seg_off + 8, 0x10)  # segment 0 address 0 -> 0x10
        bad = os.path.join(self.d, "seg.keto")
        wb(bad, bytes(data))
        with Container(bad) as c:
            rows = c.verify()
        self.assertFalse(rows[0]["ok"])
        self.assertIn("segment table differs", rows[0]["detail"])
        self.assertIs([r for r in rows if r["space"] == "metadata"][0]["ok"], False)

    def test_data_tamper_and_data_sha256(self):
        p = os.path.join(self.d, "c.keto")
        small_container(p)
        bad = self.patched(p, b"abcabc", b"abXabc")
        with Container(bad) as c:
            rows = c.verify()
        self.assertFalse(rows[0]["ok"])
        self.assertIs([r for r in rows if r["space"] == "data"][0]["ok"], False)

    def test_truncated_container_raises_clean_format_error(self):
        p = os.path.join(self.d, "c.keto")
        small_container(p)
        data = rb(p)
        for cut in (30, 200, len(data) - 10):
            t = os.path.join(self.d, "t%d.keto" % cut)
            wb(t, data[:cut])
            with self.assertRaises(FormatError):
                Container(t)
            rc, _out, err = cli("-f", t, "verify")
            self.assertEqual(rc, 2, err)
            self.assertNotIn("Traceback", err)

    def test_verify_plugin_on_snapshot_container_and_expected_fingerprint(self):
        p = os.path.join(self.d, "snap.keto")
        w = ContainerWriter(p, {"live_snapshot": {"format": "keto-snapshot/1", "records": {}}})
        w.close()
        rc, out, err = cli("-f", p, "-r", "json", "verify")
        self.assertEqual(rc, 0, err)
        rows = json.loads(out)
        self.assertTrue(all(r["OK"] for r in rows), rows)
        rc, out, _ = cli("-f", p, "-r", "json", "verify", "--expected-fingerprint", w.fingerprint)
        self.assertTrue(json.loads(out)[-1]["OK"])
        rc, out, _ = cli("-f", p, "-r", "json", "verify", "--expected-fingerprint", "0" * 64)
        self.assertFalse(json.loads(out)[-1]["OK"])

    def test_version1_container_is_reported_unprotected(self):
        p = os.path.join(self.d, "c.keto")
        small_container(p)
        data = bytearray(rb(p))
        struct.pack_into("<I", data, 8, 1)  # version 1 (written before the header digest existed)
        old = os.path.join(self.d, "v1.keto")
        wb(old, bytes(data))
        with Container(old) as c:
            self.assertIsNone(c.digest_ok)
            meta_row = [r for r in c.verify() if r["space"] == "metadata"][0]
        self.assertIsNone(meta_row["ok"])
        self.assertIn("not integrity-protected", meta_row["detail"])

    def test_writer_exclusive_and_streaming_append(self):
        p = os.path.join(self.d, "a.keto")
        small_container(p)
        with self.assertRaises(FormatError):
            ContainerWriter(p, {}, exclusive=True)
        w = ContainerWriter(os.path.join(self.d, "b.keto"), {})
        w.append("process", 0x1000, b"A" * 10)
        w.append("process", 0x100A, b"B" * 6)   # contiguous: same segment
        w.append("process", 0x3000, b"C" * 4)   # gap: new segment
        w.close()
        with Container(w.path) as c:
            self.assertEqual([(s.address, s.length) for s in c.segments], [(0x1000, 16), (0x3000, 4)])
            self.assertEqual(c.layers()["process"].read(0x1008, 4), b"AABB")
            self.assertTrue(all(r["ok"] for r in c.verify()))

    def test_truncated_lime_is_rejected_and_releases_the_file(self):
        p = os.path.join(self.d, "h.lime")
        write_lime(p, [(0x1000, b"x" * 4096), (0x10000, b"y" * 4096)])
        data = rb(p)
        for cut in (len(data) - 100, len(data) - 4096 - 10):
            t = os.path.join(self.d, "t.lime")
            wb(t, data[:cut])
            with self.assertRaises(FormatError):
                open_lime("h", t)
            os.remove(t)  # the file handle was released (Windows would refuse otherwise)


class AcquireSafetyTests(unittest.TestCase):
    """EVD-1 / EVD-4 / ACQ-4: acquisition never destroys evidence and does not stamp the analyst's GPU."""

    def setUp(self):
        self.d = tempfile.mkdtemp(dir=TMP)
        self.src = os.path.join(self.d, "dump.bin")
        with open(self.src, "wb") as fh:
            fh.write(os.urandom(1 << 16))

    def test_in_place_import_is_refused_and_source_kept(self):
        before = rb(self.src)
        rc, _out, err = cli("acquire", "--method", "import", "--input", self.src, "--out", self.src, "--force")
        self.assertEqual(rc, 2)
        self.assertIn("input file itself", err)
        self.assertEqual(rb(self.src), before)

    def test_existing_output_is_not_overwritten(self):
        out = os.path.join(self.d, "e.keto")
        small_container(out)
        before = rb(out)
        rc, _o, err = cli("acquire", "--method", "import", "--input", self.src, "--out", out)
        self.assertEqual(rc, 2)
        self.assertIn("refusing to overwrite", err)
        rc, _o, err = cli("acquire", "--method", "import", "--input", os.path.join(self.d, "missing"), "--out", out)
        self.assertEqual(rc, 2)
        self.assertEqual(rb(out), before)

    def test_missing_input_leaves_no_file(self):
        out = os.path.join(self.d, "new.keto")
        rc, _o, _e = cli("acquire", "--method", "import", "--input", os.path.join(self.d, "nope"), "--out", out)
        self.assertEqual(rc, 2)
        self.assertFalse(os.path.exists(out))

    def test_import_records_no_live_device_and_prints_fingerprint(self):
        out = os.path.join(self.d, "i.keto")
        rc, stdout, err = cli("acquire", "--method", "import", "--input", self.src, "--out", out)
        self.assertEqual(rc, 0, err)
        with Container(out) as c:
            self.assertNotIn("device", c.metadata)
            self.assertEqual(c.metadata["acquisition"]["status"], "complete")
            self.assertEqual(c.layers()["vram"].read(0, 1 << 16), rb(self.src))
            self.assertIn(c.fingerprint, stdout)
        rc, _o, _e = cli("acquire", "--method", "import", "--input", self.src, "--out", out, "--force")
        self.assertEqual(rc, 0)


class TimelinerTests(unittest.TestCase):
    def test_offline_timeline_has_no_analyst_cache_events(self):
        """EVD-3: jitcache/shadercache read this machine by default and must not enter an image's timeline."""
        with Context(image=synth()) as c:
            rows = PLUGINS["timeliner"](c, {}).run().as_dicts()
        plugins_with_events = {r["Plugin"] for r in rows if r["Type"] != "-"}
        self.assertFalse(plugins_with_events & {"nvidia.jitcache", "nvidia.shadercache"}, plugins_with_events)
        skipped = {r["Plugin"]: r["Description"] for r in rows if r["Type"] == "-"}
        self.assertIn("analyst machine", skipped.get("nvidia.jitcache", ""))


class ContextErrorTests(unittest.TestCase):
    """CLI-2 / IMG-9 / IMG-12: bad inputs give clean errors (exit 2, no traceback)."""

    def assertCleanError(self, *argv):
        rc, _out, err = cli(*argv)
        self.assertEqual(rc, 2, err)
        self.assertNotIn("Traceback", err)
        return err

    def test_bad_inputs(self):
        empty = os.path.join(TMP, "empty.bin")
        open(empty, "wb").close()
        self.assertIn("empty", self.assertCleanError("-f", empty, "nvidia.info"))
        self.assertCleanError("-f", TMP, "nvidia.info")
        self.assertCleanError("-f", synth(), "--host-image", os.path.join(TMP, "nope.lime"), "nvidia.sysmemmap")
        self.assertIn("same file", self.assertCleanError("-f", synth(), "--host-image", synth(), "nvidia.cubinscan"))
        self.assertCleanError("--snapshot", os.path.join(TMP, "nope.json"), "nvidia.pslist")
        self.assertIn("unknown profile", self.assertCleanError("-f", synth(), "-p", "nosuch", "nvidia.chanscan"))
        self.assertCleanError("-f", synth(), "--reference", os.path.join(TMP, "nope.cubin"), "nvidia.kernels")
        self.assertCleanError("-f", synth(), "regexscan", "--pattern", "(")
        self.assertCleanError("-f", synth(), "regexscan", "--pattern", "x", "--layer", "nope")
        self.assertCleanError("-f", synth(), "hexdump", "--address", "0", "--length", "2G")
        rc, _o, err = cli("-f", synth(), "--output-file", os.path.join(TMP, "no", "dir", "x.txt"), "nvidia.chanscan")
        self.assertEqual(rc, 2)
        self.assertNotIn("Traceback", err)

    def test_vram_size_smaller_than_image_warns(self):
        with self.assertLogs("keto.context", level="WARNING"):
            Context(image=synth(), vram_size=1 << 20).close()


class CliTests(unittest.TestCase):
    def test_shell_command_runs(self):
        """CLI-1"""
        rc, out, err = cli("-f", synth(), "shell", "--command", "print(ctx.profile.name)")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.strip(), "ada")

    def test_bool_options_keep_plugin_defaults(self):
        """CLI-3: an omitted store_true flag no longer overrides a default of True; --no-<flag> exists."""
        from keto.cli import build_parser
        p = build_parser()
        self.assertIsNone(p.parse_args(["--host-image", "x", "wsl.dxgallocs"]).scan)
        self.assertFalse(p.parse_args(["--host-image", "x", "wsl.dxgallocs", "--no-scan"]).scan)
        self.assertTrue(p.parse_args(["--host-image", "x", "wsl.dxgallocs", "--scan"]).scan)

    def test_short_names_and_options_after_the_plugin(self):
        """CLI-5"""
        rc, out, err = cli("-f", synth(), "-q", "chanscan", "-r", "json")
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(json.loads(out)), 4)
        rc, out, _ = cli("list", "-r", "csv")
        self.assertTrue(out.startswith("TreeDepth,Plugin"))

    def test_parse_size_hex_is_not_a_unit(self):
        from keto.framework.util import parse_size
        self.assertEqual([parse_size(s) for s in ("0x1B", "0xAB", "0x1000", "4K", "2G", "512M", "100")],
                         [0x1B, 0xAB, 0x1000, 4096, 2 << 30, 512 << 20, 100])

    def test_kcore_limit_options_parse(self):
        from keto.cli import build_parser
        a = build_parser().parse_args(["acquire", "--method", "kcore", "--out", "x.keto", "--phys-range",
                                       "0x100000-4G", "--max-bytes", "2G"])
        self.assertEqual((a.phys_range, a.max_bytes), (["0x100000-4G"], 2 << 30))

    def test_internal_errors_are_reported_without_traceback(self):
        from keto.framework.plugin import Plugin

        class Boom(Plugin):
            NAME = "test.boom"
            SOURCES = ("file",)

            def run(self):
                raise ValueError("kaboom")
        try:
            rc, _o, err = cli("test.boom")
            self.assertEqual(rc, 3)
            self.assertIn("internal error in test.boom: ValueError: kaboom", err)
            self.assertNotIn("Traceback", err)
        finally:
            PLUGINS.pop("test.boom", None)


class HostileInputTests(unittest.TestCase):
    """DOS-1..DOS-4"""

    def test_truncated_dxbc_part_table(self):
        hdr = b"DXBC" + b"\0" * 16 + struct.pack("<III", 1, 1000, 10)
        self.assertIsNone(gpucode.parse_dxbc(hdr))
        img = os.path.join(TMP, "dxbc_tail.raw")
        with open(img, "wb") as fh:
            fh.write(b"\0" * (1 << 20) + hdr)
        rc, _out, err = cli("-f", img, "-q", "nvidia.artifactscan")
        self.assertEqual(rc, 0, err)

    def test_deflate_bomb_is_capped(self):
        co = zlib.compressobj(9)
        raw = b"".join([co.compress(b"\0" * (16 << 20)) for _ in range(8)] + [co.flush()])  # 128 MiB
        for declared, limit in ((4096, 4096), (0, 64 << 20)):
            old = fb.MAX_ENTRY_SIZE
            fb.MAX_ENTRY_SIZE = 64 << 20
            try:
                flags = fb.FLAG_64BIT | fb.FLAG_DEFLATE
                body = struct.pack(fb.ENTRY_FMT, 2, 0x101, 64, len(raw), len(raw), 0, 0, 0, 89, 0, 0, flags, 0,
                                   declared) + raw
                f = fb.parse_fatbin(struct.pack("<IHHQ", fb.FATBIN_MAGIC, 1, 16, len(body)) + body)
                self.assertIsNone(f.entries[0].data)
                self.assertIn("exceeds %d bytes" % limit, f.entries[0].error)
            finally:
                fb.MAX_ENTRY_SIZE = old

    def test_lz4_overlap_copy_matches_bytewise_reference_and_is_bounded(self):
        def ref(src, expected=0):  # the original byte-by-byte decoder semantics
            out, i = bytearray(), 0
            while i < len(src):
                t = src[i]; i += 1
                lit = t >> 4
                if lit == 15:
                    while True:
                        b = src[i]; i += 1; lit += b
                        if b != 255:
                            break
                out += src[i:i + lit]; i += lit
                if i >= len(src):
                    break
                off = src[i] | src[i + 1] << 8; i += 2
                ml = t & 15
                if ml == 15:
                    while True:
                        b = src[i]; i += 1; ml += b
                        if b != 255:
                            break
                s = len(out) - off
                for k in range(ml + 4):
                    out.append(out[s + k])
            return bytes(out[:expected] if expected else out)
        rnd = random.Random(3)
        for _ in range(60):
            chunks = [bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 9))) * rnd.randint(1, 300)
                      for _ in range(rnd.randint(1, 6))]
            data = b"".join(chunks)
            comp = lz4.compress(data)
            self.assertEqual(lz4.decompress(comp), data)
            self.assertEqual(lz4.decompress(comp), ref(comp))
            n = rnd.randint(1, len(data))
            self.assertEqual(lz4.decompress(comp, expected_size=n), data[:n])
        bomb = bytes([0x1F]) + b"A" + bytes([1, 0]) + b"\xff" * 4000 + b"\x00" + bytes([0x10]) + b"B"
        self.assertEqual(len(lz4.decompress(bomb, expected_size=100)), 100)
        with self.assertRaises(lz4.LZ4Error):
            lz4.decompress(bomb, max_size=1000)

    @unittest.skipUnless(compression.zstd_available(), "no zstd backend")
    def test_zstd_is_bounded_and_reports_consumed_size(self):
        payload = os.urandom(1 << 16) * 4
        frame = compression.zstd_compress(payload)
        out, used = compression.zstd_frame(frame + b"TRAILER")
        self.assertEqual((out, used), (payload, len(frame)))
        self.assertIsNone(compression.zstd_frame(compression.zstd_compress(b"\0" * (64 << 20)), max_output=1 << 20))
        hits = list(compression.iter_zstd_frames(b"xx" + frame + b"yy" + frame, base=0x100))
        self.assertEqual([(h[0], h[1]) for h in hits], [(0x102, len(frame)), (0x104 + len(frame), len(frame))])


class _Chunky(DataLayer):
    """A layer without regions(): forces scan()'s chunked path."""
    KIND = "test"

    def __init__(self, data):
        super().__init__("chunky")
        self.data = data

    def ranges(self):
        return [(0, len(self.data))]

    def _read_run(self, off, n):
        return self.data[off:off + n]

    @property
    def size(self):
        return len(self.data)


class SparseLayerPerformanceTests(unittest.TestCase):
    """A real Windows live dump has ~280,000 runs of pages. Rebuilding the starts list on every read made a
    self-profile take 405 s, and one worker task per run made a pool-tag scan take 437 s; both are now
    proportional to the data, not to runs x reads."""

    def test_starts_built_once_per_ranges_list(self):
        from keto.framework.layers import SegmentedLayer, BytesLayer
        base = BytesLayer("b", bytes(range(256)) * 64)
        layer = SegmentedLayer("s", [(i * 0x2000, 0x10, base, i * 0x10) for i in range(500)])
        first = layer._starts()
        self.assertIs(layer._starts(), first)
        self.assertEqual(layer.read(0x2000 * 7, 4), bytes(range(0x70, 0x74)))
        self.assertIs(layer._starts(), first)

    def test_many_small_regions_are_batched(self):
        specs = [(i * 0x10000, "f.bin", i * 0x1000, 0x1000) for i in range(5000)]
        tasks = parallel.plan(specs, overlap=16, part_size=1 << 20)
        self.assertEqual(len(tasks), 20)  # 5000 x 4 KiB in 1 MiB tasks, not 5000 tasks
        pieces = [p for _path, ps in tasks for p in ps]
        self.assertEqual(len(pieces), 5000)
        for (fstart, fend, keep_from, limit, loff), (l_off, _p, f_off, length) in zip(pieces, specs):
            self.assertEqual((fstart, fend, keep_from, limit, loff), (f_off, f_off + length, l_off, l_off + length,
                                                                      l_off))  # each region scanned on its own
        big = parallel.plan([(0, "f.bin", 0, 3 << 20)], overlap=16, part_size=1 << 20)
        self.assertEqual([len(ps) for _p, ps in big], [1, 1, 1])  # a large region is still split with overlap
        self.assertEqual(big[1][1][0][:2], ((1 << 20) - 16, (2 << 20) + 16))


class ScanBoundaryTests(unittest.TestCase):
    """IMG-1: no phantom matches at worker-part or chunk boundaries; hits in offset order."""

    def test_parallel_and_chunked_equal_serial(self):
        rnd = random.Random(9)
        data = bytearray(rnd.getrandbits(8) for _ in range(1 << 20))
        for k in range(0, len(data) - 400, 4999):
            data[k:k + 300] = b"A" * 300 if k % 2 else b"SHARED-PAGE-%08d " % k
        data = bytes(data)
        makers = [lambda: sc.RegexScanner(rb"A{20,}", max_length=64),
                  lambda: sc.AnchoredScanner([b"PAGE", b"SHARED"], rb"SHARED-PAGE-\d+", before=8, after=32)]
        path = os.path.join(TMP, "bound.raw")
        with open(path, "wb") as fh:
            fh.write(data)
        layer = FileLayer("raw", path)
        old = (parallel.PARALLEL_MIN, parallel.PART_SIZE, os.environ.get("KETO_WORKERS"))
        try:
            for make in makers:
                cut = make().overlap

                def hits(lay, **kw):
                    return [(o, (v.group() if hasattr(v, "group") else v)[:cut]) for o, v in sc.scan(lay, make(), **kw)]
                os.environ["KETO_WORKERS"] = "1"
                serial = hits(layer)
                parallel.PARALLEL_MIN, parallel.PART_SIZE = 0, (32 << 10) + 7
                os.environ["KETO_WORKERS"] = "3"
                par = hits(layer)
                parallel.PARALLEL_MIN, parallel.PART_SIZE = old[0], old[1]
                chunked = hits(_Chunky(data), chunk_size=(24 << 10) + 3)
                self.assertEqual(serial, par)
                self.assertEqual(serial, chunked)
                self.assertEqual([o for o, _ in serial], sorted(o for o, _ in serial))
        finally:
            parallel.PARALLEL_MIN, parallel.PART_SIZE = old[0], old[1]
            if old[2] is None:
                os.environ.pop("KETO_WORKERS", None)
            else:
                os.environ["KETO_WORKERS"] = old[2]
            layer.close()
            parallel._shutdown()


class ProfileTests(unittest.TestCase):
    def test_gpu_name_banners(self):
        """IMG-3"""
        from keto.framework.automagic import NAME_RE
        from keto.framework.profiles import registry
        reg = registry([])
        for text, want in ((b"NVIDIA GeForce RTX 4050 Laptop GPU\0", "ada"), (b"Tesla V100-SXM2-16GB", "volta"),
                           (b"NVIDIA GeForce GTX 1080 Ti", "pascal"), (b"NVIDIA H100 80GB HBM3", "hopper"),
                           (b"NVIDIA GeForce RTX 3090", "ampere"), (b"NVIDIA Tesla K80", "kepler")):
            m = NAME_RE.search(text)
            self.assertEqual(reg.by_device_name(m.group().decode()).name, want, text)

    def test_contradicting_profile_is_flagged(self):
        """IMG-2"""
        with Context(image=synth(), profile="hopper") as c:
            with self.assertLogs("keto.automagic", level="WARNING"):
                _ = c.profile
            self.assertIn("CONTRADICTING ada", c.profile_reason)
        with Context(image=synth(), profile="ada") as c:
            _ = c.profile
            self.assertEqual(c.profile_reason, "selected with --profile")


class QmdV0501Tests(unittest.TestCase):
    """QMD V05_01 (Blackwell task with sub-tasks) is decoded from the published clcdc0qmd.h layout."""

    def build(self, programs):
        from keto.gpu import qmd
        def sub(prog, grid, block, regs):
            return {"prog_lo": (prog >> 4) & 0xFFFFFFFF, "prog_hi": prog >> 36, "grid_w": grid[0], "grid_h": grid[1],
                    "grid_d": grid[2], "block_x": block[0], "block_y": block[1], "block_z": block[2], "regs": regs,
                    "smem": 1}
        first = dict(sub(*programs[0]), sub_tasks=len(programs), qmd_type=2)
        return qmd.encode("v05_01", first, cbufs=[(0, 0x7000000040, 0x100)],
                          sub_tasks=[sub(*p) for p in programs[1:]])

    def test_round_trip_and_sub_tasks(self):
        from keto.gpu import qmd
        raw = self.build([(0x300000000, (128, 1, 1), (256, 1, 1), 32), (0x380000010, (4, 2, 1), (64, 2, 1), 40)])
        self.assertEqual(qmd.detect(raw), "v05_01")
        q = qmd.decode(raw)
        self.assertTrue(q.plausible())
        self.assertTrue(qmd.quick_plausible(raw))
        self.assertEqual((q.program_address, q.grid, q.block, q.registers, q.shared_memory, q.qmd_type),
                         (0x300000000, (128, 1, 1), (256, 1, 1), 32, 128, "grid CTA"))
        self.assertEqual(q.constant_buffers(), [(0, 0x7000000040, 0x100)])
        subs = q.sub_tasks
        self.assertEqual([s.sub_task for s in subs], [0, 1])
        self.assertEqual((subs[1].program_address, subs[1].grid, subs[1].block, subs[1].registers),
                         (0x380000010, (4, 2, 1), (64, 2, 1), 40))
        self.assertEqual(subs[1].release_address, q.release_address)  # the release belongs to the task

    def test_every_sub_task_program_is_a_launch(self):
        """End to end: sub-task 1 of a V05_01 task runs the image's injected writable code; it must appear as a
        launch and be flagged by suspiciouslaunch (the task's sub-task 0 is the known vector_add kernel)."""
        from keto.gpu import discovery, qmd
        truth = json.load(open(synth("ground_truth.json")))
        add, inj = truth["launches"][0]["program_va"], truth["injected_code"]["va"]
        real_decode = qmd.decode

        def as_task(raw, version=None):
            q = real_decode(raw, version)
            if q is None or q.program_address != add:
                return q
            return real_decode(self.build([(add, q.grid, q.block, q.registers), (inj, (1, 1, 1), (32, 1, 1), 16)]))
        old = discovery.qmd_fmt.decode
        discovery.qmd_fmt.decode = as_task
        try:
            with Context(image=synth()) as c:
                launches = PLUGINS["nvidia.launches"](c, {}).run().as_dicts()
                flagged = PLUGINS["nvidia.malware.suspiciouslaunch"](c, {}).run().as_dicts()
        finally:
            discovery.qmd_fmt.decode = old
        subs = [r for r in launches if "sub-task 1/2" in str(r["QMD"])]
        self.assertTrue(subs)  # vector_add is launched twice in the image (one launch still pending)
        self.assertEqual({r["Program VA"] for r in subs}, {inj})
        self.assertTrue(any(r["Program VA"] == inj for r in flagged), flagged)


class IndicatorTests(unittest.TestCase):
    def test_miner_contexts(self):
        """DET-4"""
        from keto.indicators.miners import classify
        for text in ("python -m pip install argon2-cffi", "zlib miniz", "cuckoo sandbox", "OctopusDeploy"):
            self.assertEqual(classify(text, context="process"), [], text)
        self.assertEqual(classify("alephium-wallet", context="string"), [])
        self.assertIn(("miner-algorithm", "rx/0"), classify("xmrig --algo rx/0", context="process"))
        self.assertIn(("miner-software", "rigel"), classify("/usr/bin/rigel -a kawpow", context="process"))
        self.assertEqual(classify("blake3_hash_many", context="kernel"), [("hash-primitive", "blake3")])
        self.assertIn(("miner-algorithm", "ethash"), classify("ethash_search", context="kernel"))
        self.assertIn(("miner-algorithm", "blake3"), classify("blake3"))  # default context unchanged

    def test_secrets(self):
        """DET-12 (regex part)"""
        from keto.indicators.secrets import find
        got = lambda s: [(n, v) for _, n, v in find(b"xx " + s + b" yy")]
        self.assertEqual(got(b"PWD=/home/user/project\0"), [])
        self.assertEqual(got(b"PWD=C:\\Users\\x\0"), [])
        self.assertEqual(got(b"PWd:" + bytes([0x8F, 0x91, 0xA3, 0xFF, 0x92, 0x81, 0xEE, 0x9A])), [])
        self.assertEqual(got(b'db_password = "hunter2hunter2"'), [("password-assignment", 'db_password = "hunter2hunter2')])
        self.assertEqual(got(b"UID=sa;PWD=Sup3rS3cret;"), [("password-assignment", "PWD=Sup3rS3cret;")])

    def test_driver_kernel_families(self):
        """DET-3"""
        from keto.indicators.driver_kernels import is_driver_internal, is_nvidia_library
        for n in ("cudaSubgridLaunch", "cudaFabricOpErrorStatusCount", "_Z28__cuda_syscall_bw_tld_sharedILb0EE7tex"):
            self.assertTrue(is_driver_internal(n), n)
        self.assertFalse(is_driver_internal("decrypt_payload"))
        self.assertTrue(is_nvidia_library("/usr/lib/wsl/lib/libcuda.so.1.1"))
        self.assertTrue(is_nvidia_library(r"C:\Windows\System32\DriverStore\FileRepository\nv\nvcuda64.dll"))
        self.assertFalse(is_nvidia_library("/home/user/libevil.so"))

    def test_xid_times_without_zone_are_not_declared_utc(self):
        from keto.indicators.xid import _timestamp
        self.assertIsNone(_timestamp("2026-11-16T10:00:00 host kernel: x", None, None).tzinfo)
        self.assertIsNone(_timestamp("Nov 16 10:00:00 host kernel: x", None, 2026).tzinfo)
        z = _timestamp("2026-11-16T10:00:00+02:00 host kernel: x", None, None)
        self.assertEqual((z.utcoffset().total_seconds(), z.hour), (0, 8))

    def test_envscan_injection_severity_follows_location(self):
        """DET-15"""
        from keto.plugins.nvidia.envscan import severity
        self.assertEqual(severity("LD_PRELOAD", "/dev/shm/a.so"), "high")
        self.assertEqual(severity("LD_PRELOAD", "/usr/lib/libfoo.so"), "medium")
        self.assertEqual(severity("CUDA_INJECTION64_PATH", "/opt/nvidia/nsight/libinj.so"), "medium")
        self.assertEqual(severity("CUDA_INJECTION64_PATH", "C:\\Users\\u\\AppData\\Local\\Temp\\i.dll"), "high")


class RendererAndCorePluginTests(unittest.TestCase):
    def test_json_keeps_na_reasons_and_quick_rows_stay_on_one_line(self):
        from keto.framework.treegrid import Disassembly, TreeGrid, na
        g = TreeGrid([("A", str), ("B", object)], [(0, (na("not in snapshot"), Disassembly("l1\nl2"))), (0, ("x", 1))])
        row = json.loads(render_to_string(g, "json"))[0]
        self.assertIsNone(row["A"])
        self.assertEqual(row["__na"], {"A": "not in snapshot"})
        lines = render_to_string(g, "quick").splitlines()
        self.assertEqual(lines[2], "N/A (not in snapshot)\t<see below>")
        self.assertEqual(lines[-1], "x\t1")

    def test_hexdump_reports_unbacked_bytes(self):
        """IMG-10"""
        with Context(image=synth()) as c:
            row = PLUGINS["hexdump"](c, {"address": 0x20000, "length": 64}).run().as_dicts()[0]
            self.assertTrue(row["Unbacked"].startswith("all 64"))
            row = PLUGINS["hexdump"](c, {"address": (64 << 20) - 16, "length": 64}).run().as_dicts()[0]
            self.assertIn("48 of 64 byte(s) NOT backed", row["Unbacked"])

    def test_regexscan_accepts_gpu_address_spaces(self):
        """IMG-11"""
        with Context(image=synth()) as c:
            rows = PLUGINS["regexscan"](c, {"pattern": "SHARED", "layer": "as_100000"}).run().as_dicts()
        self.assertTrue(rows)
        self.assertTrue(all(r["Layer"] == "as_100000" for r in rows))

    def test_banners_drop_overlapping_duplicates(self):
        with Context(image=synth()) as c:
            texts = [r["Banner"] for r in PLUGINS["banners"](c, {}).run().as_dicts()]
        self.assertFalse(any(a != b and a in b for a in texts for b in texts), texts)

    def test_layerwriter_output_is_sparse_and_correct(self):
        d = tempfile.mkdtemp(dir=TMP)
        lime = os.path.join(d, "s.lime")
        write_lime(lime, [(0x1000, b"x" * 4096), (0x40000000, b"y" * 4096)])
        with Context(image=lime, output_dir=os.path.join(d, "o")) as c:
            path = PLUGINS["layerwriter"](c, {}).run().as_dicts()[0]["File"]
        with open(path, "rb") as fh:
            fh.seek(0x1000)
            self.assertEqual(fh.read(4), b"xxxx")
            fh.seek(0x40000000)
            self.assertEqual(fh.read(4), b"yyyy")
        if os.name == "nt":
            import ctypes
            hi = ctypes.c_ulong(0)
            lo = ctypes.windll.kernel32.GetCompressedFileSizeW(path, ctypes.byref(hi))
            self.assertLess((hi.value << 32) + lo, 64 << 20)


class CacheParserTests(unittest.TestCase):
    def test_shadercache_guess_kind_and_large_files(self):
        """WIN-5 / WIN-6 / section 11"""
        from keto.formats import shadercache
        d = tempfile.mkdtemp(dir=TMP)
        nv = os.path.join(d, "collected")
        os.makedirs(nv)
        dxbc = gpucode.build_dxbc(program_type=5)
        with open(os.path.join(nv, "abc_1.nvph"), "wb") as fh:
            fh.write(b"nvph" + b"\0" * 300 + dxbc + b"\0" * 5000 + dxbc + b"\0" * 300)
        self.assertEqual(shadercache.guess_kind(nv), "nvdx")
        old = (shadercache.READ_CHUNK, shadercache.CHUNK_OVERLAP)
        shadercache.READ_CHUNK, shadercache.CHUNK_OVERLAP = 1024, 512  # force many chunks
        try:
            e = shadercache.read_blob_file("nvdx", os.path.join(nv, "abc_1.nvph"))
        finally:
            shadercache.READ_CHUNK, shadercache.CHUNK_OVERLAP = old
        self.assertEqual((e.shaders, e.compute_shaders, e.error), (2, 2, None))
        rows = PLUGINS["nvidia.shadercache"](Context(), {"path": nv}).run().as_dicts()
        self.assertTrue(rows[0]["Program"].startswith("(no program name recorded: NVIDIA DXCache abc"))
        self.assertNotIn("no longer on disk", rows[0]["Attention"] or "")

    def test_jitcache_build_stamp(self):
        from keto.formats.computecache import CacheEntry
        e = CacheEntry("p", 1, 1, b"Jun  3 202617:23:34HOST64sm_89\r\n\r\n.version 9.0\n", b"", 0, True)
        self.assertEqual(e.stamp, "Jun 3 2026 17:23:34, HOST64, sm_89")


class ReportTests(unittest.TestCase):
    def test_integrity_status_and_hash_primitive_severity(self):
        from keto import report
        with Context(image=synth()) as c:
            rep = report.build(c, include_live=False)
        self.assertTrue(rep["integrity"].startswith("verified"), rep["integrity"])
        rule = [r for r in report.RULES if r.plugin == "nvidia.malware.miner"][0]
        self.assertEqual(rule.sev({"Category": "hash-primitive"}), "low")
        self.assertEqual(rule.sev({"Category": "miner-algorithm"}), "high")
        bad = os.path.join(TMP, "bad_report.keto")
        data = rb(synth())
        with open(bad, "wb") as fh:
            fh.write(data.replace(b'"0x197"', b'"0x164"', 1))
        logging.disable(logging.WARNING)
        try:
            with Context(image=bad, profile="ada") as c:
                rep = report.build(c, include_live=False)
        finally:
            logging.disable(logging.NOTSET)
        self.assertTrue(rep["integrity"].startswith("FAILED"), rep["integrity"])
        self.assertIn("EVIDENCE INTEGRITY FAILED", report.to_html(rep))


if __name__ == "__main__":
    unittest.main()
