"""Regression tests for the image-analysis findings of the 2026-11-23 audit, checked against
the synthetic ground truth where one exists."""

import json
import os
import random
import shutil
import struct
import tempfile
import time
import unittest

from keto.formats import aes, compression, cubin as cubin_fmt, fatbin as fatbin_fmt, vbios
from keto.formats.container import ContainerWriter
from keto.formats.imaging import swizzle
from keto.framework.context import Context
from keto.framework.exceptions import RequirementError
from keto.framework.layers import BytesLayer
from keto.framework.plugin import PLUGINS, load_plugins
from keto.framework.profiles import registry
from keto.gpu import artifacts, qmd, ramin
from keto.gpu.gmmu import SYS_COH, VID
from keto.plugins.nvidia.artifacts import Secrets, pe_extent
from keto.plugins.nvidia.memory import classify
from keto.testing.synth import PTX_MINER, build_all, build_image, build_snapshot_metadata, sass_function

TMP = TRUTH = None


def setUpModule():
    global TMP, TRUTH
    load_plugins()
    TMP = tempfile.mkdtemp(prefix="keto-fixes-")
    TRUTH = build_all(TMP)["truth"]


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def ctx(image=None, **kw):
    kw.setdefault("output_dir", os.path.join(TMP, "out"))
    return Context(image=image or os.path.join(TMP, "synthetic.keto"), **kw)


def run(name, c=None, **opts):
    with (c or ctx()) as cx:
        g = PLUGINS[name](cx, opts).run()
        return g.as_dicts()


def raw_image(name, data, gen="ada"):
    """A raw VRAM file with its metadata sidecar (so the profile comes from the chipset)."""
    path = os.path.join(TMP, name)
    with open(path, "wb") as fh:
        fh.write(data)
    with open(path + ".json", "w") as fh:
        json.dump(build_snapshot_metadata(gen), fh)
    return path


class InstanceBlockValidity(unittest.TestCase):
    """DET-1: random data must not yield (privileged) channels."""

    def test_random_pages_with_the_signature_never_validate(self):
        rnd = random.Random(1)
        for name in ("kepler", "maxwell", "volta", "turing", "ada", "hopper", "blackwell"):
            prof = registry().get(name)
            fc = prof.ramfc
            pages = bytearray(rnd.getrandbits(8) for _ in range(1500 * 4096))
            for i in range(1500):
                o = i * 4096 + fc["signature"]
                v = struct.unpack_from("<I", pages, o)[0]
                struct.pack_into("<I", pages, o, (v & ~fc["signature_mask"]) | fc["signature_value"])
            layer = BytesLayer("vram", bytes(pages))
            valid = [pa for pa in range(0, len(pages), 4096)
                     if ramin.parse_instance_block(layer, pa, prof, 64 << 20).valid]
            self.assertEqual(valid, [], name)

    def _block(self, prof, **kw):
        args = dict(pdb=0x100000, gp_base_va=0x2_0000_0000, gp_limit2=3, userd_addr=0x30000, gp_get=3, gp_put=4)
        args.update(kw)
        return bytearray(ramin.encode_instance_block(prof, **args))

    def _parse(self, prof, blk):
        return ramin.parse_instance_block(BytesLayer("vram", bytes(blk)), 0, prof, 64 << 20)

    def test_structural_contradictions_invalidate(self):
        prof = registry().get("turing")
        fc, ri = prof.ramfc, prof.ramin
        self.assertTrue(self._parse(prof, self._block(prof)).valid)
        # sysmem page directory beyond 52 bits (the audit's 0x3a4f6824c7c11000)
        blk = self._block(prof, pdb_aperture=SYS_COH, pdb=0x3A4F6824C7C11000)
        self.assertFalse(self._parse(prof, blk).valid)
        blk = self._block(prof, pdb_aperture=SYS_COH, pdb=0x7_8000_0000)  # 30 GiB of host RAM: fine
        self.assertTrue(self._parse(prof, blk).valid)
        # GP_GET / GP_PUT outside the 8-entry ring
        self.assertFalse(self._parse(prof, self._block(prof, gp_get=8)).valid)
        self.assertFalse(self._parse(prof, self._block(prof, gp_put=553449550)).valid)
        # reserved GP_BASE_HI bit, reserved USERD_HI bits
        blk = self._block(prof)
        struct.pack_into("<I", blk, fc["gp_base_hi"], struct.unpack_from("<I", blk, fc["gp_base_hi"])[0] | 1 << 30)
        self.assertFalse(self._parse(prof, blk).valid)
        blk = self._block(prof)
        struct.pack_into("<I", blk, fc["userd_hi"], 0x100)
        self.assertFalse(self._parse(prof, blk).valid)
        # a subcontext marked valid whose page directory is garbage
        blk = self._block(prof, subcontexts=[(0, VID, 0x100000)])
        self.assertTrue(self._parse(prof, blk).valid)
        struct.pack_into("<I", blk, ri["sc_pdb_valid"], 0b11)
        struct.pack_into("<II", blk, ri["sc_page_dir_base"] + 16, 0xDEAD1001, 0xFFFFFFFF)
        ib = self._parse(prof, blk)
        self.assertFalse(ib.valid)
        self.assertTrue(any("subcontext" in r for r in ib.rejects))

    def test_no_gpfifo_is_invalid(self):
        prof = registry().get("ada")
        self.assertFalse(self._parse(prof, self._block(prof, gp_limit2=0)).valid)


class ChannelUserd(unittest.TestCase):
    def test_chanscan_all_keeps_runlist_userd_on_ampere_plus(self):
        """IMG-5: --all no longer drops the runlist-only USERD; channel C (in no runlist) shows N/A."""
        rows = {int(r["InstanceBlock"]): r for r in run("nvidia.chanscan", all=True)}
        ch = TRUTH["channels"]
        for k in ("A", "B", "D"):
            self.assertEqual(int(rows[ch[k]["inst"]]["USERD"]), ch[k]["userd"])
        self.assertIn("not in a runlist", str(rows[ch["C"]["inst"]]["USERD"]))


class QmdPlausibility(unittest.TestCase):
    """DET-5: launch descriptors outside the hardware limits are not QMDs."""

    def test_limits(self):
        ok = qmd.decode(qmd.make_launch(0x3_0000_0100, grid=(64, 1, 1), block=(128, 1, 1), registers=16))
        self.assertTrue(ok.plausible())
        bad = [dict(registers=0), dict(registers=300), dict(block=(8, 8, 65)), dict(block=(1025, 1, 1)),
               dict(grid=(1 << 31, 1, 1)), dict(shared=240 << 10), dict(cbufs=[(0, 0x1000, 0x1FFF0)])]
        for kw in bad:
            args = dict(grid=(64, 1, 1), block=(128, 1, 1), registers=16)
            args.update(kw)
            q = qmd.decode(qmd.make_launch(0x3_0000_0100, **args))
            self.assertFalse(q.plausible(), kw)
            if "block" in kw or "grid" in kw:
                self.assertFalse(qmd.quick_plausible(q.raw), kw)

    def test_audit_false_positives_rejected(self):
        # the two descriptors 64 MiB of System32 DLLs produced (V00_06 0 registers, V05_00 511 registers)
        q = qmd.decode(qmd.make_launch(0xC0002CE0, grid=(64618520, 33, 960), block=(7, 8, 9), registers=0,
                                       version="v00_06"))
        self.assertFalse(q.plausible())
        q = qmd.decode(qmd.make_launch(0x10, grid=(1946185216, 17408, 29696), block=(271, 1, 1), registers=511,
                                       version="v05_00"))
        self.assertFalse(q.plausible())


class Surfaces(unittest.TestCase):
    def test_integer_tables_are_not_xrgb_images(self):
        """DET-5: 32-bit integers below 2^24 look like XRGB pixels; they are not smooth and are dropped."""
        rnd = random.Random(7)
        data = bytearray(4 << 20)
        for off in range(0x100000, 0x300000, 4):
            struct.pack_into("<I", data, off, rnd.randrange(1 << 24))
        path = raw_image("ints.raw", bytes(data))
        self.assertEqual(run("nvidia.surfaces", ctx(path)), [])

    def test_ground_truth_surfaces_kept(self):
        got = {(int(r["PA"]), r["Width"], r["Height"]) for r in run("nvidia.surfaces")}
        self.assertEqual(got, {(s["pa"], s["width"], s["height"]) for s in TRUTH["surfaces"]})

    def test_manual_bounds(self):
        """DOS-6: absurd sizes are refused cleanly."""
        for opts in (dict(offset=0, width=100000, height=100000), dict(offset=0, width=8192, height=8192),
                     dict(offset=0x3FFF000, width=256, height=256),
                     dict(offset=0, width=64, height=64, layout="blocklinear", block_height=3)):
            with self.assertRaises(RequirementError, msg=opts):
                run("nvidia.surfaces", **opts)
        rows = run("nvidia.surfaces", offset=0x1000000, width=256, height=128)
        self.assertEqual(rows[0]["Width"], 256)

    def test_residual_capture(self):
        """IMG-13: surfaces, strings and residual work on a CUDA residual capture (layer 'residual', GPU VA)."""
        from keto.testing.synth import _surface_pixels
        va = 0x7F00_0000_0000
        data = bytearray(1 << 20)
        data[0x10000:0x10000 + 256 * 128 * 4] = _surface_pixels(256, 128, 0)
        text = PTX_MINER.encode()
        data[0x80000:0x80000 + len(text)] = text
        path = os.path.join(TMP, "residual.keto")
        w = ContainerWriter(path, {"acquisition": {"method": "cuda"}})
        w.add_segment("residual", va, bytes(data))
        w.close()
        s = run("nvidia.surfaces", ctx(path))
        self.assertEqual([(int(r["PA"]), r["Width"], r["Height"]) for r in s], [(va + 0x10000, 256, 128)])
        self.assertIn("residual", s[0]["MappedAt"])
        st = run("nvidia.strings", ctx(path))
        self.assertTrue(any(int(r["PA"]) >= va and "ethash_search" in r["String"] for r in st))
        res = {int(r["Start PA"]): r for r in run("nvidia.residual", ctx(path))}
        self.assertEqual(res[va + 0x80000]["Content"], "PTX source")
        self.assertIn(va + 0x10000, res)


class VbiosChecks(unittest.TestCase):
    """DET-11: structural anomaly checks and --known-good."""

    def _chain(self, rom):
        return vbios.parse_chain(rom, 0)

    def test_clean_rom(self):
        rom = vbios.build_rom()
        self.assertEqual(vbios.anomalies(rom, self._chain(rom), len(rom)), [])

    def test_anomalies(self):
        rom = bytearray(vbios.build_rom())
        rom[0x150] ^= 1  # checksum
        self.assertIn("checksum BAD in image 0", vbios.anomalies(bytes(rom), self._chain(bytes(rom)), len(rom)))
        rom = bytearray(vbios.build_rom())
        rom[0x55] = 0  # not the last image, nothing follows
        p = vbios.anomalies(bytes(rom), self._chain(bytes(rom)), len(rom))
        self.assertTrue(any(x.startswith("chain:") for x in p), p)
        # second image from another vendor
        first = bytearray(vbios.build_rom())
        first[0x55] = 0
        first[-1] = (first[-1] + 0x80) % 256  # keep the checksum right
        second = vbios.build_rom(vendor=0x8086, device=0x1234)
        rom = bytes(first) + second
        p = vbios.anomalies(rom, self._chain(rom), len(rom))
        self.assertTrue(any(x.startswith("vendor mismatch: image 1 is 8086:1234") for x in p), p)
        # sign-on banner disagreeing with the BIT version, BIT token outside the ROM
        rom = bytearray(vbios.build_rom(strings=(b"NVIDIA Corp", b"Version 95.07.11.00.01 ")))
        struct.pack_into("<H", rom, 0x200 + 18 + 4, 0xFFF0)  # token 'B' offset
        rom[-1] = 0
        rom[-1] = (-sum(rom)) % 256
        p = vbios.anomalies(bytes(rom), self._chain(bytes(rom)), len(rom))
        self.assertTrue(any("sign-on banner says 95.07.11.00.01" in x for x in p), p)
        self.assertTrue(any("point outside the ROM" in x for x in p), p)

    def test_plugin_finding_and_known_good(self):
        rom = vbios.build_rom()
        img = bytearray(1 << 20)
        img[0x10000:0x10000 + len(rom)] = rom
        img[0x10000 + len(rom) + 0x10:0x10000 + len(rom) + 0x30] = b"\xcc" * 0x20  # appended payload
        path = raw_image("rom.raw", bytes(img))
        rows = run("nvidia.vbios", ctx(path))
        self.assertEqual(len(rows), 1)
        self.assertIn("trailing data: 32 non-padding byte(s)", rows[0]["Finding"])
        good = os.path.join(TMP, "good.sha256")
        with open(good, "w") as fh:
            fh.write("# known-good\n%s  RTX4050-95.07.2D.00.5F\n" % vbios.digest(rom))
        rows = run("nvidia.vbios", ctx(path), known_good=good)
        self.assertTrue(rows[0]["KnownGood"])
        ref = os.path.join(TMP, "ref.rom")
        other = bytearray(rom)
        other[0x300] = 0x94
        with open(ref, "wb") as fh:
            fh.write(bytes(other))
        rows = run("nvidia.vbios", ctx(path), known_good=ref)
        self.assertFalse(rows[0]["KnownGood"])
        self.assertIn("known-good: differs from %s at +0x300" % ref, rows[0]["Finding"])
        rows = run("nvidia.vbios")  # the synthetic image's ROM is clean
        self.assertEqual([r["Finding"] for r in rows], ["none"])


class ModifiedImage(unittest.TestCase):
    """Malfind (DET-14 / NI-7) and fillscan (DET-13) on a modified copy of the ground-truth image."""

    @classmethod
    def setUpClass(cls):
        data, cls.truth = build_image(gen="ada")
        data = bytearray(data)
        cls.deep = 0xC00000 + 0x100000  # 1 MiB into the writable 2 MiB tensor page (AS1 0x4_0000_0000)
        code = sass_function(4242, 16)
        data[cls.deep:cls.deep + len(code)] = code
        inj = cls.truth["injected_code"]
        data[inj["pa"]:inj["pa"] + inj["size"]] = bytes(inj["size"])  # launched page no longer looks like SASS
        data[0x3C00000:0x3E00000] = struct.pack("<f", 1.0) * (0x200000 // 4)  # 00 00 80 3F
        data[0x3E00000:0x3F00000] = bytes(range(8)) * (0x100000 // 8)       # 00 01 .. 07
        cls.path = raw_image("modified.raw", bytes(data))

    def test_malfind_scans_whole_page_and_flags_launches(self):
        rows = {int(r["VA"]): r for r in run("nvidia.malware.malfind", ctx(self.path))}
        self.assertIn(0x4_0000_0000 + 0x100000, rows)
        self.assertEqual(rows[0x4_0010_0000]["Reason"], "SASS in writable page")
        inj = self.truth["injected_code"]["va"]
        self.assertTrue(rows[inj]["Reason"].startswith("launch PROGRAM_ADDRESS in writable page (launched by"))

    def test_fillscan_patterns_starting_with_zero(self):
        rows = {(int(r["Start"]), r["Pattern"]) for r in run("nvidia.malware.fillscan", ctx(self.path))}
        self.assertTrue({(0x3C00000, "0000803f"), (0x3E00000, "0001020304050607"),
                         (self.truth["fill"]["pa"], "ff")} <= rows, rows)


class CommandStreams(unittest.TestCase):
    def test_gputimeline_skips_pending_relaunch(self):
        """IMG-4: the pending GPFIFO entry relaunches q1; it has not run, so it is not a completion."""
        rows = run("nvidia.gputimeline")
        self.assertEqual(len(rows), len(TRUTH["timeline"]))
        self.assertEqual(sorted(int(r["GPU time (ns)"]) for r in rows), sorted(e["ns"] for e in TRUTH["timeline"]))

    def test_semaphores_include_qmd_release(self):
        rows = run("nvidia.semaphores")
        q = [r for r in rows if r["Engine"] == "compute (QMD release)"]
        self.assertTrue(q)
        self.assertEqual({int(r["Address"]) for r in q}, {0x2_0003_0020})
        self.assertEqual({int(r["Payload"]) for r in q}, {5})

    def test_pbscan_does_not_merge_channels(self):
        rows = {int(r["Offset"]): r for r in run("nvidia.pbscan")}
        self.assertIn(0x410400, rows)  # channel B's segment b1 is its own stream
        self.assertLessEqual(0x410000 + rows[0x410000]["Bytes"], 0x410400)
        self.assertTrue(rows[0x410400]["ReferencedByChannel"])

    def test_launches_method_text(self):
        """DOC-4."""
        m = PLUGINS["nvidia.launches"].METHOD
        self.assertIn("V00_06..V05_01", m)  # V05_01 sub-tasks are decoded too
        self.assertNotIn("other versions shown raw", m)

    def test_graphics_method_names(self):
        """NI-1: names from NVIDIA's 3D / 2D / video class headers."""
        db = registry().classes
        self.assertEqual(db.method_name("3d", 0x1618), "BEGIN")
        self.assertEqual(db.method_name("3d", 0x1B00), "SET_REPORT_SEMAPHORE_A")
        self.assertEqual(db.method_name("3d", 0x0D78), "DRAW_VERTEX_ARRAY")
        self.assertEqual(db.method_name("2d", 0x08DC), "PIXELS_FROM_MEMORY_SRC_Y0_INT")
        self.assertEqual(db.method_name("video", 0x0300), "EXECUTE")
        self.assertGreater(len(db.methods["3d"]), 500)
        self.assertGreater(len(db.methods["2d"]), 150)


class MemoryViews(unittest.TestCase):
    def test_vamap_tags_virtual_copy_destination(self):
        """IMG-6: channel B copies VA -> VA; the destination is tagged too."""
        rows = run("nvidia.vamap", aspace="as_%x" % TRUTH["address_spaces"]["AS1"])
        use = {int(r["Start VA"]): r["Use"] for r in rows}
        self.assertIn("copy destination", use[0x9_0000_0000])
        self.assertIn("copy source", use[0x4_0000_0000])

    def test_memmap_dump_writes_map_file(self):
        """NI-6."""
        out = os.path.join(TMP, "memmap")
        name = "as_%x" % TRUTH["address_spaces"]["AS1"]
        rows = run("nvidia.memmap", ctx(output_dir=out), aspace=name, dump=True)
        with open(os.path.join(out, name + ".map")) as fh:
            lines = [ln.split() for ln in fh if not ln.startswith("#")]
        self.assertEqual(len(lines), len(rows))
        dumped = [r for r in rows if r["Readable"]]
        for ln, r in zip(lines, rows):
            self.assertEqual(int(ln[0], 16), int(r["VA"]))
            if r["Readable"]:
                self.assertEqual(int(ln[5], 16), int(r["FileOffset"]))
        self.assertEqual(os.path.getsize(os.path.join(out, name + ".dmp")), sum(int(r["Size"]) for r in dumped))

    def test_mappings_fill_label(self):
        rows = run("nvidia.mappings", aspace="as_%x" % TRUTH["address_spaces"]["AS1"])
        use = {int(r["Start VA"]): r["Contents"] for r in rows}
        self.assertEqual(use[TRUTH["fill"]["va"]], "fill 0xff")

    def test_classify(self):
        """NI-8: magics beyond ELF, text with trailing zeros, PTX."""
        self.assertEqual(classify(PTX_MINER.encode() + bytes(3000)), "PTX source")
        self.assertEqual(classify(b"user=admin password=hunter22\n" + bytes(4000)), "text")
        cases = {b"\x89PNG\r\n\x1a\n": "PNG image", b"\xff\xd8\xff\xe0": "JPEG image", b"PK\x03\x04": "ZIP archive",
                 b"\x1f\x8b\x08\x00": "gzip data", b"\x28\xb5\x2f\xfd": "zstd frame", b"\x04\x22\x4d\x18": "LZ4 frame",
                 b"SQLite format 3\x00": "SQLite database", b"%PDF-1.7": "PDF document",
                 b"-----BEGIN CERTIFICATE-----": "PEM block", fatbin_fmt.FATBIN_MAGIC_BYTES: "CUDA fatbin"}
        for magic, want in cases.items():
            self.assertEqual(classify(magic + bytes(range(256)) * 4), want, magic)
        pe = bytearray(512)
        pe[:2], pe[0x3C:0x40], pe[0x80:0x84] = b"MZ", struct.pack("<I", 0x80), b"PE\x00\x00"
        self.assertEqual(classify(bytes(pe)), "PE executable")
        self.assertEqual(classify(cubin_fmt.build_cubin({"k": sass_function(1)})), "ELF (CUDA cubin)")
        self.assertEqual(classify(b"\xff" * 4096), "fill 0xff")

    def test_residual_classification_and_previews(self):
        rows = {int(r["Start PA"]): r for r in run("nvidia.residual")}
        self.assertNotIn(TRUTH["runlist"]["pa"], rows)                 # live runlist
        self.assertFalse(any(0x30000 <= pa < 0x31000 for pa in rows))  # live USERD pages
        aes_pa = TRUTH["aes"][0]["pa"]
        self.assertTrue(bytes(rows[aes_pa]["Preview"]).startswith(bytes.fromhex(TRUTH["aes"][0]["key"])))
        self.assertEqual(int(rows[aes_pa]["FirstData"]), aes_pa)
        self.assertEqual(rows[TRUTH["ptx"]["pa"]]["Content"], "PTX source")
        self.assertEqual(rows[0x1700000]["Content"], "PEM block")
        self.assertEqual(rows[TRUTH["cubins"][0]]["Content"], "ELF (CUDA cubin)")
        self.assertEqual(rows[TRUTH["fatbin"]["pa"]]["Content"], "CUDA fatbin")

    def test_strings_label_fatbin_by_its_physical_extent(self):
        rows = run("nvidia.strings", min_length=12)
        owners = {r["Owner"] for r in rows if TRUTH["fatbin"]["pa"] <= int(r["PA"]) < TRUTH["fatbin"]["pa"] + 0x1000}
        self.assertTrue(owners)
        self.assertEqual(owners, {"fatbin @0x%x" % TRUTH["fatbin"]["pa"]})


class Artefacts(unittest.TestCase):
    def test_secrets_dedupe(self):
        """DET-12: the JWT inside the bearer header is one secret."""
        rows = run("nvidia.secrets")
        kinds = [r["Kind"] for r in rows]
        self.assertEqual(kinds.count("jwt"), 1)
        self.assertNotIn("bearer-token", kinds)
        self.assertEqual(len(rows), 6)  # 5 planted blocks; the AWS block holds a key id and a secret key
        hits = [(10, "bearer-token", "x" * 40), (32, "jwt", "y" * 18), (100, "password-assignment", "z" * 9)]
        self.assertEqual([h[1] for h in Secrets._dedupe(hits)], ["jwt", "password-assignment"])
        self.assertEqual(run("nvidia.secrets", kind="bearer-token")[0]["Kind"], "bearer-token")

    def test_dumpfiles_manifest_surfaces_and_pe_size(self):
        """IMG-7 and the 512-byte PE carved as 1 MiB."""
        out = os.path.join(TMP, "dump")
        run("nvidia.dumpfiles", ctx(output_dir=out))
        with open(os.path.join(out, "manifest.json")) as fh:
            manifest = json.load(fh)
        surf = [m for m in manifest if m["kind"] == "surface"]
        self.assertEqual(len(surf), len(TRUTH["surfaces"]))
        import hashlib
        for m in surf:
            self.assertTrue(m["file"].endswith(".png"))
            with open(m["file"], "rb") as fh:
                png = fh.read()
            self.assertEqual((m["sha256"], m["size"]), (hashlib.sha256(png).hexdigest(), len(png)))
        pe = [m for m in manifest if m["kind"].startswith("hostexe_PE")]
        self.assertEqual([(m["offset"], m["size"]) for m in pe], [(TRUTH["hostcode"]["pe"], 512)])

    def test_pe_extent(self):
        pe = bytearray(0x2000)
        pe[:2], pe[0x3C:0x40], pe[0x80:0x84] = b"MZ", struct.pack("<I", 0x80), b"PE\x00\x00"
        struct.pack_into("<HH", pe, 0x84, 0x8664, 2)
        struct.pack_into("<H", pe, 0x94, 0xF0)                 # SizeOfOptionalHeader (PE32+)
        struct.pack_into("<H", pe, 0x98, 0x20B)
        struct.pack_into("<II", pe, 0x98 + 36, 0x200, 0)       # FileAlignment
        struct.pack_into("<I", pe, 0x98 + 60, 0x400)           # SizeOfHeaders
        sec = 0x98 + 0xF0
        struct.pack_into("<II", pe, sec + 16, 0x600, 0x400)    # .text raw size / pointer
        struct.pack_into("<II", pe, sec + 40 + 16, 0x100, 0xA00)
        self.assertEqual(pe_extent(bytes(pe)), 0xC00)
        struct.pack_into("<II", pe, 0x98 + 144, 0xC00, 0x234)  # certificate table appended
        self.assertEqual(pe_extent(bytes(pe)), 0x1000)
        self.assertIsNone(pe_extent(b"MZ" + bytes(100)))

    def test_ptx_in_fatbin_counted_once(self):
        rows = run("nvidia.ptxscan")
        self.assertEqual([r["Entries"] for r in rows].count("vector_add"), 1)
        self.assertEqual(len(rows), 2)

    def test_fatbin_undecodable_entry(self):
        """IMG-8: an entry that cannot be decompressed is reported as such by fatbinscan and cubinscan."""
        cub = cubin_fmt.build_cubin({"k": sass_function(5)})
        fb = bytearray(fatbin_fmt.build_fatbin([(fatbin_fmt.KIND_ELF, 89, cub, True)]))
        flags = struct.unpack_from("<Q", fb, 16 + 40)[0]
        struct.pack_into("<Q", fb, 16 + 40, (flags & ~fatbin_fmt.FLAG_COMPRESS) | fatbin_fmt.FLAG_ZSTD)
        img = bytearray(1 << 20)
        img[0x40000:0x40000 + len(fb)] = fb
        path = raw_image("badfatbin.raw", bytes(img))
        entries = [r for r in run("nvidia.fatbinscan", ctx(path)) if r["Kind"] == "ELF"]
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]["Status"].startswith("undecodable:"), entries[0]["Status"])
        cubins = [r for r in run("nvidia.cubinscan", ctx(path)) if r["Source"].startswith("fatbin")]
        self.assertEqual(len(cubins), 1)
        self.assertTrue(cubins[0]["Names"].startswith("undecodable:"))

    @unittest.skipUnless(compression.zstd_available(), "no zstd back-end")
    def test_cubins_in_raw_zstd_frames(self):
        """NI-2: a zstd frame in host memory holding a cubin (how drivers ship internal GPU code)."""
        cub = cubin_fmt.build_cubin({"driver_internal_kernel": sass_function(9)})
        frame = compression.zstd_compress(b"\x00" * 0x100 + cub + b"\x11" * 64)
        img = bytearray(2 << 20)
        img[0x123456:0x123456 + len(frame)] = frame
        img[0x180000:0x180004] = compression.ZSTD_MAGIC  # a stray magic is quietly ignored
        found = list(artifacts.sweep(BytesLayer("host", bytes(img)), None, ("cubin",)))
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].offset, found[0].detail["kernels"]), (0x123456, ["driver_internal_kernel"]))
        self.assertIn("zstd frame", found[0].summary)
        path = raw_image("zstd.raw", bytes(img))
        rows = [r for r in run("nvidia.cubinscan", ctx(path)) if r["Source"].startswith("zstd")]
        self.assertEqual([(int(r["Offset"]), r["Names"]) for r in rows], [(0x123456, "driver_internal_kernel")])
        dump = run("nvidia.cubindump", ctx(path, output_dir=os.path.join(TMP, "zdump")))
        with open(dump[0]["File"], "rb") as fh:
            self.assertEqual(fh.read(), cub)

    def test_sweep_survives_malformed_objects(self):
        """DOS-1: a DXBC header claiming 10 parts at the very end of the buffer, a truncated fatbin wrapper and a
        truncated SPIR-V header must not abort the sweep."""
        tail = b"DXBC" + bytes(16) + struct.pack("<III", 1, 1000, 10)
        data = bytes(1 << 20) + fatbin_fmt.WRAPPER_MAGIC_BYTES + bytes(4) + b"\x03\x02\x23\x07" + bytes(8) + tail
        cub = cubin_fmt.build_cubin({"k": sass_function(3)})
        data = cub + data
        found = list(artifacts.sweep(BytesLayer("x", data), registry().classes))
        self.assertTrue(any(a.kind == "cubin" and a.detail.get("kernels") == ["k"] for a in found))


class HostPagesPartialWalk(unittest.TestCase):
    def test_broken_task_list_gives_partial_results(self):
        """A smeared host image: the task walk stops early; the error is a row and unowned pages are not medium."""
        from unittest import mock
        from keto.hostmem import pageowners

        def owners(km, pages, errors=None):
            errors.append("task list: next pointer 0xffff888000000000 not present")
            return {}

        with mock.patch("keto.hostmem.session.kernel_memory", return_value=object()), \
                mock.patch.object(pageowners, "owners", owners), \
                mock.patch.object(pageowners, "kernel_image_range", return_value=None), \
                mock.patch.object(pageowners, "classify", return_value="kernel"):
            rows = run("nvidia.malware.hostpages")
        self.assertIn("not present", rows[0]["Finding"])
        self.assertEqual(rows[0]["Severity"], "info")
        self.assertEqual(len(rows), 1 + 3)  # three host pages are GPU-mapped in the ground truth
        self.assertEqual({r["Severity"] for r in rows[1:]}, {"low"})


class Options(unittest.TestCase):
    """CLI-2: numeric options are validated instead of raising ZeroDivisionError and friends."""

    def test_bad_numbers(self):
        for name, opts in (("nvidia.physmap", {"granularity": 0}), ("nvidia.physmap", {"granularity": 100}),
                           ("nvidia.aeskeys", {"align": 0}), ("nvidia.residual", {"min_size": 0}),
                           ("nvidia.ptwalk", {"limit": 0}), ("nvidia.strings", {"limit": 0}),
                           ("nvidia.timeslices", {"factor": 0}), ("nvidia.pbscan", {"window": 0}),
                           ("nvidia.malware.fillscan", {"min_size": 0}), ("nvidia.malware.miner", {"strings_limit": 0}),
                           ("nvidia.varegexscan", {"pattern": "("})):
            with self.assertRaises(RequirementError, msg=name):
                run(name, **opts)


class AesSpeed(unittest.TestCase):
    """PERF-1: zero-filled memory is rejected before any per-offset Python check, keys are still all found."""

    def test_keys_found_in_zero_heavy_data(self):
        rnd = random.Random(11)
        buf = bytearray(1 << 20)
        want = []
        for i, ks in enumerate((16, 24, 32, 16, 24, 32)):
            key = bytes(rnd.getrandbits(8) for _ in range(ks))
            s = aes.expand_key(key)
            order = "bytes"
            if i >= 3:
                s, order = b"".join(s[j:j + 4][::-1] for j in range(0, len(s), 4)), "u32-le"
            pos = 0x10000 * (i + 1) + 4 * i  # 4-byte aligned, not 16
            buf[pos:pos + len(s)] = s
            want.append((pos, ks * 8, order, key))
        self.assertEqual(sorted(aes.find_key_schedules(bytes(buf))), sorted(want))

    def test_zero_data_is_fast(self):
        zeros = bytes(16 << 20)
        t = time.time()
        for off in range(0, len(zeros), 4 << 20):
            self.assertEqual(list(aes.find_key_schedules(zeros[off:off + (4 << 20) + 256], off)), [])
        # 0.5 s/MiB before the fix; ~0.01 s/MiB after (generous bound for loaded test machines)
        self.assertLess((time.time() - t) / 16, 0.1)

    def test_ground_truth_keys(self):
        rows = run("nvidia.aeskeys", reveal=True)
        self.assertEqual(sorted((int(r["Offset"]), r["Bits"], r["ByteOrder"], r["Key"]) for r in rows),
                         sorted((k["pa"], k["bits"], k["order"], k["key"]) for k in TRUTH["aes"]))


if __name__ == "__main__":
    unittest.main()
