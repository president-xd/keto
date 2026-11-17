"""Unit tests for decoders/encoders and file formats (no image needed)."""

import os
import random
import struct
import tempfile
import unittest

from keto.formats import aes, fatbin, imaging, lz4, ptx, vbios
from keto.formats.container import Container, ContainerWriter, open_lime, write_lime
from keto.formats.cubin import build_cubin, parse_cubin, sm_from_flags
from keto.framework.layers import BytesLayer, SegmentedLayer
from keto.framework.profiles import registry
from keto.framework.scanners import AnchoredScanner, BytesScanner, RegexScanner, scan, scan_aligned_u32
from keto.gpu import gmmu, pushbuf, qmd, ramin, runlist, sass

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "jit_sm89_probe.cubin")


class GmmuTests(unittest.TestCase):
    def test_v2_pte_roundtrip(self):
        raw = gmmu.encode_pte("v2", gmmu.VID, 0x12345000, readonly=True, privileged=True, kind=0xFE)
        m = gmmu.decode_pte("v2", raw, 0x1000, 0x1000, 0, "small")
        self.assertEqual((m.pa, m.aperture, m.readonly, m.privileged, m.kind), (0x12345000, gmmu.VID, True, True, 0xFE))

    def test_v2_sysmem_and_peer(self):
        m = gmmu.decode_pte("v2", gmmu.encode_pte("v2", gmmu.SYS_COH, 0x7_8901_2000), 0, 0x1000, 0, "small")
        self.assertEqual((m.aperture, m.pa), (gmmu.SYS_COH, 0x7_8901_2000))
        m = gmmu.decode_pte("v2", gmmu.encode_pte("v2", gmmu.PEER, 0x4000, peer_id=5), 0, 0x1000, 0, "small")
        self.assertEqual((m.aperture, m.peer_id, m.pa), (gmmu.PEER, 5, 0x4000))

    def test_v2_bit_positions_match_dev_mmu_h(self):
        # NV_MMU_VER2_PTE: VALID 0, APERTURE 2:1, VOL 3, ENCRYPTED 4, PRIVILEGE 5, READ_ONLY 6, ATOMIC_DISABLE 7,
        # ADDRESS_VID (35-3):8, KIND 63:56
        raw = gmmu.encode_pte("v2", gmmu.VID, 0x1000, volatile=True, encrypted=True, atomic_disable=True)
        self.assertEqual(raw & 0xFF, 0b10011001)
        self.assertEqual((raw >> 8) & ((1 << 25) - 1), 1)

    def test_v3_pcf(self):
        raw = gmmu.encode_pte("v3", gmmu.VID, 0xABC000, readonly=True, privileged=True, kind=6)
        self.assertEqual((raw >> 3) & 0x1F, 0b00110)  # PCF PRIVILEGE_RO_ATOMIC_CACHED_ACE = 6
        m = gmmu.decode_pte("v3", raw, 0, 0x1000, 0, "small")
        self.assertEqual((m.pa, m.readonly, m.privileged, m.kind), (0xABC000, True, True, 6))

    def test_dual_pde(self):
        for fmt in ("v2", "v3"):
            lo, hi = gmmu.encode_dual_pde(fmt, big=(gmmu.VID, 0x123400), small=(gmmu.SYS_COH, 0x5_6789_A000))
            big, small = gmmu.decode_dual_pde(fmt, lo, hi)
            self.assertEqual(big, (gmmu.VID, 0x123400))
            self.assertEqual(small, (gmmu.SYS_COH, 0x5_6789_A000))

    def test_walk_and_translate(self):
        from keto.testing.synth import AddressSpaceBuilder, Image
        img = Image(0x400000)
        b = AddressSpaceBuilder(img, "v2", 0x100000, 0x200000)
        b.map(0x1_2340_0000, 0x300000, 0x2000)
        b.map(0x2_0000_0000, 0x310000, 0x10000, page=0x10000, readonly=True)
        img.put(0x300010, b"hello-gpu")
        layer = BytesLayer("vram", bytes(img.buf))
        w = gmmu.GmmuWalker({gmmu.VID: layer}, b.pdb, "v2", vram_size=len(img.buf))
        gl = gmmu.GmmuLayer("as", w)
        self.assertEqual(len(w.mappings()), 3)
        self.assertEqual(gl.read(0x1_2340_0010, 9), b"hello-gpu")
        self.assertEqual(gl.translate(0x2_0000_8000)[1], 0x318000)
        self.assertTrue(gl.translate(0x2_0000_8000)[0].readonly)
        self.assertIsNone(gl.translate(0x3_0000_0000))


class StructureTests(unittest.TestCase):
    def setUp(self):
        self.prof = registry().get("ada")

    def test_instance_block_roundtrip(self):
        """Encode then parse an instance block with every generation's RAMIN/RAMFC layout."""
        for gen in ("kepler", "maxwell", "pascal", "volta", "turing", "ampere", "ada", "hopper", "blackwell"):
            with self.subTest(gen=gen):
                prof = registry().get(gen)
                fc, ri = prof.ramfc, prof.ramin
                raw = ramin.encode_instance_block(prof, pdb=0x100000, gp_base_va=0x2_0000_0000, gp_limit2=5,
                                                  userd_addr=0x30200, gp_get=1, gp_put=2, privileged=True, chid=7,
                                                  subcontexts=[(3, gmmu.VID, 0x180000)])
                self.assertEqual(struct.unpack_from("<I", raw, fc["signature"])[0] & 0xFFFF, 0xFACE)
                ib = ramin.parse_instance_block(BytesLayer("x", raw), 0, prof, 1 << 30)
                self.assertTrue(ib.valid)
                self.assertEqual((ib.pdb, ib.gp_base_va, ib.gp_entries), (0x100000, 0x2_0000_0000, 32))
                # Kepler..Turing keep USERD in RAMFC; from Ampere it comes from the runlist entry
                self.assertEqual(ib.userd_addr or 0, 0x30200 if "userd_lo" in fc else 0)
                if fc.get("hce_ctrl") is not None:
                    self.assertTrue(ib.privileged)
                self.assertEqual(ib.chid_hint, 7 if fc.get("chid") else None)
                want_sc = [(3, 0x180000)] if ri.get("sc_count") else []
                self.assertEqual([(s.veid, s.pdb) for s in ib.subcontexts], want_sc)

    def test_runlist(self):
        data = bytearray(0x2000)
        rl = runlist.encode_tsg(9, 2, scale=4, timeout=200) + runlist.encode_channel(1, 0x21000, 0x30000) + \
            runlist.encode_channel(2, 0x22000, 0x30200)
        data[0x1000:0x1000 + len(rl)] = rl
        rls = runlist.scan_runlists(BytesLayer("v", bytes(data)), 1 << 30)
        self.assertEqual(len(rls), 1)
        g = rls[0].groups[0]
        self.assertEqual((g.header.tsgid, g.header.timeslice_ticks, [c.chid for c in g.channels],
                          [c.inst_addr for c in g.channels]), (9, 200 << 4, [1, 2], [0x21000, 0x22000]))

    def test_pushbuffer_decode(self):
        db = registry().classes
        pb = pushbuf.encode_methods(1, 0, [0xC9C0]) + pushbuf.encode_methods(1, 0x2B4, [0x2000200]) + \
            pushbuf.encode_methods(2, 0, [0xC7B5]) + pushbuf.encode_methods(2, 0x400, [0, 0x1000, 0, 0x2000, 64, 64, 64, 1]) \
            + pushbuf.encode_methods(2, 0x300, [0x182]) + pushbuf.encode_methods(0, 0x20, [5], op="IMMD")
        methods, events, _ = pushbuf.interpret(pb, 0, db)
        kinds = [e.kind for e in events]
        self.assertEqual(kinds, ["bind", "launch", "bind", "copy", "interrupt"])
        self.assertEqual(events[1].details["qmd_va"], 0x2000200 << 8)
        self.assertEqual((events[3].details["src"], events[3].details["dst"], events[3].details["bytes"]),
                         (0x1000, 0x2000, 64))

    def test_gp_entry(self):
        e = pushbuf.decode_gpfifo(pushbuf.encode_gp_entry(0x12_3456_7890, 77, sync=True))[0]
        self.assertEqual((e.va, e.length, e.sync), (0x12_3456_7890, 77, "WAIT"))

    def test_qmd(self):
        raw = qmd.make_launch(0x3_0000_0100, grid=(7, 2, 1), block=(128, 2, 1), cbufs=[(0, 0x4_0000_0000, 0x100)])
        q = qmd.decode(raw)
        self.assertTrue(q.plausible())
        self.assertEqual((q.program_address, q.grid, q.block), (0x3_0000_0100, (7, 2, 1), (128, 2, 1)))
        self.assertEqual(q.constant_buffers(), [(0, 0x4_0000_0000, 0x100)])
        self.assertEqual(raw[72], 0x30)  # QMD_MAJOR_VERSION 3 / QMD_VERSION 0 live in byte 72


class FileFormatTests(unittest.TestCase):
    def test_lz4_roundtrip(self):
        rnd = random.Random(1)
        for data in (b"", b"a", b"abc" * 1000, bytes(rnd.getrandbits(8) for _ in range(5000)),
                     b"x" * 20 + bytes(range(256)) * 20):
            self.assertEqual(lz4.decompress(lz4.compress(data)), data)

    def test_lz4_reference_vector(self):
        # literal "abcd" + match(offset 4, length 8) + final literals "efgh"
        block = bytes([0x44]) + b"abcd" + b"\x04\x00" + bytes([0x40]) + b"efgh"
        self.assertEqual(lz4.decompress(block), b"abcd" + b"abcdabcd" + b"efgh")

    def test_real_cubin(self):
        c = parse_cubin(open(FIXTURE, "rb").read())
        self.assertEqual(c.sm, 89)
        self.assertEqual(c.toolkit_version, "13.1")
        self.assertEqual(c.virtual_sm, 52)
        k = c.kernels[0]
        self.assertEqual((k.name, k.regcount, k.attributes["exit_offsets"]), ("probe_kernel", 8, [0x60]))
        self.assertEqual(k.params, [{"ordinal": 0, "offset": 0, "size": 8}])
        self.assertTrue(any("ptxas" in s for s in c.tool_strings))
        self.assertTrue(sass.looks_like_code(k.text))
        self.assertEqual(sass.find_epilogues(k.text), [0x60])

    def test_sm_flags(self):
        self.assertEqual(sm_from_flags(8, 0x06005904), 89)
        self.assertEqual(sm_from_flags(7, 0x00560556), 86)

    def test_built_cubin_and_fatbin(self):
        from keto.testing.synth import sass_function
        cub = build_cubin({"k1": sass_function(1), "k2": sass_function(2)})
        c = parse_cubin(cub)
        self.assertEqual(sorted(c.kernel_names()), ["k1", "k2"])
        fb = fatbin.parse_fatbin(fatbin.build_fatbin([(fatbin.KIND_ELF, 89, cub, True),
                                                       (fatbin.KIND_PTX, 89, b".version 8.5\n.target sm_89\n", False)]))
        self.assertEqual([e.kind_name for e in fb.entries], ["ELF", "PTX"])
        self.assertTrue(fb.entries[0].compressed)
        self.assertEqual(fb.entries[0].data, cub)

    def test_fatbin_entry_codecs(self):
        """LZ4 (0x2000), deflate (0x1000) and zstd (0x8000) entries all decompress to the original cubin."""
        from keto.formats import compression
        from keto.testing.synth import sass_function
        cub = build_cubin({"k_codec": sass_function(3)})
        for codec, flag in (("lz4", 0x2000), ("deflate", 0x1000), ("zstd", 0x8000)):
            with self.subTest(codec=codec):
                if codec == "zstd" and not compression.zstd_available():
                    self.skipTest("no zstd back-end on this Python")
                e = fatbin.parse_fatbin(fatbin.build_fatbin([(fatbin.KIND_ELF, 89, cub, codec)])).entries[0]
                self.assertEqual((e.compression, e.flags & flag, e.data, e.error), (codec, flag, cub, None))
        bad = bytearray(fatbin.build_fatbin([(fatbin.KIND_ELF, 89, cub, "deflate")]))
        bad[16 + fatbin.ENTRY_SIZE:16 + fatbin.ENTRY_SIZE + 8] = b"\xff" * 8  # corrupt the stream
        e = fatbin.parse_fatbin(bytes(bad)).entries[0]
        self.assertIsNone(e.data)
        self.assertIn("deflate", e.error)

    def test_ptx(self):
        text = b"// Generated by NVIDIA NVVM Compiler\n.version 8.5\n.target sm_89\n.address_size 64\n" \
               b".extern .func (.param .b32 r) vprintf(.param .b64 a);\n.visible .entry foo(\n.param .u64 p)\n{\nret;\n}\n"
        buf = b"\x00" * 10 + text + b"\x00\xff"
        span = ptx.carve(buf, buf.index(b".version"))
        m = ptx.parse(buf[span[0]:span[1]])
        self.assertEqual((m.version, m.target, m.entries, m.externs), ("8.5", "sm_89", ["foo"], ["vprintf"]))

    def test_aes_known_answer(self):
        sched = aes.expand_key(bytes(range(16)))
        self.assertEqual(sched[-16:].hex(), "13111d7fe3944a17f307a78b4d2b30c5")  # FIPS-197 appendix C.1
        data = os.urandom(100) + sched + os.urandom(100)
        hits = list(aes.find_key_schedules(data, 0, align=4, skip_low_entropy=False))
        self.assertIn((100, 128, "bytes", bytes(range(16))), hits)

    def test_vbios(self):
        rom = vbios.build_rom(version=(0x95, 0x07, 0x2D, 0x00, 0x5F))
        img = vbios.parse_chain(rom, 0)
        self.assertEqual((img[0].vendor, img[0].device, img[0].checksum_ok), (0x10DE, 0x28A1, True))
        bit = vbios.parse_bit(rom, rom.find(vbios.BIT_SIG))
        self.assertEqual(vbios.vbios_version(rom, bit, 0), "95.07.2D.00.5F")

    def test_blocklinear_roundtrip(self):
        rnd = random.Random(3)
        for w, h, bh in ((64, 16, 1), (128, 64, 2), (100 * 4, 37, 4)):
            w -= w % 16
            lin = bytes(rnd.getrandbits(8) for _ in range(w * h))
            self.assertEqual(imaging.deswizzle(imaging.swizzle(lin, w, h, bh), w, h, bh), lin)

    def test_container_and_lime(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.keto")
            w = ContainerWriter(p, {"device": {"name": "test"}})
            w.add_segment("vram", 0x1000, b"A" * 100)
            w.add_segment("sysmem", 0x9000, [b"B" * 10, b"C" * 10])
            w.close()
            c = Container(p)
            self.assertEqual(c.metadata["device"]["name"], "test")
            layers = c.layers()
            self.assertEqual(layers["vram"].read(0x1000 + 98, 2), b"AA")
            self.assertEqual(layers["sysmem"].read(0x9000 + 8, 4), b"BBCC")
            self.assertTrue(all(r["ok"] for r in c.verify()))
            c.file_layer().close()
            lp = os.path.join(d, "h.lime")
            write_lime(lp, [(0x1000, b"x" * 16), (0x10000, b"y" * 16)])
            lay = open_lime("h", lp)
            self.assertEqual(lay.read(0x10000, 3), b"yyy")
            self.assertFalse(lay.is_valid(0x2000))
            lay.close()


class ScannerTests(unittest.TestCase):
    def test_chunk_boundaries(self):
        data = bytearray(200000)
        for pos in (0, 65530, 65536, 131070, 199990):
            data[pos:pos + 6] = b"NEEDLE"
        layer = BytesLayer("t", bytes(data))
        expect = [0, 65530, 65536, 131070, 199990]
        self.assertEqual([o for o, _ in scan(layer, BytesScanner(b"NEEDLE"), chunk_size=65536)], expect)
        self.assertEqual([o for o, _ in scan(layer, RegexScanner(rb"NEE.LE", max_length=8), chunk_size=65536)], expect)
        got = sorted(o for o, _ in scan(layer, AnchoredScanner([b"needle"], ignore_case=True), chunk_size=65536))
        self.assertEqual(got, expect)

    def test_sparse_layer_and_aligned_scan(self):
        base = BytesLayer("b", b"\x00" * 0x3000)
        data = bytearray(0x3000)
        struct.pack_into("<I", data, 0x2010, 0xFACE)
        seg = SegmentedLayer("s", [(0x10000, 0x3000, BytesLayer("d", bytes(data)), 0)])
        self.assertEqual(list(scan_aligned_u32(seg, 0x10, 0x1000, lambda v: v == 0xFACE)), [(0x12000, 0xFACE)])
        self.assertFalse(seg.is_valid(0x13000))
        self.assertEqual(seg.read(0x12ffe, 4, pad=True), b"\x00\x00\x00\x00")
        del base


class ProfileTests(unittest.TestCase):
    def test_profiles_valid(self):
        reg = registry()
        self.assertFalse(reg.errors)
        self.assertEqual(reg.by_chipset(0x197).name, "ada")
        self.assertEqual(reg.by_nvml_arch(9).name, "hopper")
        self.assertEqual(reg.by_compute_capability("8.6").name, "ampere")
        self.assertEqual(reg.by_device_name("NVIDIA GeForce RTX 4050 Laptop GPU").name, "ada")
        self.assertEqual(reg.get("blackwell").mmu_format, "v3")
        self.assertEqual(reg.classes.class_name(0xC6C0), "AMPERE_COMPUTE_A")
        self.assertEqual(reg.classes.method_name("copy", 0x300), "LAUNCH_DMA")


if __name__ == "__main__":
    unittest.main()
