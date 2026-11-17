"""The same ground-truth scenario, built with each NVIDIA generation's structures, Kepler..Blackwell.

Every image uses that generation's page-table format (VER1 / VER2 / VER3), instance-block and RAMFC
layout, runlist entry format, engine class ids, host semaphore methods and QMD version, so each test
checks that discovery, command decoding and the analysis plugins work on that generation's layouts.
"""

import os
import shutil
import tempfile
import unittest

from keto.framework.context import Context
from keto.framework.plugin import PLUGINS, load_plugins
from keto.testing.synth import GENERATIONS, build_all


def col(grid, name):
    i = grid.column_index(name)
    return [v[i] for _, v in grid.rows]


class _Generation:
    GEN = None

    @classmethod
    def setUpClass(cls):
        load_plugins()
        cls.tmp = tempfile.mkdtemp(prefix="keto-gen-%s-" % cls.GEN)
        cls.truth = build_all(cls.tmp, gen=cls.GEN)["truth"]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def ctx(self):
        return Context(image=os.path.join(self.tmp, "synthetic.keto"),
                       host_image=os.path.join(self.tmp, "synthetic_host.lime"),
                       output_dir=os.path.join(self.tmp, "out"))

    def run_plugin(self, name, **opts):
        with self.ctx() as c:
            g = PLUGINS[name](c, opts).run()
            g.rows  # materialise while the image is open
            return g

    def test_profile_detected_from_chipset(self):
        with self.ctx() as c:
            self.assertEqual(c.profile.name, self.GEN)

    def test_profile_detected_from_structures_alone(self):
        """A bare raw dump (no metadata sidecar, banners wiped) is still recognised from the class ids bound
        with SET_OBJECT, the QMD version bytes and the instance-block layout."""
        with open(os.path.join(self.tmp, "synthetic_vram.raw"), "rb") as fh:
            data = bytearray(fh.read())
        data[0x100:0x600] = bytes(0x500)
        bare = os.path.join(self.tmp, "bare.raw")
        with open(bare, "wb") as fh:
            fh.write(data)
        with Context(image=bare) as c:
            self.assertEqual(c.profile.name, self.GEN, c.profile_reason)
            self.assertIn("structures in the image", c.profile_reason)

    def test_instance_blocks_and_privilege(self):
        g = self.run_plugin("nvidia.chanscan")
        insts = sorted(int(x) for x in col(g, "InstanceBlock"))
        self.assertEqual(insts, sorted(v["inst"] for v in self.truth["channels"].values()))
        chids = dict(zip((int(x) for x in col(g, "InstanceBlock")), col(g, "ChID")))
        for ch in self.truth["channels"].values():
            if isinstance(chids[ch["inst"]], int):  # GB2xx RAMFC holds no CHID
                self.assertEqual(chids[ch["inst"]], ch["chid"])

    def test_address_spaces(self):
        g = self.run_plugin("nvidia.addrspaces")
        self.assertEqual(sorted(int(x) for x in col(g, "PDB")), sorted(self.truth["address_spaces"].values()))
        self.assertEqual(set(col(g, "MMU")), {self.truth["mmu"].upper()})

    def test_page_sizes(self):
        g = self.run_plugin("nvidia.memmap", aspace="as_%x" % self.truth["address_spaces"]["AS1"])
        sizes = {int(va): int(sz) for va, sz in zip(col(g, "VA"), col(g, "Size"))}
        if self.truth["huge_page"]:
            self.assertEqual(sizes[self.truth["huge_page"]["va"]], 0x200000)
        else:  # VER1: the 2 MiB buffer is mapped with big pages
            self.assertEqual(sizes[0x4_0000_0000], self.truth["big_page"])

    def test_runlist(self):
        g = self.run_plugin("nvidia.malware.chanxview")
        inrl = dict(zip((int(x) for x in col(g, "InstanceBlock")), col(g, "Runlist")))
        self.assertFalse(inrl[self.truth["channels"]["C"]["inst"]])
        self.assertTrue(inrl[self.truth["channels"]["A"]["inst"]])
        rl = self.run_plugin("nvidia.runlist")
        self.assertEqual(sorted(x for x in col(rl, "ChID") if isinstance(x, int)), [0, 1, 2])

    def test_launches_resolve_program(self):
        g = self.run_plugin("nvidia.launches")
        self.assertIn("vector_add", col(g, "Kernel"))
        self.assertEqual(set(col(g, "QMD")), {self.truth["qmd_version"].upper()})
        s = self.run_plugin("nvidia.malware.suspiciouslaunch")
        self.assertEqual([int(x) for x in col(s, "Program VA")], [self.truth["injected_code"]["va"]])

    def test_copies(self):
        g = self.run_plugin("nvidia.copies")
        self.assertEqual(sorted(col(g, "Bytes")), sorted(c["bytes"] for c in self.truth["copies"]))

    def test_qmdscan_version_and_stray(self):
        q = self.run_plugin("nvidia.qmdscan")
        self.assertEqual(set(col(q, "QMD")), {self.truth["qmd_version"].upper()})
        refd = dict(zip((int(x) for x in col(q, "PA")), col(q, "Referenced")))
        self.assertFalse(refd[self.truth["stray_qmd"]])
        self.assertTrue(refd[0x420000])

    def test_gpu_timeline(self):
        g = self.run_plugin("nvidia.gputimeline")
        got = {int(x) for x in col(g, "GPU time (ns)") if isinstance(x, int)}
        self.assertEqual(got, {e["ns"] for e in self.truth["timeline"]})

    def test_malfind(self):
        mf = self.run_plugin("nvidia.malware.malfind")
        self.assertEqual([int(x) for x in col(mf, "VA")], [self.truth["injected_code"]["va"]])


for _gen in GENERATIONS:
    _name = "Test%sGeneration" % _gen.capitalize()
    globals()[_name] = type(_name, (_Generation, unittest.TestCase), {"GEN": _gen})
del _gen, _name

if __name__ == "__main__":
    unittest.main()
