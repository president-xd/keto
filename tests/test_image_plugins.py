"""Every memory-image plugin against the synthetic ground-truth image."""

import json
import os
import shutil
import tempfile
import unittest

from keto.cli import main
from keto.framework.context import Context
from keto.framework.plugin import LOAD_ERRORS, PLUGINS, load_plugins
from keto.framework.renderers import RENDERERS, render_to_string
from keto.testing.synth import build_all

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "jit_sm89_probe.cubin")
TMP = None
TRUTH = None


def setUpModule():
    global TMP, TRUTH
    TMP = tempfile.mkdtemp(prefix="keto-test-")
    TRUTH = build_all(TMP, real_cubin=FIXTURE)["truth"]


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def ctx(**kw):
    kw.setdefault("image", os.path.join(TMP, "synthetic.keto"))
    kw.setdefault("host_image", os.path.join(TMP, "synthetic_host.lime"))
    kw.setdefault("output_dir", os.path.join(TMP, "out"))
    return Context(**kw)


def run(name, c=None, **opts):
    return PLUGINS[name](c or ctx(), opts).run()


def col(grid, name):
    i = grid.column_index(name)
    return [v[i] for _, v in grid.rows]


class ImagePluginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        load_plugins()

    def test_no_plugin_load_errors(self):
        self.assertEqual(LOAD_ERRORS, {})

    def test_every_image_plugin_runs_and_renders(self):
        skip = {"yarascan", "nvidia.vayarascan", "nvidia.bugreport", "nvidia.xid"}
        needs = {"regexscan": {"pattern": "SHARED"}, "nvidia.varegexscan": {"pattern": "SHARED"},
                 "hexdump": {"address": 0x20000}}
        for name, cls in sorted(PLUGINS.items()):
            if name in skip or "image" not in cls.SOURCES:
                continue
            with self.subTest(plugin=name):
                grid = cls(ctx(), needs.get(name, {})).run()
                for r in RENDERERS:
                    render_to_string(grid, r)

    def test_profile_detection(self):
        c = ctx()
        self.assertEqual(c.profile.name, "ada")
        raw = Context(image=os.path.join(TMP, "synthetic_vram.raw"))
        self.assertEqual(raw.profile.name, "ada")  # from the .json sidecar
        self.assertIn("chipset", raw.profile_reason)

    def test_chanscan(self):
        g = run("nvidia.chanscan")
        self.assertEqual(sorted(int(x) for x in col(g, "InstanceBlock")),
                         sorted(v["inst"] for v in TRUTH["channels"].values()))
        priv = dict(zip((int(x) for x in col(g, "InstanceBlock")), col(g, "Privileged")))
        self.assertTrue(priv[TRUTH["channels"]["D"]["inst"]])

    def test_runlist_and_hidden_channel(self):
        g = run("nvidia.malware.chanxview")
        inrl = dict(zip((int(x) for x in col(g, "InstanceBlock")), col(g, "Runlist")))
        self.assertFalse(inrl[TRUTH["channels"]["C"]["inst"]])
        self.assertTrue(inrl[TRUTH["channels"]["A"]["inst"]])
        rl = run("nvidia.runlist")
        self.assertEqual(sorted(x for x in col(rl, "ChID") if isinstance(x, int)), [0, 1, 2])

    def test_engine_context(self):
        g = run("nvidia.contexts")
        rows = {int(r["InstanceBlock"]): r for r in g.as_dicts()}
        a = rows[TRUTH["channels"]["A"]["inst"]]
        self.assertEqual((a["Mode"], int(a["EngineCtx"]), a["Resolves to"]),
                         ("virtual", TRUTH["engine_context"]["va"], "vidmem:0x%x" % TRUTH["engine_context"]["pa"]))
        self.assertTrue(bytes(a["SavedState"]).startswith(b"GRCTX"))

    def test_address_spaces(self):
        g = run("nvidia.addrspaces")
        self.assertEqual(sorted(int(x) for x in col(g, "PDB")), sorted(TRUTH["address_spaces"].values()))

    def test_huge_and_sysmem_mappings(self):
        g = run("nvidia.memmap", aspace="as_%x" % TRUTH["address_spaces"]["AS1"])
        sizes = {int(va): int(sz) for va, sz in zip(col(g, "VA"), col(g, "Size"))}
        self.assertEqual(sizes[TRUTH["huge_page"]["va"]], 0x200000)
        s = run("nvidia.sysmemmap")
        self.assertEqual([int(x) for x in col(s, "Host/Peer PA")], [TRUTH["sysmem_mapping"]["host_pa"]])
        self.assertTrue(bytes(col(s, "Preview")[0]).startswith(b"HOST-SYSMEM-PAGE"))

    def test_pending_work(self):
        g = run("nvidia.pending")
        self.assertEqual(len([r for d, r in g.rows if d == 1]), TRUTH["channels"]["A"]["pending"])

    def test_launches_resolve_kernels(self):
        g = run("nvidia.launches")
        kernels = col(g, "Kernel")
        self.assertIn("vector_add", kernels)
        s = run("nvidia.malware.suspiciouslaunch")
        self.assertEqual([int(x) for x in col(s, "Program VA")], [TRUTH["injected_code"]["va"]])

    def test_copies_and_exfil(self):
        g = run("nvidia.copies")
        self.assertEqual(sorted(col(g, "Bytes")), sorted(c["bytes"] for c in TRUTH["copies"]))
        e = run("nvidia.malware.exfil")
        why = " ".join(col(e, "Why"))
        self.assertIn("physical copy to host RAM", why)
        self.assertIn("sysmem-coh window", why)

    def test_code_artifacts(self):
        g = run("nvidia.cubinscan")
        self.assertTrue(set(TRUTH["cubins"]) <= {int(x) for x in col(g, "Offset")})
        self.assertIn("fatbin (lz4)", col(g, "Source"))
        k = run("nvidia.kernels")
        self.assertTrue({"vector_add", "matmul_tiled", "probe_kernel"} <= set(col(k, "Kernel")))
        p = run("nvidia.ptxscan")
        self.assertIn("ethash_search, kawpow_hash", col(p, "Entries"))
        imp = run("nvidia.imports")
        self.assertIn("vprintf", col(imp, "Import"))

    def test_malware_findings(self):
        sf = run("nvidia.malware.sassfind")
        self.assertEqual(sorted(int(x) for x in col(sf, "Start")),
                         sorted([TRUTH["injected_code"]["pa"], TRUTH["orphan_code"]["pa"]]))
        mf = run("nvidia.malware.malfind")
        self.assertEqual([int(x) for x in col(mf, "VA")], [TRUTH["injected_code"]["va"]])
        pt = run("nvidia.malware.ptcheck")
        findings = set(col(pt, "Finding"))
        self.assertTrue({"privileged-in-user", "shared-physical-page", "exposes-page-table"} <= findings)
        mi = run("nvidia.malware.miner")
        self.assertTrue({"ethash", "kawpow"} <= set(col(mi, "Indicator")))
        hc = run("nvidia.malware.hostcode")
        self.assertEqual(col(hc, "Kind").count("executable"), 2)
        self.assertEqual(col(hc, "Kind").count("script"), TRUTH["hostcode"]["scripts"])
        rows = [(int(o), k, i) for o, k, i in zip(col(hc, "Offset"), col(hc, "Kind"), col(hc, "Identification"))]
        sc = [r for r in rows if r[1] == "shellcode"]
        self.assertEqual(len(sc), TRUTH["hostcode"]["shellcode"]["patterns"])
        self.assertTrue(all(TRUTH["hostcode"]["shellcode"]["pa"] <= o < TRUTH["hostcode"]["shellcode"]["pa"] + 64
                            for o, _, _ in sc))
        fs = [r for r in rows if r[1] == "filesystem"]
        self.assertEqual([o for o, _, _ in fs], [TRUTH["hostcode"]["filesystem"]["pa"]])
        self.assertIn("ext4", fs[0][2])
        self.assertIn("vramfs", fs[0][2])
        ar = [r for r in rows if r[1] == "archive"]
        self.assertEqual([o for o, _, _ in ar], [TRUTH["hostcode"]["archive"]["pa"]])
        self.assertIn(TRUTH["hostcode"]["archive"]["first"], ar[0][2])

    def test_secrets_keys_vbios(self):
        s = run("nvidia.secrets")
        kinds = set(col(s, "Kind"))
        self.assertTrue({"pem-private-key", "aws-access-key-id", "jwt", "unix-crypt-hash", "github-token"} <= kinds)
        self.assertTrue(all("*" in v for v in col(s, "Value")))  # redacted by default
        a = run("nvidia.aeskeys", reveal=True)
        self.assertEqual(sorted((int(o), k) for o, k in zip(col(a, "Offset"), col(a, "Key"))),
                         sorted((x["pa"], x["key"]) for x in TRUTH["aes"]))
        v = run("nvidia.vbios")
        self.assertEqual(col(v, "Version"), [TRUTH["vbios"]["version"]])

    def test_surfaces(self):
        g = run("nvidia.surfaces")
        got = {(int(pa), w, h, lay) for pa, w, h, lay in zip(col(g, "PA"), col(g, "Width"), col(g, "Height"),
                                                               col(g, "Layout"))}
        want = {(s["pa"], s["width"], s["height"], s["layout"]) for s in TRUTH["surfaces"]}
        self.assertEqual(got, want)
        alpha = dict(zip((int(pa) for pa in col(g, "PA")), col(g, "Alpha")))
        self.assertEqual(alpha[0x1200000], "0x00")  # XRGB texture (alpha 0x00) is recovered too
        self.assertEqual(alpha[0x1000000], "0xff")
        for f in col(g, "File"):
            with open(f, "rb") as fh:
                self.assertEqual(fh.read(8), b"\x89PNG\r\n\x1a\n")

    def test_stray_structures(self):
        q = run("nvidia.qmdscan")
        refd = dict(zip((int(x) for x in col(q, "PA")), col(q, "Referenced")))
        self.assertFalse(refd[TRUTH["stray_qmd"]])
        pb = run("nvidia.pbscan")
        refd = dict(zip((int(x) for x in col(pb, "Offset")), col(pb, "ReferencedByChannel")))
        self.assertFalse(refd[TRUTH["stray_pushbuffer"]])

    def test_dumpfiles_manifest(self):
        out = os.path.join(TMP, "dump")
        g = run("nvidia.dumpfiles", ctx(output_dir=out))
        with open(os.path.join(out, "manifest.json")) as fh:
            manifest = json.load(fh)
        self.assertEqual(len(manifest), len(g))
        self.assertTrue({"cubin", "ptx", "vbios", "surface"} <= {m["kind"] for m in manifest})

    def test_verify_container(self):
        g = run("verify")
        self.assertTrue(all(col(g, "OK")))


class CliTests(unittest.TestCase):
    def _run(self, *argv):
        path = os.path.join(TMP, "cli_out.txt")
        rc = main(["-q", "--output-file", path] + list(argv))
        with open(path, encoding="utf-8") as fh:
            return rc, fh.read()

    def test_list(self):
        rc, out = self._run("list")
        self.assertEqual(rc, 0)
        self.assertIn("nvidia.chanscan", out)

    def test_plugin_json(self):
        rc, out = self._run("-f", os.path.join(TMP, "synthetic.keto"), "-r", "json", "nvidia.chanscan")
        self.assertEqual(rc, 0)
        self.assertEqual(len(json.loads(out)), 4)

    def test_missing_image_is_clean_error(self):
        rc, _ = self._run("nvidia.chanscan")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
