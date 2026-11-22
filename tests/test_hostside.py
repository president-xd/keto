"""Host-side GPU artefacts: process memory, provenance, baselines, real driver data."""

import glob
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from keto.formats.cubin import build_cubin
from keto.framework.context import Context
from keto.framework.layers import BytesLayer
from keto.framework.plugin import PLUGINS, load_plugins
from keto.framework.profiles import registry
from keto.gpu import artifacts, qmd, sass
from keto.indicators import driver_kernels
from keto.plugins.nvidia import hostside
from keto.testing.synth import PTX_MINER, sass_function

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = os.path.join(HERE, "fixtures", "real")


def _payload_blob():
    """A host-memory image holding a driver-like module, a miner module, a loaded copy and PTX."""
    benign = build_cubin({"memcpy128": sass_function(11), "cilp_traphandler_save": sass_function(12)})
    evil_text = sass_function(13, 30)
    evil = build_cubin({"ethash_search": evil_text})
    copy = bytearray(evil_text)
    struct.pack_into("<Q", copy, 0x48, struct.unpack_from("<Q", copy, 0x48)[0] ^ 0xABCD000000)  # relocation patch
    blob = bytearray(0x40000)
    blob[0x1000:0x1000 + len(benign)] = benign
    blob[0x8000:0x8000 + len(evil)] = evil
    blob[0x10000:0x10000 + len(copy)] = copy
    ptx = PTX_MINER.encode()
    blob[0x20000:0x20000 + len(ptx)] = ptx
    return bytes(blob)


class DriverKernelTests(unittest.TestCase):
    def test_allowlist(self):
        for n in ("memcpy128", "memcpyDtoD2D_aligned", "cilp_traphandler_save", "cnpLaunchDevice",
                  "syscall_no_stack_switch_trampoline___assertfail", "_Z22cnpLaunchQueueAlloc_idmPm$67",
                  "__cuda_sm70_votesync_any", "membar_war_bug2022401", "deviceGraphScheduler"):
            self.assertTrue(driver_kernels.is_driver_internal(n), n)
        for n in ("ethash_search", "kawpow_hash", "decrypt_payload", "main_kernel"):
            self.assertFalse(driver_kernels.is_driver_internal(n), n)

    def test_skeleton_hash_tolerates_relocation(self):
        code = bytearray(sass_function(5, 20))
        h1 = sass.skeleton_hash(bytes(code))
        struct.pack_into("<Q", code, 0x40, struct.unpack_from("<Q", code, 0x40)[0] ^ 0xFFFF0000)  # immediate field
        self.assertEqual(sass.skeleton_hash(bytes(code)), h1)
        struct.pack_into("<Q", code, 0x40, struct.unpack_from("<Q", code, 0x40)[0] ^ 0x1)        # opcode change
        self.assertNotEqual(sass.skeleton_hash(bytes(code)), h1)


class RealDriverDataTests(unittest.TestCase):
    def test_real_qmds_from_driver_592(self):
        """QMDs written by the real NVIDIA driver (RTX 4050, 592.82) decode exactly as recorded."""
        blob = open(os.path.join(REAL, "qmd_v03_ada_drv592.bin"), "rb").read()
        meta = json.load(open(os.path.join(REAL, "qmd_v03_ada_drv592.json")))
        self.assertEqual(len(blob), meta["count"] * qmd.QMD_SIZE)
        for i, exp in enumerate(meta["expected"]):
            q = qmd.decode(blob[i * 256:(i + 1) * 256])
            self.assertEqual(q.version, "v03_00")  # detected from the descriptor
            self.assertTrue(q.plausible())
            self.assertEqual((q.program_address, list(q.grid), list(q.block), q.registers),
                             (exp["program_address"], exp["grid"], exp["block"], exp["registers"]))
        found = list(artifacts.sweep(BytesLayer("x", blob + b"\x00" * 256), None, ("qmd",)))
        self.assertEqual(len(found), meta["count"])

    def test_qmd_signature(self):
        self.assertEqual(qmd.signature("v03_00"), (72, 0xFF, 0x30))
        self.assertEqual(qmd.signature("v05_00"), (56, 0xFF0000, 0x50 << 16))

    def test_real_nvidia_fatbins_if_driver_installed(self):
        win = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "DriverStore", "FileRepository")
        libs = [p for p in glob.glob("/usr/lib/wsl/lib/libnvdxdlkernels.so") + glob.glob("/usr/lib/x86_64-linux-gnu/libcublas*.so*")
                + glob.glob("/usr/local/cuda/lib64/libcublas*.so*")
                + glob.glob(os.path.join(win, "nv*", "nvdirectsr.dll")) + glob.glob(os.path.join(win, "nv*", "nvoptix.dll"))
                if os.path.isfile(p)]
        if not libs:
            self.skipTest("no NVIDIA library with embedded fatbins on this machine")
        with open(libs[0], "rb") as fh:
            data = fh.read(48 << 20)
        found = list(artifacts.sweep(BytesLayer("lib", data), None, ("fatbin",), None))
        self.assertGreater(len(found), 0)
        undecodable = sum(1 for a in found if "(undecodable)" in a.summary)
        self.assertEqual(undecodable, 0, "real NVIDIA fatbin entries failed to decode")


OPENCL_DECRYPTOR = (b"// packer stage\n__kernel void f(__global const uchar *a, __global const uchar *b,\n"
                    b"                __global uchar *c, const uint d) {\n"
                    b"    size_t i = get_global_id(0);\n    c[i] = a[i] ^ b[i % d];\n}\n")
OPENCL_BENIGN = (b"__kernel void saxpy(__global float *y, __global const float *x, float a) {\n"
                 b"    size_t i = get_global_id(0);\n    y[i] = a * x[i] + y[i];\n}\n")


class NonCudaCodeTests(unittest.TestCase):
    """OpenCL C source, SPIR-V and DXBC (non-CUDA GPU code used by in-the-wild loaders)."""

    def setUp(self):
        from keto.formats import gpucode
        blob = bytearray(0x20000)
        blob[0x1000:0x1000 + len(OPENCL_DECRYPTOR)] = OPENCL_DECRYPTOR
        blob[0x3000:0x3000 + len(OPENCL_BENIGN)] = OPENCL_BENIGN
        sp = gpucode.build_spirv_kernel("f", xor_mod=True)
        blob[0x6000:0x6000 + len(sp)] = sp
        dx = gpucode.build_dxbc(program_type=5)
        blob[0x9000:0x9000 + len(dx)] = dx
        ptx = (b".version 8.5\n.target sm_89\n.address_size 64\n.visible .entry f(\n.param .u64 f_param_0\n)\n{\n"
               b"\trem.u32 %r3, %r1, %r2;\n\txor.b32 %r4, %r5, %r6;\n\tret;\n}\n")
        blob[0xC000:0xC000 + len(ptx)] = ptx
        self.layer = BytesLayer("proc", bytes(blob), base=0x7F0000000000)

    def test_sweep_finds_every_kind(self):
        found = list(artifacts.sweep(self.layer, registry().classes, ("opencl", "spirv", "dxbc", "ptx")))
        by = {}
        for a in found:
            by.setdefault(a.kind, []).append(a)
        ocl = {tuple(a.detail["entries"]): a for a in by["opencl"]}
        self.assertTrue(ocl[("f",)].detail["decryptor"])
        self.assertFalse(ocl[("saxpy",)].detail["decryptor"])
        sp = by["spirv"][0]
        self.assertEqual((sp.detail["entries"], sp.detail["opencl"], sp.detail["decryptor"]), (["f"], True, True))
        self.assertEqual(by["dxbc"][0].detail["program_type"], "compute")
        self.assertTrue(by["ptx"][0].detail["decryptor"])

    def test_decryptor_is_high_severity(self):
        for a in artifacts.sweep(self.layer, registry().classes, ("opencl", "spirv")):
            why = hostside.assess(a, "[heap]", "rw-p", hostside.provenance(a, None))
            want = "high" if a.detail.get("decryptor") else "medium"
            self.assertEqual(hostside.severity(a, why), want, (a, why))

    def test_dxbc_parser_rejects_garbage(self):
        from keto.formats import gpucode
        self.assertIsNone(gpucode.parse_dxbc(b"DXBC" + b"\xff" * 60))
        self.assertIsNone(gpucode.parse_spirv(struct.pack("<5I", gpucode.SPIRV_MAGIC, 0x00090000, 0, 5, 0)))


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.db = registry().classes
        self.layer = BytesLayer("proc", _payload_blob(), base=0x7F0000000000)

    def _assess(self, baseline=None):
        out = []
        for a in artifacts.sweep(self.layer, self.db):
            prov = hostside.provenance(a, baseline)
            why = hostside.assess(a, "[heap]", "rw-p", prov)
            out.append((a, prov, why, hostside.severity(a, why)))
        return out

    def test_name_attribution_and_flags(self):
        res = self._assess()
        by_kind = {}
        for a, prov, why, sev in res:
            by_kind.setdefault(a.kind, []).append((a, prov, why, sev))
        benign = [r for r in by_kind["cubin"] if "memcpy128" in r[0].detail["kernels"]][0]
        self.assertEqual(benign[1], "NVIDIA driver-internal (name match only)")
        self.assertEqual(benign[2], "")
        evil = [r for r in by_kind["cubin"] if "ethash_search" in r[0].detail["kernels"]][0]
        self.assertEqual(evil[3], "high")
        copy = [r for r in by_kind["sass"] if r[0].offset >= 0x7F0000010000][0]
        self.assertIn("loaded copy of kernel ethash_search", copy[0].summary)
        self.assertEqual(copy[3], "high")
        self.assertTrue(any(r[3] == "high" for r in by_kind["ptx"]))

    def test_baseline_suppresses_known_code(self):
        clean = BytesLayer("clean", build_cubin({"my_app_kernel": sass_function(21)}) + b"\x00" * 64)
        sink = {}
        for a in artifacts.sweep(clean, self.db):
            sink.update(a.detail.get("kernel_hashes") or {})
        base = driver_kernels.Baseline(sink)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "b.json")
            base.save(p)
            base = driver_kernels.Baseline.load(p)
        layer = BytesLayer("x", build_cubin({"my_app_kernel": sass_function(21)}) + b"\x00" * 64)
        a = [x for x in artifacts.sweep(layer, self.db) if x.kind == "cubin"][0]
        self.assertEqual(hostside.provenance(a, base), "known-good (baseline hash)")
        self.assertEqual(hostside.assess(a, "[heap]", "rw-p", "known-good (baseline hash)"), "")


@unittest.skipUnless((sys.platform.startswith("linux") and os.path.exists("/proc/self/mem")) or os.name == "nt",
                     "Linux /proc or Windows ReadProcessMemory needed")
class ProcessAcquisitionTests(unittest.TestCase):
    def test_capture_child_process_and_find_payload(self):
        """A child holds a GPU payload in its heap; the parent (allowed by ptrace_scope=1) captures it."""
        with tempfile.TemporaryDirectory() as d:
            payload = os.path.join(d, "payload.bin")
            with open(payload, "wb") as fh:
                fh.write(_payload_blob())
            child = subprocess.Popen([sys.executable, "-c",
                                      "import sys,time; b=bytearray(open(sys.argv[1],'rb').read()); "
                                      "import os; print('ready', os.getpid(), flush=True); time.sleep(60)", payload],
                                     stdout=subprocess.PIPE)
            try:
                word, pid = child.stdout.readline().split()
                self.assertEqual(word, b"ready")
                pid = int(pid)  # a venv python.exe on Windows is a launcher: the payload lives in its child
                out = os.path.join(d, "child.keto")
                from keto.cli import main
                rc = main(["-q", "--output-file", os.path.join(d, "log.txt"), "acquire", "--method", "process",
                           "--pid", str(pid), "--out", out])
                self.assertEqual(rc, 0)
                load_plugins()
                with Context(image=out) as ctx:
                    self.assertEqual(ctx.metadata["process"]["pid"], pid)
                    rows = PLUGINS["nvidia.artifactscan"](ctx, {"suspicious_only": True}).run().as_dicts()
                kernels = " ".join(r["Kernels"] for r in rows)
                self.assertIn("ethash_search", kernels)
                self.assertTrue(all(r["Severity"] in ("high", "medium", "low") for r in rows))
                self.assertNotIn("memcpy128", kernels)  # driver-internal name is not flagged
            finally:
                child.kill()
                child.wait()


if __name__ == "__main__":
    unittest.main()
