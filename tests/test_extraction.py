"""Host-side extraction: kernel names referenced by host code, shader caches, GPU environment variables."""

import os
import sqlite3
import tempfile
import unittest

from keto.formats import gpucode, shadercache
from keto.formats.container import ContainerWriter
from keto.formats.cubin import build_cubin
from keto.framework.context import Context
from keto.framework.layers import BytesLayer
from keto.framework.plugin import PLUGINS, load_plugins
from keto.gpu import artifacts
from keto.testing.synth import sass_function


def u16(s):
    return s.encode("utf-16-le")


class HostRefTests(unittest.TestCase):
    def test_kernel_names_referenced_by_host_code(self):
        cub = build_cubin({"decrypt_stage2": sass_function(4), "unused_kernel": sass_function(5)})
        blob = bytearray(0x40000)
        blob[0x1000:0x1000 + len(cub)] = cub
        # host .rdata: the device name passed to __cudaRegisterFunction / cuModuleGetFunction
        blob[0x30000:0x30010] = b"\x00decrypt_stage2\x00"
        a = [x for x in artifacts.sweep(BytesLayer("p", bytes(blob)), None, ("cubin",)) if x.kind == "cubin"][0]
        self.assertEqual(list(a.detail["host_refs"]), ["decrypt_stage2"])
        self.assertEqual(a.detail["host_refs"]["decrypt_stage2"], 0x30001)
        self.assertIn("1/2 kernel(s) named by host code", a.summary)


class EnvScanTests(unittest.TestCase):
    def test_ascii_and_utf16(self):
        load_plugins()
        blob = bytearray(0x10000)
        lin = b"\x00PATH=/usr/bin\x00CUDA_INJECTION64_PATH=/tmp/.x/libinj.so\x00LD_PRELOAD=/dev/shm/a.so\x00"
        blob[0x100:0x100 + len(lin)] = lin
        win = b"\x00\x00" + u16("Path=C:\\Windows\x00NVTX_INJECTION64_PATH=C:\\Users\\Public\\x.dll\x00"
                                "CUDA_CACHE_DISABLE=1\x00\x00")
        blob[0x2000:0x2000 + len(win)] = win
        blob[0x8000:0x8000 + len(lin)] = lin  # duplicate copy: reported once
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "p.keto")
            w = ContainerWriter(p, {"process": {"pid": 1}})
            w.add_segment("process", 0x7F0000000000, bytes(blob))
            w.close()
            with Context(image=p) as c:
                rows = PLUGINS["nvidia.envscan"](c, {}).run().as_dicts()
        got = {(r["Variable"], r["Value"], r["Encoding"], r["Severity"]) for r in rows}
        self.assertEqual(got, {("CUDA_INJECTION64_PATH", "/tmp/.x/libinj.so", "ascii", "high"),
                               ("LD_PRELOAD", "/dev/shm/a.so", "ascii", "high"),  # temp location

                               ("NVTX_INJECTION64_PATH", "C:\\Users\\Public\\x.dll", "utf-16", "high"),
                               ("CUDA_CACHE_DISABLE", "1", "utf-16", "medium")})


class ShaderCacheTests(unittest.TestCase):
    def _d3d_db(self, path, exe, last, shaders):
        db = sqlite3.connect(path)
        db.executescript("CREATE TABLE keys(keyid INTEGER PRIMARY KEY, key BLOB, last_accessed REAL);"
                         "CREATE TABLE vals(keyid INTEGER, type INTEGER, value BLOB);"
                         "CREATE TABLE app_id(id INTEGER PRIMARY KEY, exe_path TEXT, app_name TEXT, engine_name TEXT,"
                         " app_version INTEGER, engine_version INTEGER, app_profile_version INTEGER);")
        db.execute("INSERT INTO app_id VALUES (0, ?, NULL, NULL, 0, 0, 0)", (exe,))
        for i, blob in enumerate(shaders, 1):
            db.execute("INSERT INTO keys VALUES (?, ?, ?)", (i, os.urandom(16), last + i))
            db.execute("INSERT INTO vals VALUES (?, 0, ?)", (i, blob))
        db.commit()
        db.close()

    def test_d3d_cache_programs(self):
        load_plugins()
        with tempfile.TemporaryDirectory() as root:
            app = os.path.join(root, "D3DSCache", "0123456789abcdef")
            os.makedirs(app)
            exe = "C:\\Users\\u\\AppData\\Local\\Temp\\ArmouryCrate.exe"
            self._d3d_db(os.path.join(app, "6F75932F-0000-0000-0000-000000000000_VEN_10DE&DEV_28A1&SUBSYS_0&REV_A1"
                                           ".dxcache"), exe, 1794000000.0,
                         [gpucode.build_dxbc(program_type=5), gpucode.build_dxbc(program_type=0), b"not a shader"])
            entries = list(shadercache.iter_cache("d3d", os.path.join(root, "D3DSCache")))
            self.assertEqual(len(entries), 1)
            e = entries[0]
            self.assertEqual((e.app, e.adapter, e.entries, e.shaders, e.compute_shaders),
                             (exe, "NVIDIA 10DE:28A1", 3, 2, 1))
            with Context() as c:
                rows = PLUGINS["nvidia.shadercache"](c, {"path": os.path.join(root, "D3DSCache")}).run().as_dicts()
            self.assertEqual(rows[0]["Program"], exe)
            self.assertIn("user-writable", rows[0]["Attention"])
            self.assertIn("1 compute shader", rows[0]["Attention"])
            self.assertEqual(rows[0]["Last used"].year, 2026)

    def test_nvidia_cache_files(self):
        with tempfile.TemporaryDirectory() as root:
            d = os.path.join(root, "DXCache")
            os.makedirs(d)
            with open(os.path.join(d, "0001.nvph"), "wb") as fh:
                fh.write(b"nvph\x00\x0f\x0f\x0f" + b"\x00" * 64 + u16("C:\\Games\\miner_gui.exe") + b"\x00" * 16
                         + gpucode.build_spirv_kernel())
            e = list(shadercache.iter_cache("nvdx", d))[0]
            self.assertIn("C:\\Games\\miner_gui.exe", e.names)
            self.assertEqual((e.shaders, e.compute_shaders, e.error), (1, 1, None))


if __name__ == "__main__":
    unittest.main()
