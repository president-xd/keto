"""PDB / ISF symbol readers, PE CodeView, the symbol cache and 'keto pdb'.

Synthetic PDBs run everywhere. On Windows the parser is also checked against real PDBs: the debugger's cached
ntdll.pdb (published x64 layouts) and, when the matching ntkrnlmp.pdb is in a local symbol store, against the
offsets ntoskrnl.exe's own accessor functions use and against its export table."""

import glob
import io
import json
import lzma
import os
import struct
import tempfile
import unittest
import zlib

from keto.testing import synth_pdb as sp
from keto.winmem import isf, pdb, pe, symbols
from keto.winmem.symtab import ARRAY, BITFIELD, ENUM, POINTER, STRUCT, UNION, SymbolError

GUID_RAW = struct.pack("<IHH", 0x11223344, 0x5566, 0x7788) + bytes.fromhex("99AABBCCDDEEFF00")
GUID = "112233445566778899AABBCCDDEEFF00"


def synthetic_pdb():
    T = 0x1000  # first type index
    types = [
        (0x1002, struct.pack("<II", 0x0022, 8 << 13)),                          # T+0: ULONG* (64-bit)
        (0x1205, struct.pack("<IBB", 0x0022, 3, 4)),                            # T+1: ULONG bitfield len 3 pos 4
        (0x1503, struct.pack("<II", 0x0020, 0x0022) + sp.numeric(15) + sp.cstr("")),  # T+2: UCHAR[15]
        sp.structure(0, 0, "_NODE", fwdref=True),                               # T+3: forward reference
        (0x1002, struct.pack("<II", T + 3, 8 << 13)),                           # T+4: _NODE* (through the fwdref)
        (0x1203, sp.member(0x0022, 0, "LowPart") + sp.member(0x0012, 4, "HighPart")),   # T+5: union fields
        sp.structure(T + 5, 8, "_PAIR", count=2, union=True),                   # T+6: union _PAIR
        (0x1203, sp.enumerate_(0, "Zero") + sp.enumerate_(0x9000, "Big")),      # T+7: enum fields (LF_USHORT value)
        (0x1507, struct.pack("<HHII", 2, 0, 0x0074, T + 7) + sp.cstr("_KIND")),  # T+8: enum _KIND : int
        (0x1203, sp.member(T + 6, 0x40, "Pair") + sp.member(T + 8, 0x48, "Kind")
         + sp.member(0x0603, 0x9000, "Far")),                                   # T+9: continuation list
        (0x1203, sp.member(0x0022, 0, "Value") + sp.member(T + 1, 8, "Bits") + sp.member(T + 2, 0x10, "Name")
         + sp.member(T + 4, 0x20, "Next") + sp.member(T + 0, 0x28, "Counter") + sp.index(T + 9)),  # T+10
        sp.structure(T + 10, 0x9008, "_NODE", count=8),                          # T+11: the definition
        (0x1001, struct.pack("<IH", T + 11, 1)),                                # T+12: const _NODE
    ]
    publics = [("KiSystemStartup", 1, 0x10), ("PsActiveProcessHead", 2, 0x200), ("Unmapped", 9, 0)]
    return sp.build(GUID_RAW, 3, types, publics, sections=[0x1000, 0x50000])


class SyntheticPdbTests(unittest.TestCase):
    def setUp(self):
        self.p = pdb.PdbSymbols(synthetic_pdb(), source="synthetic")

    def test_identity_and_publics(self):
        self.assertEqual(self.p.guid, "112233445566778899AABBCCDDEEFF00")
        self.assertEqual(self.p.age, 3)
        self.assertEqual(self.p.machine, "x64")
        self.assertEqual(self.p.symbols["KiSystemStartup"], 0x1010)
        self.assertEqual(self.p.symbols["PsActiveProcessHead"], 0x50200)
        self.assertNotIn("Unmapped", self.p.symbols)  # segment beyond the section table

    def test_struct_members_fwdref_and_continuation(self):
        t = self.p.struct("_NODE")
        self.assertEqual((t.kind, t.size), (STRUCT, 0x9008))
        self.assertEqual(self.p.offsetof("_NODE", "Value"), 0)
        off, bits = self.p.member("_NODE", "Bits")
        self.assertEqual((off, bits.kind, bits.bit_pos, bits.bit_len), (8, BITFIELD, 4, 3))
        off, arr = self.p.member("_NODE", "Name")
        self.assertEqual((arr.kind, arr.count, arr.size), (ARRAY, 15, 15))
        off, nxt = self.p.member("_NODE", "Next")
        self.assertEqual(nxt.kind, POINTER)
        self.assertIs(self.p.resolve(nxt.target), t)  # the fwdref resolves to the full definition
        self.assertEqual(self.p.offsetof("_NODE", "Pair.HighPart"), 0x44)  # LF_INDEX continuation, nested union
        self.assertEqual(self.p.member("_NODE", "Pair")[1].kind, UNION)
        self.assertEqual(self.p.offsetof("_NODE", "Far"), 0x9000)  # numeric leaf LF_USHORT
        self.assertEqual(self.p.member("_NODE", "Far")[1].size, 8)  # basic pointer mode 6 = 64-bit

    def test_enum_and_errors(self):
        self.assertEqual(self.p.enum("_KIND"), {"Zero": 0, "Big": 0x9000})
        self.assertEqual(self.p.member("_NODE", "Kind")[1].kind, ENUM)
        with self.assertRaises(SymbolError):
            self.p.struct("_MISSING")
        with self.assertRaises(SymbolError):
            self.p.member("_NODE", "Nope")
        with self.assertRaises(SymbolError):
            self.p.member("_NODE", "Value.Deeper")

    def test_rejects_non_pdb(self):
        for data in (b"", b"MZ" * 100, b"Microsoft C/C++ program database 2.00\r\n\x1aJG\x00\x00" + bytes(64)):
            with self.assertRaises(SymbolError):
                pdb.PdbSymbols(data)


class IsfTests(unittest.TestCase):
    DOC = {"metadata": {"windows": {"pdb": {"GUID": "aabbccdd-0011-2233-4455-66778899aabb", "age": 2,
                                            "database": "ntkrnlmp.pdb", "machine_type": 0x8664}}},
           "base_types": {"unsigned long": {"size": 4, "signed": False, "kind": "int"},
                          "pointer": {"size": 8, "signed": False, "kind": "int"}, "void": {"size": 0, "kind": "void"}},
           "user_types": {"_A": {"kind": "struct", "size": 16, "fields": {
               "X": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
               "F": {"offset": 4, "type": {"kind": "bitfield", "bit_position": 3, "bit_length": 2,
                                           "type": {"kind": "base", "name": "unsigned long"}}},
               "P": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_A"}}}}}},
           "enums": {"_E": {"size": 4, "base": "unsigned long", "constants": {"One": 1}}},
           "symbols": {"PsActiveProcessHead": {"address": 0x1234}}}

    def test_isf_json_xz(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.json.xz")
            with lzma.open(path, "wt", encoding="utf-8") as fh:
                json.dump(self.DOC, fh)
            t = isf.load(path)
        self.assertEqual((t.guid, t.age, t.pdb_name, t.machine), ("AABBCCDD00112233445566778899AABB", 2,
                                                                  "ntkrnlmp.pdb", "x64"))
        self.assertEqual(t.rva("PsActiveProcessHead"), 0x1234)
        off, f = t.member("_A", "F")
        self.assertEqual((off, f.bit_pos, f.bit_len), (4, 3, 2))
        self.assertIs(t.resolve(t.member("_A", "P")[1].target), t.struct("_A"))
        self.assertEqual(t.enum("_E"), {"One": 1})

    def test_bad_isf(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.json")
            with open(path, "w") as fh:
                fh.write("{\"not\": 1}")
            with self.assertRaises(SymbolError):
                isf.load(path)


class SymbolStoreTests(unittest.TestCase):
    def test_find_local_layouts(self):
        key = GUID + "3"
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(symbols.find_local("ntkrnlmp.pdb", key, [d]))
            store = os.path.join(d, "ntkrnlmp.pdb", key)
            os.makedirs(store)
            open(os.path.join(store, "ntkrnlmp.pdb"), "wb").close()
            self.assertEqual(symbols.find_local("ntkrnlmp.pdb", key, [d]), os.path.join(store, "ntkrnlmp.pdb"))
        with tempfile.TemporaryDirectory() as d:  # Volatility symbol pack layout, GUID-age spelling
            folder = os.path.join(d, "windows", "ntkrnlmp.pdb")
            os.makedirs(folder)
            target = os.path.join(folder, "%s-%s.json.xz" % (GUID, "3"))
            open(target, "wb").close()
            self.assertEqual(symbols.find_local("ntkrnlmp.pdb", key, [d]), target)

    def test_nt_symbol_path_parsing(self):
        dirs = symbols._nt_symbol_path_dirs(r"srv*C:\sym*https://msdl.microsoft.com/download/symbols;D:\local;"
                                            r"cache*E:\c;https://x")
        self.assertEqual(dirs, [r"C:\sym", r"D:\local", r"E:\c"])

    def test_check_match(self):
        t = pdb.PdbSymbols(synthetic_pdb())
        self.assertEqual(symbols.check_match(t, "x.pdb", t.guid + "1"), [])
        self.assertTrue(symbols.check_match(t, "x.pdb", "0" * 32 + "1"))

    def test_cab_mszip(self):
        payload = os.urandom(5000) + b"A" * 70000  # spans several 32 KiB MSZIP blocks
        blocks, pos = [], 0
        hist = b""
        while pos < len(payload):
            chunk = payload[pos:pos + 32768]
            c = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=hist[-32768:]) if hist else \
                zlib.compressobj(9, zlib.DEFLATED, -15)
            blocks.append((b"CK" + c.compress(chunk) + c.flush(), len(chunk)))
            hist += chunk
            pos += len(chunk)
        data_off = 36 + 8 + 16 + len(b"x.pdb\x00")
        cfdata = b"".join(struct.pack("<IHH", 0, len(b), n) + b for b, n in blocks)
        header = b"MSCF" + struct.pack("<IIIIIBBHHHHH", 0, data_off + len(cfdata), 0, 44, 0, 3, 1, 1, 1, 0, 0, 0)
        folder = struct.pack("<IHH", data_off, len(blocks), 1)
        cffile = struct.pack("<IIHHHH", len(payload), 0, 0, 0, 0, 0x20) + b"x.pdb\x00"
        self.assertEqual(symbols.cab_extract(header + folder + cffile + cfdata), payload)
        with self.assertRaises(SymbolError):
            symbols.cab_extract(header + struct.pack("<IHH", data_off, 1, 3) + cffile + cfdata)  # LZX


class PdbCommandTests(unittest.TestCase):
    def test_find_and_info_with_name_and_key(self):
        from keto import cli
        with tempfile.TemporaryDirectory() as d:
            key = "AB" * 16 + "1"
            store = os.path.join(d, "ntkrnlmp.pdb", key)
            os.makedirs(store)
            with open(os.path.join(store, "ntkrnlmp.pdb"), "wb") as fh:
                fh.write(synthetic_pdb())
            out = os.path.join(d, "o.txt")
            rc = cli.main(["--output-file", out, "pdb", "find", "--name", "ntkrnlmp.pdb", "--key", key,
                           "--symbols-dir", d])
            self.assertEqual(rc, 0)
            with open(out) as fh:
                self.assertIn(store, fh.read())
            rc = cli.main(["--output-file", out, "pdb", "find", "--name", "ntkrnlmp.pdb", "--key", "CD" * 16 + "1",
                           "--symbols-dir", d])
            self.assertEqual(rc, 1)
            rc = cli.main(["--output-file", out, "pdb", "info", "--symbol-file", os.path.join(store, "ntkrnlmp.pdb")])
            self.assertEqual(rc, 0)
            with open(out) as fh:
                self.assertIn("112233445566778899AABBCCDDEEFF00", fh.read())


SYM_DIR = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sym"


@unittest.skipUnless(os.name == "nt" and glob.glob(SYM_DIR + r"\ntdll.pdb\*\ntdll.pdb"), "needs a cached ntdll.pdb")
class RealNtdllPdbTests(unittest.TestCase):
    """Published x64 layouts (stable since Windows 8): _PEB.Ldr 0x18, ProcessParameters 0x20, BeingDebugged 0x2;
    _LDR_DATA_TABLE_ENTRY.DllBase 0x30, FullDllName 0x48, BaseDllName 0x58; _TEB.ProcessEnvironmentBlock 0x60;
    _KUSER_SHARED_DATA.NtMajorVersion 0x26C, NtSystemRoot 0x30."""

    def test_layouts(self):
        p = pdb.load(glob.glob(SYM_DIR + r"\ntdll.pdb\*\ntdll.pdb")[0])
        self.assertEqual(p.machine, "x64")
        for (s, m), want in {("_PEB", "BeingDebugged"): 2, ("_PEB", "Ldr"): 0x18, ("_PEB", "ProcessParameters"): 0x20,
                             ("_LDR_DATA_TABLE_ENTRY", "DllBase"): 0x30, ("_LDR_DATA_TABLE_ENTRY", "FullDllName"): 0x48,
                             ("_LDR_DATA_TABLE_ENTRY", "BaseDllName"): 0x58, ("_TEB", "ProcessEnvironmentBlock"): 0x60,
                             ("_KUSER_SHARED_DATA", "NtMajorVersion"): 0x26C,
                             ("_KUSER_SHARED_DATA", "NtSystemRoot"): 0x30}.items():
            self.assertEqual(p.offsetof(s, m), want, "%s.%s" % (s, m))
        self.assertEqual(p.sizeof("_UNICODE_STRING"), 16)


def _local_kernel_pdb():
    if os.name != "nt":
        return None, None
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "ntoskrnl.exe")
    if not os.path.isfile(path):
        return None, None
    cv = pe.from_file(path).codeview()
    found = symbols.find_local(cv.pdb_name, cv.key, symbols.search_dirs()) if cv else None
    return path, found


@unittest.skipUnless(_local_kernel_pdb()[1], "needs the PDB of this machine's ntoskrnl.exe (keto pdb fetch)")
class RealKernelPdbTests(unittest.TestCase):
    """Independent ground truth: ntoskrnl's exported accessors compile the _EPROCESS offsets into their machine
    code (``mov rax,[rcx+disp32]`` = 48 8B 81 disp32; ``lea rax,[rcx+disp32]`` = 48 8D 81 disp32)."""

    ACCESSORS = {"PsGetProcessId": "UniqueProcessId", "PsGetProcessPeb": "Peb",
                 "PsGetProcessInheritedFromUniqueProcessId": "InheritedFromUniqueProcessId",
                 "PsGetProcessImageFileName": "ImageFileName", "PsGetProcessDxgProcess": "DxgProcess",
                 "PsGetProcessWin32Process": "Win32Process", "PsGetProcessSectionBaseAddress": "SectionBaseAddress"}

    @classmethod
    def setUpClass(cls):
        exe, found = _local_kernel_pdb()
        cls.image = pe.from_file(exe)
        cls.table = symbols.load(found)

    def test_guid_matches(self):
        self.assertEqual(self.table.guid, self.image.codeview().guid)

    def test_eprocess_offsets_match_accessor_code(self):
        exports = self.image.exports()
        checked = 0
        for fn, member in self.ACCESSORS.items():
            if fn not in exports or not self.table.has_member("_EPROCESS", member):
                continue
            code = self.image.read(exports[fn], 16)
            i = max(code.find(b"\x48\x8b\x81"), -1)
            j = code.find(b"\x48\x8d\x81")
            pos = i if i >= 0 else j
            if pos < 0:
                continue
            disp = struct.unpack_from("<i", code, pos + 3)[0]
            self.assertEqual(self.table.offsetof("_EPROCESS", member), disp, fn)
            checked += 1
        self.assertGreaterEqual(checked, 4)

    def test_publics_match_exports(self):
        exports = self.image.exports()
        common = [n for n in exports if n in self.table.symbols]
        self.assertGreater(len(common), 500)
        bad = [n for n in common if exports[n] != self.table.symbols[n]]
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
