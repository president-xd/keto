"""``keto acquire --method pramin`` against an emulated BAR0 (keto.testing.fakebar0) and a fake sysfs tree.

Nothing here touches real sysfs or hardware: every Host gets a temporary sysfs root, an explicit platform and euid,
and either the emulator or the real ``Bar0Mmio`` over an ordinary file. The method itself is validated against the
emulator only; there is no bare-metal Linux NVIDIA device in the test environment."""

import ast
import errno
import io
import os
import shutil
import signal
import struct
import tempfile
import threading
import unittest
from unittest import mock

from keto.acquire import pramin
from keto.acquire.cli import _base_metadata
from keto.cli import build_parser, main
from keto.formats.container import Container
from keto.framework.context import Context
from keto.framework.exceptions import FormatError, InvalidAddressException, RequirementError
from keto.framework.plugin import PLUGINS, load_plugins
from keto.testing.fakebar0 import (APERTURE, LOCAL_MEMORY_RANGE, PBUS_BAR0_WINDOW, USABLE_FB_SIZE_IN_MB,
                                   XAL_EP_BAR0_WINDOW, ConcurrentDriver, FakeBar0, encode_local_memory_range,
                                   make_sysfs, pci_device, poke)
from keto.testing.synth import build_all

MiB = 1 << 20
TMP = None


def setUpModule():
    global TMP
    TMP = tempfile.mkdtemp(prefix="keto-pramin-")


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def pattern(size, seed=1):
    """Deterministic non-zero VRAM content (no 4 KiB page of all-ones, no PRI error words)."""
    block = bytes((i * 7 + seed) & 0x7F for i in range(4096))
    return b"".join(block[:4092] + struct.pack("<I", 0x1000 + i) for i in range(size // 4096))


class Env:
    """A fake sysfs tree, an emulated BAR0 and a Host wired to them."""

    def __init__(self, vram=None, chipset=0x197, devices=None, lockdown="[none] integrity confidentiality",
                 open_bar0=None, nvml=None, system="Linux", euid=0, **fake_kw):
        self.dir = tempfile.mkdtemp(dir=TMP)
        self.root = os.path.join(self.dir, "sys")
        self.devices = make_sysfs(self.root, devices if devices is not None else [pci_device()], lockdown=lockdown)
        self.vram = vram if vram is not None else pattern(4 * MiB)
        self.fake = FakeBar0(self.vram, chipset=chipset, **fake_kw)
        self.err = io.StringIO()
        self.host = pramin.Host(sysfs_root=self.root, system=system, euid=euid, err=self.err,
                                open_bar0=open_bar0 or (lambda path, size: self.fake.reopen()),
                                nvml=nvml or (lambda: None))
        self.n = 0

    def args(self, *argv, out=None):
        self.n += 1
        out = out or os.path.join(self.dir, "out%d.keto" % self.n)
        return build_parser().parse_args(["acquire", "--method", "pramin", "--out", out] + list(argv))

    def acquire(self, *argv, out=None):
        """Run the method; returns (rc, path, stdout). Exceptions propagate."""
        a = self.args(*argv, out=out)
        buf = io.StringIO()
        self.stdout = buf
        rc = pramin.acquire_pramin(a, buf, _base_metadata(a), host=self.host)
        return rc, a.out, buf.getvalue()

    def last_out(self):
        return os.path.join(self.dir, "out%d.keto" % self.n)


def meta(path):
    with Container(path) as c:
        return c.metadata


def vram_of(path):
    with Container(path) as c:
        layer = c.layers()["vram"]
        return layer.minimum_address, layer.read(layer.minimum_address, layer.size)


# -- architecture ---------------------------------------------------------------------------------------------------

class ArchitectureTests(unittest.TestCase):
    CASES = [  # chipset, chip, generation, window register, BASE bits, size register
        (0x0E4, "GK104", "kepler", 0x1700, "23:0", None),
        (0x124, "GM204", "maxwell", 0x1700, "23:0", None),
        (0x134, "GP104", "pascal", 0x1700, "23:0", None),
        (0x140, "GV100", "volta", 0x1700, "23:0", None),
        (0x164, "TU104", "turing", 0x1700, "23:0", LOCAL_MEMORY_RANGE),
        (0x170, "GA100", "ampere", 0x1700, "23:0", LOCAL_MEMORY_RANGE),
        (0x172, "GA102", "ampere", 0x1700, "23:0", USABLE_FB_SIZE_IN_MB),
        (0x197, "AD107", "ada", 0x1700, "23:0", USABLE_FB_SIZE_IN_MB),
        (0x180, "GH100", "hopper", 0x10FD40, "21:0", USABLE_FB_SIZE_IN_MB),
        (0x1A0, "GB100", "blackwell", 0x10FD40, "22:0", USABLE_FB_SIZE_IN_MB),
        (0x1B2, "GB202", "blackwell", 0x10FD40, "22:0", USABLE_FB_SIZE_IN_MB),
        (0x1C0, "GR100", "rubin", 0x10FD40, "30:0", USABLE_FB_SIZE_IN_MB),
    ]

    def test_boot_registers_decode_to_the_cited_window_register(self):
        for cs, name, gen, reg, bits, sreg in self.CASES:
            with self.subTest(chipset=hex(cs)):
                fake = FakeBar0(bytes(MiB), chipset=cs)
                chip = pramin.identify(fake)
                self.assertEqual((chip.chipset, chip.name, chip.generation), (cs, name, gen))
                self.assertEqual((chip.window.offset, chip.window.base_bits), (reg, bits))
                self.assertEqual(chip.window.has_target, reg == 0x1700)
                self.assertEqual(chip.size_register, sreg)
                self.assertEqual(chip.boot42 is not None, cs >= 0x130)  # BOOT_42 is read from Pascal on only
                if cs < 0x130:
                    self.assertNotIn(("r32", 0xA00, fake.boot42), fake.log)

    def test_boot42_wins_over_boot0(self):
        fake = FakeBar0(bytes(MiB), chipset=0x197, boot0=(0x194 << 20) | 0xA1)
        chip = pramin.identify(fake)
        self.assertEqual(chip.name, "AD107")
        self.assertIn("BOOT_42", chip.notes[0])

    def test_unidentifiable_chips_are_refused(self):
        cases = [
            (dict(boot0=0xFFFFFFFF), "does not respond"),
            (dict(boot0=0xBADF0200), "SEC_FAULT"),
            (dict(boot0=0xBADF1100), "PRI error"),
            (dict(chipset=0x050, boot0=0x050000A2), "older than Fermi"),
            (dict(chipset=0x0C4), "Fermi"),
            (dict(chipset=0x17B), "integrated"),
            (dict(chipset=0x1AB), "integrated"),
            (dict(chipset=0x175), "no cited PRAMIN window register"),
            (dict(chipset=0x1D0), "no cited PRAMIN window register"),
            (dict(chipset=0x164, boot42=0xBADF1100), "BOOT_42"),
        ]
        for kw, msg in cases:
            with self.subTest(**{k: hex(v) for k, v in kw.items()}):
                fake = FakeBar0(bytes(MiB), **kw)
                with self.assertRaises(RequirementError) as cm:
                    pramin.identify(fake)
                self.assertIn(msg, str(cm.exception))
                self.assertEqual(fake.window_writes(), [])

    def test_vram_size_registers(self):
        ada = FakeBar0(bytes(MiB), chipset=0x197, size_value=0x1800)
        self.assertEqual(pramin.size_from_register(ada, pramin.identify(ada))[0], 0x1800 * MiB)
        tu = FakeBar0(bytes(MiB), chipset=0x164, size_value=encode_local_memory_range(8 << 30))
        size, what = pramin.size_from_register(tu, pramin.identify(tu))
        self.assertEqual(size, 8 << 30)
        self.assertIn("LOWER_MAG", what)
        ecc = FakeBar0(bytes(MiB), chipset=0x164, size_value=encode_local_memory_range(16 << 30, ecc=True))
        self.assertEqual(pramin.size_from_register(ecc, pramin.identify(ecc))[0], (16 << 30) // 16 * 15)
        for bad in (0, 0xFFFFFFFF, 0xBADF1100):
            z = FakeBar0(bytes(MiB), chipset=0x197, size_value=bad)
            self.assertIsNone(pramin.size_from_register(z, pramin.identify(z))[0])
        gp = FakeBar0(bytes(MiB), chipset=0x134)
        self.assertIsNone(pramin.size_from_register(gp, pramin.identify(gp))[0])

    def test_window_value_encoding(self):
        w = pramin.WIN_PBUS
        # BASE = addr >> 16, TARGET cleared to VID_MEM, reserved bits 31:26 kept (read-modify-write)
        self.assertEqual(w.value(0xFC000000 | (2 << 24) | 0x1234, 0x50000), 0xFC000005)
        self.assertEqual(w.max_vram, 1 << 40)
        self.assertEqual(pramin.WIN_GH100.max_vram, 1 << 38)
        self.assertEqual(pramin.WIN_GB100.max_vram, 1 << 39)
        for bad in (0x8000, 1 << 40):
            with self.assertRaises(ValueError):
                w.value(0, bad)
        self.assertEqual(pramin.WIN_GH100.value(0xFFC00000, 0xFFFF0000), 0xFFC0FFFF)
        with self.assertRaises(ValueError):
            pramin.WIN_GH100.value(0, 1 << 38)

    def test_hopper_acquisition_uses_the_xal_register(self):
        vram = pattern(3 * MiB)
        env = Env(vram=vram, chipset=0x180, window=0x2A)
        rc, out, _ = env.acquire()
        self.assertEqual(rc, 0)
        self.assertEqual(vram_of(out), (0, vram))
        offsets = {off for op, off, *_ in env.fake.log if op == "w32"}
        self.assertEqual(offsets, {XAL_EP_BAR0_WINDOW})
        self.assertEqual(env.fake.window_writes(), [0x0, 0x10, 0x20, 0x2A])  # three 1 MiB positions, restore
        m = meta(out)
        self.assertEqual(m["pramin"]["window_register"]["offset"], "0x10fd40")
        self.assertEqual(m["device"]["architecture"], "hopper")

    def test_size_without_register_needs_nvml_or_operator(self):
        bdf = "0000:01:00.0"
        env = Env(vram=pattern(2 * MiB), chipset=0x134)
        with self.assertRaises(RequirementError) as cm:
            env.acquire()
        self.assertIn("--vram-size", str(cm.exception))
        self.assertEqual(env.fake.window_writes(), [])
        rc, out, _ = env.acquire("--vram-size", "2M")
        self.assertEqual(rc, 0)
        self.assertTrue(meta(out)["pramin"]["vram_size_source"].startswith("operator"))
        other = {"devices": [{"name": "other", "pci": {"bus_id": "00000000:02:00.0"}, "memory": {"total": MiB}}]}
        env2 = Env(vram=pattern(2 * MiB), chipset=0x134, nvml=lambda: other)
        with self.assertRaises(RequirementError):
            env2.acquire()  # NVML knows another GPU only: not used
        ours = {"devices": [{"name": "GTX 1080", "pci": {"bus_id": "00000000:01:00.0"}, "memory": {"total": 2 * MiB}}]}
        env3 = Env(vram=pattern(2 * MiB), chipset=0x134, nvml=lambda: ours)
        rc, out, _ = env3.acquire("--vram-size", "1M")
        m = meta(out)["pramin"]
        self.assertTrue(m["vram_size_source"].startswith("nvml"), m["vram_size_source"])
        self.assertEqual(m["vram_size"], 2 * MiB)
        self.assertIn(bdf, m["vram_size_candidates"]["nvml"]["detail"].replace("00000000:", "0000:"))
        self.assertIn("--vram-size 0x100000 ignored", env3.err.getvalue())

    def test_new_files_parse_as_python38(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for rel in ("keto/acquire/pramin.py", "keto/testing/fakebar0.py", "tests/test_pramin.py"):
            with open(os.path.join(here, rel), encoding="utf-8") as fh:
                src = fh.read()
            ast.parse(src, rel, feature_version=(3, 8))
            for name in ("removeprefix", "removesuffix", "bit_count"):  # 3.9+/3.10+ methods
                self.assertNotIn(".%s(" % name, src, rel)


# -- preconditions --------------------------------------------------------------------------------------------------

class PreconditionTests(unittest.TestCase):
    def refused(self, env, *argv):
        with self.assertRaises(RequirementError) as cm:
            env.acquire(*argv)
        self.assertEqual(env.fake.log, [], "BAR0 was touched before the refusal")
        self.assertFalse(os.path.exists(env.last_out()), "an output file was created")
        return str(cm.exception)

    def test_not_linux(self):
        self.assertIn("needs Linux", self.refused(Env(system="Windows")))

    def test_not_root(self):
        self.assertIn("needs root", self.refused(Env(euid=1000)))

    def test_lockdown(self):
        msg = self.refused(Env(lockdown="none [integrity] confidentiality"))
        self.assertIn("lockdown is active", msg)
        self.assertIn("LOCKDOWN_PCI_ACCESS", msg)
        self.assertIn("[confidentiality]", self.refused(Env(lockdown="none integrity [confidentiality]")))

    def test_device_selection(self):
        intel = pci_device("0000:00:02.0", vendor=0x8086, device=0x46a6)
        audio = pci_device("0000:01:00.1", device=0x22BA, cls=0x040300, driver="snd_hda_intel")
        self.assertIn("not an NVIDIA device", self.refused(Env(devices=[intel, pci_device()]), "--pci", "00:02.0"))
        self.assertIn("not a display controller", self.refused(Env(devices=[audio, pci_device()]), "--pci",
                                                               "0000:01:00.1"))
        two = [pci_device("0000:01:00.0"), pci_device("0000:41:00.0", device=0x2684, cls=0x030200)]
        msg = self.refused(Env(devices=two))
        self.assertIn("2 NVIDIA GPUs", msg)
        self.assertIn("0000:01:00.0", msg)
        self.assertIn("0000:41:00.0", msg)
        self.assertIn("no NVIDIA display/3D controller", self.refused(Env(devices=[intel, audio])))
        self.assertIn("no such PCI device", self.refused(Env(), "--pci", "0000:09:00.0"))
        self.assertIn("expected a PCI address", self.refused(Env(), "--pci", "gpu0"))
        env = Env(devices=two)  # the 3D controller is chosen explicitly
        rc, out, _ = env.acquire("--pci", "41:00.0")
        self.assertEqual(meta(out)["pramin"]["pci"]["bdf"], "0000:41:00.0")

    def test_power_state_and_memory_decoding(self):
        self.assertIn("D3cold", self.refused(Env(devices=[pci_device(power_state="D3cold")])))
        self.assertIn("power state D3", self.refused(Env(devices=[pci_device(power_state=None, pm_state=3)])))
        env = Env(devices=[pci_device(power_state=None, pm_state=0)])  # PMCSR says D0
        self.assertEqual(meta(env.acquire()[1])["pramin"]["power_state"], "D0")
        msg = self.refused(Env(devices=[pci_device(command=0x0004)]))
        self.assertIn("memory decoding is disabled", msg)
        self.assertIn("COMMAND 0x0004", msg)

    def test_mmap_refusals_explain_the_cause(self):
        def refuse(code):
            def opener(path, size):
                raise OSError(code, os.strerror(code), path)
            return opener
        msg = self.refused(Env(open_bar0=refuse(errno.EINVAL)))
        self.assertIn("CONFIG_IO_STRICT_DEVMEM", msg)
        self.assertIn("iomem=relaxed", msg)
        self.assertIn("lockdown", self.refused(Env(open_bar0=refuse(errno.EPERM))))
        self.assertIn("BAR0", self.refused(Env(devices=[pci_device(bar0_size=4 * MiB)])))

    def test_bound_driver_needs_the_override(self):
        for drv in ("nvidia", "nouveau", "NovaCore"):
            with self.subTest(driver=drv):
                msg = self.refused(Env(devices=[pci_device(driver=drv)]))
                self.assertIn("--allow-bound-driver", msg)
                self.assertIn("unbind", msg)
        env = Env(devices=[pci_device(driver="nvidia")])
        rc, out, _ = env.acquire("--allow-bound-driver")
        self.assertEqual(rc, 0)
        m = meta(out)
        self.assertIs(m["pramin"]["driver_active"], True)
        self.assertEqual(m["pramin"]["driver"], "nvidia")
        self.assertIn("ACTIVE", env.err.getvalue())
        self.assertTrue(any("CORRUPT" in w for w in m["acquisition"]["warnings"]))
        self.assertIn("nvidia (ACTIVE)", m["acquisition"]["notes"])

    def test_vfio_is_allowed_with_a_pause_warning(self):
        env = Env(devices=[pci_device(driver="vfio-pci")])
        rc, out, _ = env.acquire()
        self.assertEqual(rc, 0)
        m = meta(out)["pramin"]
        self.assertEqual((m["driver"], m["driver_active"], m["vfio_passthrough"]), ("vfio-pci", False, True))
        self.assertIn("PAUSED", env.err.getvalue())

    def test_unbound_device_records_no_driver(self):
        env = Env()
        rc, out, _ = env.acquire()
        m = meta(out)
        self.assertEqual((m["pramin"]["driver"], m["pramin"]["driver_active"]), (None, False))
        self.assertEqual(env.err.getvalue(), "")

    def test_main_thread_only(self):
        env = Env()
        got = []
        t = threading.Thread(target=lambda: got.append(self._catch(env)))
        t.start()
        t.join()
        self.assertIn("main thread", got[0])
        self.assertEqual(env.fake.log, [])

    @staticmethod
    def _catch(env):
        try:
            env.acquire()
        except RequirementError as exc:
            return str(exc)
        return "no error"


# -- window discipline ------------------------------------------------------------------------------------------------

class WindowDisciplineTests(unittest.TestCase):
    def test_every_write_is_read_back_and_every_aperture_read_is_followed_by_a_window_check(self):
        env = Env(vram=pattern(4 * MiB), window=0x02000123)  # left pointing at sysmem (TARGET 2)
        rc, out, _ = env.acquire()
        log, reg = env.fake.log, PBUS_BAR0_WINDOW
        for i, entry in enumerate(log):
            if entry[0] == "w32":
                self.assertEqual(log[i + 1][:2], ("r32", reg), "write at %d not read back" % i)
            if entry[0] == "ap":
                self.assertEqual(log[i + 1][:2], ("r32", reg), "aperture read at %d not followed by a check" % i)
        self.assertEqual(env.fake.window_raw, 0x02000123)
        self.assertEqual(env.fake.window_writes()[-1], 0x02000123)
        m = meta(out)["pramin"]
        self.assertEqual((m["window_before"], m["window_after"], m["window_restored_to"]),
                         ("0x02000123", "0x02000123", "0x02000123"))
        self.assertIs(m["window_restore_verified"], True)
        self.assertEqual(m["window_restored_reason"], "original value")
        self.assertIn("SYS_MEM_COHERENT", m["window_before_decoded"])
        self.assertEqual(vram_of(out), (0, env.vram))

    def test_window_moved_once_by_the_driver(self):
        drv = ConcurrentDriver(base=0x300000, at=(5,))
        env = Env(vram=pattern(4 * MiB), window=0x7, driver=drv)
        rc, out, _ = env.acquire()
        self.assertEqual(rc, 0)
        self.assertEqual(vram_of(out), (0, env.vram))  # the block read through the moved window was re-read
        m = meta(out)
        self.assertEqual(m["acquisition"]["status"], "complete")
        self.assertEqual(m["pramin"]["window_moved_during_read"], 1)
        ev = m["pramin"]["window_events"][0]
        self.assertEqual((ev["kind"], ev["vram"], ev["observed"]), ("moved-during-read", "0x50000", "0x30"))
        # the driver's latest value is what its cached window position says: that is what is restored
        self.assertEqual(env.fake.window_raw, 0x30)
        self.assertEqual(m["pramin"]["window_restored_to"], "0x00000030")
        self.assertIn("another agent", m["pramin"]["window_restored_reason"])

    def test_move_between_two_window_positions_updates_the_restore_value(self):
        fake = FakeBar0(pattern(2 * MiB), window=0x3)
        reader = pramin.PraminReader(fake, pramin.WIN_PBUS)
        self.assertEqual(reader.read(0, 0x1000, 0x1000), fake.vram[0x1000:0x2000])
        fake.window_raw = 0x77  # the driver repositions the window between Keto's reads
        self.assertEqual(reader.read(0x100000, 0x100000, 0x1000), fake.vram[0x100000:0x101000])
        self.assertEqual((reader.moved_between, reader.moved), (1, 0))
        self.assertEqual(reader.events[0]["kind"], "moved-between-reads")
        self.assertTrue(reader.restore())
        self.assertEqual(fake.window_raw, 0x77)
        with self.assertRaises(ValueError):
            reader.read(0x100000, 0x1F0000, 0x20000)  # would cross the end of the 1 MiB aperture

    def test_driver_that_keeps_moving_the_window_stops_the_acquisition(self):
        drv = ConcurrentDriver(base=0x100000, from_read=3)
        env = Env(vram=pattern(4 * MiB), window=0x5, driver=drv)
        with self.assertRaises(pramin.PraminError) as cm:
            env.acquire()
        self.assertIn("bounded retries", str(cm.exception))
        m = meta(env.last_out())
        self.assertTrue(m["acquisition"]["status"].startswith("incomplete: PraminError"))
        self.assertEqual(m["pramin"]["acquired_ranges"], [{"start": "0x0", "size": 3 * pramin.BLOCK}])
        self.assertEqual(m["pramin"]["window_moved_during_read"], pramin.RETRIES + 1)
        self.assertEqual(env.fake.window_raw, 0x10)  # restored to the driver's value
        self.assertEqual(vram_of(env.last_out()), (0, env.vram[:3 * pramin.BLOCK]))

    def test_window_that_does_not_keep_the_write_is_refused(self):
        env = Env(window=0x9, window_writable=False)
        with self.assertRaises(pramin.PraminError) as cm:
            env.acquire()
        self.assertIn("did not keep", str(cm.exception))
        m = meta(env.last_out())
        self.assertEqual(m["pramin"]["acquired_ranges"], [])
        self.assertEqual(m["pramin"]["window_readback_failures"], pramin.RETRIES + 1)
        self.assertEqual(env.fake.window_raw, 0x9)
        self.assertEqual(m["pramin"]["window_after"], "0x00000009")

    def test_window_restored_after_an_exception(self):
        def boom(i):
            if i == 10:
                raise RuntimeError("bus error")
        env = Env(window=0x11, on_aperture_read=boom)
        with self.assertRaises(RuntimeError):
            env.acquire()
        self.assertEqual(env.fake.window_raw, 0x11)
        m = meta(env.last_out())
        self.assertEqual(m["acquisition"]["status"], "incomplete: RuntimeError: bus error")
        self.assertEqual(m["pramin"]["acquired_ranges"], [{"start": "0x0", "size": 10 * pramin.BLOCK}])
        self.assertIn("partial container", env.stdout.getvalue())

    def _interrupt(self, signame):
        signum = getattr(signal, signame)
        before = signal.getsignal(signum)
        env = Env(window=0x22, on_aperture_read=lambda i: signal.raise_signal(signum) if i == 7 else None)
        with self.assertRaises(KeyboardInterrupt) as cm:
            env.acquire()
        self.assertIsInstance(cm.exception, pramin.AcquisitionInterrupted)
        self.assertEqual(env.fake.window_raw, 0x22)
        self.assertEqual(signal.getsignal(signum), before)  # handlers are put back
        m = meta(env.last_out())
        self.assertEqual(m["acquisition"]["status"], "incomplete: interrupted by %s" % signame)
        self.assertEqual(m["pramin"]["acquired_ranges"], [{"start": "0x0", "size": 8 * pramin.BLOCK}])
        self.assertIs(m["pramin"]["window_restore_verified"], True)

    def test_window_restored_on_sigint(self):
        self._interrupt("SIGINT")

    def test_window_restored_on_sigterm(self):
        self._interrupt("SIGTERM")

    def test_signal_during_the_restore_does_not_cut_it_short(self):
        class SignalOnRestore(FakeBar0):
            def write32(self, offset, value):
                super().write32(offset, value)
                if value == 0x33:  # the restore write
                    signal.raise_signal(signal.SIGINT)
        env = Env()
        env.fake = SignalOnRestore(env.vram, window=0x33)
        with self.assertRaises(pramin.AcquisitionInterrupted):
            env.acquire()
        self.assertEqual(env.fake.window_raw, 0x33)
        m = meta(env.last_out())
        self.assertEqual(m["acquisition"]["status"], "complete")  # all data was read before the signal
        self.assertIs(m["pramin"]["window_restore_verified"], True)

    def test_gpu_lost_stops_and_reports_unverified_restore(self):
        env = Env(window=0x4, lose_after=20)
        with self.assertRaises(pramin.PraminError) as cm:
            env.acquire()
        self.assertIn("stopped responding", str(cm.exception))
        m = meta(env.last_out())["pramin"]
        self.assertIs(m["window_restore_verified"], False)
        self.assertIn("could NOT be restored", env.err.getvalue())
        self.assertEqual(m["acquired_ranges"], [{"start": "0x0", "size": 20 * pramin.BLOCK}])

    def test_move_and_restore_race_is_caught_only_by_a_second_pass(self):
        vram = pattern(2 * MiB)
        aba = lambda: ConcurrentDriver(base=0x100000, at=(3,), restore=True)  # noqa: E731
        env = Env(vram=vram, driver=aba())
        rc, out, _ = env.acquire()
        m = meta(out)["pramin"]
        self.assertEqual((m["window_moved_during_read"], m["changed_pages"]), (0, 0))  # invisible to one pass
        self.assertNotEqual(vram_of(out)[1], vram)
        env = Env(vram=vram, driver=aba())
        rc, out, _ = env.acquire("--passes", "2")
        m = meta(out)["pramin"]
        self.assertEqual(m["changed_ranges"], [{"start": "0x30000", "size": pramin.BLOCK, "pass": 2}])
        self.assertEqual(m["passes"], 2)


# -- data handling --------------------------------------------------------------------------------------------------

class DataHandlingTests(unittest.TestCase):
    def test_pri_error_pages(self):
        vram = bytearray(pattern(2 * MiB))
        vram[0x30000:0x31000] = struct.pack("<I", 0xBADDCAFE) * 1024     # 0xbad top nibbles, not an error code
        vram[0x40000:0x41000] = struct.pack("<I", 0xBADF1100) * 1023 + b"DATA"  # one data word: not an error page
        env = Env(vram=bytes(vram), error_regions=[(0x10000, 0x12000, 0xBADF1100), (0x20000, 0x21000, 0xBAD0AC07)])
        rc, out, _ = env.acquire()
        m = meta(out)["pramin"]
        self.assertEqual(m["error_pages"], 3)
        self.assertEqual(m["error_ranges"], [{"start": "0x10000", "size": 0x2000, "words": ["0xbadf1100"]},
                                             {"start": "0x20000", "size": 0x1000, "words": ["0xbad0ac07"]}])
        base, data = vram_of(out)
        self.assertEqual(data[0x10000:0x10004], struct.pack("<I", 0xBADF1100))  # stored as read
        self.assertEqual(data[0x30000:0x31000], bytes(vram[0x30000:0x31000]))
        self.assertTrue(pramin.is_pri_error(0xBADF5000) and pramin.is_pri_error(0xBAD00100))
        self.assertFalse(pramin.is_pri_error(0xBADDCAFE) or pramin.is_pri_error(0xFFFFFFFF))

    def test_range_limits_window_positions_and_bounds(self):
        vram = pattern(4 * MiB)
        env = Env(vram=vram, window=0x3F)
        rc, out, _ = env.acquire("--start", "0xF123", "--length", "0x200000")
        base, data = vram_of(out)
        self.assertEqual((base, len(data)), (0xF000, 0x201000))  # whole pages: [0xf000, 0x210000)
        self.assertEqual(data, vram[0xF000:0x210000])
        self.assertEqual(env.fake.window_writes(), [0x0, 0x10, 0x20, 0x3F])
        aps = [(a, n) for op, a, n, *_ in env.fake.log if op == "ap"]
        self.assertEqual(aps[0], (0xF000, pramin.BLOCK))
        self.assertTrue(all(a + n <= 0x210000 for a, n in aps))
        self.assertEqual(meta(out)["pramin"]["acquired_ranges"], [{"start": "0xf000", "size": 0x201000}])
        env = Env(vram=vram)
        env.acquire()
        self.assertEqual(env.fake.max_vram_end, 4 * MiB)  # never past the VRAM size
        with self.assertRaises(RequirementError):
            Env(vram=vram).acquire("--start", "4M")
        with self.assertRaises(RequirementError):
            Env(vram=vram).acquire("--start", "3M", "--length", "2M")

    def test_all_pages_stored_and_nothing_outside_reads_as_zero(self):
        vram = bytearray(pattern(2 * MiB))
        vram[0x1000:0x9000] = bytes(0x8000)
        vram[0x9000:0xA000] = b"\xff" * 0x1000  # an all-ones page with a live GPU is data
        env = Env(vram=bytes(vram))
        rc, out, _ = env.acquire("--start", "0", "--length", "1M")
        m = meta(out)
        self.assertIs(m["pramin"]["zero_pages_omitted"], False)
        with Container(out) as c:
            layer = c.layers()["vram"]
            self.assertEqual(layer.read(0x1000, 0x8000), bytes(0x8000))
            self.assertEqual(layer.read(0x9000, 0x1000), b"\xff" * 0x1000)
            with self.assertRaises(InvalidAddressException):
                layer.read(0x100000, 4)  # outside the acquired range: not in the image, not zeros

    def test_bulk_mode_is_explicit(self):
        env = Env()
        rc, out, _ = env.acquire("--bulk-mmio")
        self.assertGreater(env.fake.bulk_reads, 0)
        self.assertEqual(vram_of(out), (0, env.vram))
        self.assertEqual(meta(out)["pramin"]["mmio_access"], "memcpy (--bulk-mmio)")
        self.assertIn("--bulk-mmio", env.err.getvalue())
        env = Env()
        env.acquire()
        self.assertEqual(env.fake.bulk_reads, 0)

    def test_existing_output_is_never_overwritten(self):
        env = Env()
        out = os.path.join(env.dir, "evidence.keto")
        with open(out, "wb") as fh:
            fh.write(b"evidence")
        with self.assertRaises(FormatError):
            env.acquire(out=out)
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(), b"evidence")
        self.assertEqual(env.fake.window_writes(), [])
        rc, _, _ = env.acquire("--force", out=out)
        self.assertEqual(rc, 0)

    def test_container_conventions(self):
        env = Env(window=0x12)
        rc, out, stdout = env.acquire("--examiner", "case-7")
        with Container(out) as c:
            m = c.metadata
            self.assertIn(c.fingerprint, stdout)
            self.assertTrue(all(row["ok"] for row in c.verify()))
        self.assertEqual(m["acquisition"]["method"], "pramin")
        self.assertEqual(m["acquisition"]["status"], "complete")
        self.assertEqual(m["acquisition"]["examiner"], "case-7")
        self.assertIn("emulator only", m["acquisition"]["notes"])
        dev = m["device"]
        self.assertEqual((dev["chipset"], dev["architecture"], dev["pci_bus_id"], dev["vram_size"]),
                         ("0x197", "ada", "0000:01:00.0", 4 * MiB))
        p = m["pramin"]
        self.assertEqual((p["boot_0"], p["chip"], p["window_before"], p["window_after"]),
                         ("0x197000a1", "AD107", "0x00000012", "0x00000012"))
        self.assertTrue(p["vram_size_source"].startswith("register: NV_USABLE_FB_SIZE_IN_MB"))
        self.assertEqual(p["window_register"]["name"], "NV_PBUS_BAR0_WINDOW")
        self.assertIn("pass1_mib_per_s", p)


# -- the real accessor over an ordinary file ------------------------------------------------------------------------

class Bar0MmioTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(dir=TMP), "bar0.bin")
        self.data = bytes(range(256)) * (8 * MiB // 256) + pattern(MiB)  # 9 MiB
        with open(self.path, "wb") as fh:
            fh.write(self.data)

    def test_offsets_widths_and_bounds(self):
        m = pramin.Bar0Mmio.open(self.path)
        try:
            self.assertEqual(m.size, len(self.data))
            for off in (0, 4, 0x1700, 0x700000, len(self.data) - 4):
                self.assertEqual(m.read32(off), struct.unpack_from("<I", self.data, off)[0], hex(off))
            self.assertEqual(m.read_words(0x700000, 0x10000), self.data[0x700000:0x710000])
            self.assertEqual(m.read_bulk(0x8FF000, 0x1000), self.data[0x8FF000:0x900000])
            m.write32(0x1700, 0xDEADBEEF)
            self.assertEqual(m.read32(0x1700), 0xDEADBEEF)
            self.assertEqual(m.read_words(0x16FC, 12), self.data[0x16FC:0x1700] + struct.pack("<I", 0xDEADBEEF)
                             + self.data[0x1704:0x1708])
            for bad in ((m.read32, 2), (m.read32, len(self.data)), (m.read32, -4),
                        (m.read_words, len(self.data) - 4, 8), (m.read_words, 0, 6), (m.read_bulk, 1, 4),
                        (m.write32, 0x1701, 0), (m.write32, 0x1700, 1 << 32)):
                with self.assertRaises(ValueError):
                    bad[0](*bad[1:])
        finally:
            m.close()
        with self.assertRaises(ValueError):
            m.read32(0)
        with open(self.path, "rb") as fh:
            fh.seek(0x1700)
            self.assertEqual(fh.read(4), struct.pack("<I", 0xDEADBEEF))  # stores reach the file (MAP_SHARED)

    def test_acquisition_through_the_real_accessor(self):
        """BAR0 is an ordinary file standing in for resource0: it has no window semantics, so every window
        position shows the same aperture bytes, but the whole real path (sysfs, mmap, ctypes loads/stores,
        read-back, restore) runs."""
        env = Env(open_bar0=pramin.Bar0Mmio.open)
        res = os.path.join(env.devices["0000:01:00.0"], "resource0")
        aperture = pattern(MiB, seed=5)
        poke(res, 0x0, struct.pack("<I", (0x197 << 20) | 0xA1))
        poke(res, 0xA00, struct.pack("<I", (0x197 << 20) | 0x10000))
        poke(res, USABLE_FB_SIZE_IN_MB, struct.pack("<I", 2))
        poke(res, PBUS_BAR0_WINDOW, struct.pack("<I", 0x00000005))
        poke(res, APERTURE, aperture)
        rc, out, _ = env.acquire()
        self.assertEqual(rc, 0)
        self.assertEqual(vram_of(out), (0, aperture + aperture))
        with open(res, "rb") as fh:
            fh.seek(PBUS_BAR0_WINDOW)
            self.assertEqual(fh.read(4), struct.pack("<I", 5))  # restored
        p = meta(out)["pramin"]
        self.assertEqual((p["window_before"], p["window_after"], p["window_writes"]),
                         ("0x00000005", "0x00000005", 3))


# -- equivalence with the original image ----------------------------------------------------------------------------

class EquivalenceTests(unittest.TestCase):
    """The synthetic ground-truth VRAM image, acquired through the emulated BAR0 by the real pramin path, gives the
    same plugin output as the image itself."""

    PLUGINS = ("nvidia.chanscan", "nvidia.runlist", "nvidia.qmdscan", "nvidia.surfaces", "nvidia.pbscan")

    @classmethod
    def setUpClass(cls):
        load_plugins()
        cls.dir = tempfile.mkdtemp(dir=TMP)
        cls.files = build_all(os.path.join(cls.dir, "synth"))["files"]
        with open(cls.files["raw"], "rb") as fh:  # the very bytes of the baseline container's VRAM segment
            cls.data = fh.read()
        env = Env(vram=cls.data)
        cls.env = env
        with mock.patch.object(pramin, "default_host", lambda: env.host):  # the CLI path, on any OS
            cls.out = os.path.join(cls.dir, "pramin.keto")
            cls.rc = main(["-q", "--output-file", os.path.join(cls.dir, "stdout.txt"), "acquire", "--method",
                           "pramin", "--out", cls.out])

    def test_cli_acquisition(self):
        self.assertEqual(self.rc, 0)
        with open(os.path.join(self.dir, "stdout.txt")) as fh:
            text = fh.read()
        with Container(self.out) as c:
            self.assertIn(c.fingerprint, text)
            self.assertEqual(c.metadata["acquisition"]["status"], "complete")
        self.assertEqual(vram_of(self.out), (0, self.data))
        self.assertEqual(self.env.fake.window_raw, 0)

    def test_plugins_agree_with_the_original_image(self):
        for name in self.PLUGINS:
            with self.subTest(plugin=name):
                rows = []
                for image, sub in ((self.files["container"], "a"), (self.out, "b")):
                    with Context(image=image, output_dir=os.path.join(self.dir, sub, name)) as c:
                        grid = PLUGINS[name](c, {}).run()
                        self.assertEqual(c.profile.name, "ada")
                        rows.append([{k: v for k, v in r.items() if k != "File"} for r in grid.as_dicts()])
                self.assertTrue(rows[0], "%s found nothing in the synthetic image" % name)
                self.assertEqual(rows[0], rows[1])


class CliTests(unittest.TestCase):
    def test_options_parse(self):
        a = build_parser().parse_args(["acquire", "--method", "pramin", "--out", "x.keto", "--pci", "01:00.0",
                                       "--allow-bound-driver", "--start", "1G", "--length", "0x1000", "--passes",
                                       "3", "--bulk-mmio", "--vram-size", "8G"])
        self.assertEqual((a.pci, a.allow_bound_driver, a.start, a.length, a.passes, a.bulk_mmio, a.vram_size),
                         ("01:00.0", True, 1 << 30, 0x1000, 3, True, 8 << 30))
        a = build_parser().parse_args(["--vram-size", "4G", "acquire", "--method", "pramin", "--out", "x.keto"])
        self.assertEqual(a.vram_size, 4 << 30)  # the global option is not reset by the acquire subcommand
        a = build_parser().parse_args(["acquire", "--method", "kcore", "--out", "x.keto"])
        self.assertIsNone(a.vram_size)

    def test_cli_refusal_is_a_clean_error(self):
        env = Env(euid=1000)
        err = io.StringIO()
        with mock.patch.object(pramin, "default_host", lambda: env.host), mock.patch("sys.stderr", err):
            rc = main(["-q", "--output-file", os.path.join(env.dir, "o.txt"), "acquire", "--method", "pramin",
                       "--out", os.path.join(env.dir, "x.keto")])
        self.assertEqual(rc, 2)
        self.assertIn("needs root", err.getvalue())

    @unittest.skipIf(pramin.platform.system() == "Linux", "would inspect this machine's real sysfs")
    def test_default_host_refuses_off_linux(self):
        with self.assertRaises(RequirementError) as cm:
            pramin.check_preconditions(pramin.default_host(), None, lambda m: None)
        self.assertIn("needs Linux", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
