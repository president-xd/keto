"""Artefact recovery: images/surfaces, VBIOS, cryptographic keys, credentials, bulk extraction."""

from __future__ import annotations

import hashlib
import json
import struct

from keto.formats import aes, imaging, vbios
from keto.framework.exceptions import RequirementError
from keto.framework.plugin import Plugin, Requirement
from keto.framework.scanners import BytesScanner, scan
from keto.framework.treegrid import Address, TreeGrid, na
from keto.gpu import discovery
from keto.gpu.gmmu import VID, coalesce
from keto.indicators import secrets as secret_ind
from keto.plugins.nvidia.code import CubinDump

COMMON_WIDTHS = [64, 96, 128, 160, 192, 256, 320, 384, 480, 512, 640, 720, 768, 800, 1024, 1080, 1152, 1280, 1366,
                 1440, 1600, 1680, 1920, 2048, 2560, 2880, 3440, 3840, 4096]


def owner_of(ctx, pa):
    try:
        hits = discovery.reverse_lookup_all(ctx, pa)
    except Exception:
        hits = []
    return "; ".join("%s:0x%x" % (a.name, va) for a, va, _ in hits) or "unmapped"


class Surfaces(Plugin):
    NAME = "nvidia.surfaces"
    CATEGORY = "nvidia.artifacts"
    DESCRIPTION = ("Recovers images from VRAM (framebuffers, render targets, textures, video frames) and writes "
                   "them as PNG: a screenshot of what the GPU was drawing.")
    METHOD = ("Auto mode: finds 4 KiB blocks whose every 4th byte is constant 0xFF (opaque BGRA/RGBA) or 0x00 "
              "(XRGB, e.g. browser textures) while the colour bytes vary, "
              "merges runs, and picks the row width that minimises vertical pixel difference; regions mapped "
              "with a non-pitch PTE kind are also tried as NVIDIA block-linear (64Bx8 GOBs, block height 1..32 "
              "GOBs) and de-tiled. Manual mode decodes --offset/--width/--height/--layout exactly.")
    ANALOG = "linux.graphics.fbdev / windows.windows (GUI recovery)"
    REQUIREMENTS = [Requirement("offset", "address", None, "manual: physical offset of the surface"),
                    Requirement("width", int, None, "manual: width in pixels"),
                    Requirement("height", int, None, "manual: height in pixels"),
                    Requirement("layout", str, "pitch", "manual: pitch or blocklinear", choices=("pitch", "blocklinear")),
                    Requirement("block_height", int, 16, "manual: block height in GOBs (1,2,4,8,16,32)"),
                    Requirement("format", str, "bgra", "pixel order", choices=("bgra", "rgba")),
                    Requirement("max_smoothness", float, 40.0, "auto: reject candidates rougher than this")]

    def _decode(self, raw, width, height, layout, bh):
        if layout == "blocklinear":
            raw = imaging.deswizzle(raw, width * 4, height, bh)
        return raw[:width * height * 4]

    def _save(self, pixels, width, height, pa, layout):
        if not self.ctx.output_dir:
            return na("no -o given")
        rgba = imaging.bgra_to_rgba(pixels) if self.opts["format"] == "bgra" else pixels
        path = self.ctx.output_path("surface_%x_%dx%d_%s.png" % (pa, width, height, layout))
        imaging.write_png(path, width, height, rgba)
        return path

    def run(self):
        vram = self.ctx.require_vram()
        if self.opts["offset"] is not None:
            w, h = self.opts["width"], self.opts["height"]
            if not w or not h:
                raise RequirementError("manual mode needs --width and --height")
            size = w * h * 4 if self.opts["layout"] == "pitch" else imaging.surface_size(w * 4, h, self.opts["block_height"])
            px = self._decode(vram.read(self.opts["offset"], size, pad=True), w, h, self.opts["layout"],
                              self.opts["block_height"])
            return TreeGrid(self._cols(), [(0, (Address(self.opts["offset"]), w, h, self.opts["layout"],
                                                self.opts["block_height"], round(imaging.smoothness(px, w), 2),
                                                "manual", owner_of(self.ctx, self.opts["offset"]),
                                                self._save(px, w, h, self.opts["offset"], self.opts["layout"])))])
        return TreeGrid(self._cols(), self._auto(vram))

    @staticmethod
    def _cols():
        return [("PA", Address), ("Width", int), ("Height", int), ("Layout", str), ("BlockHeight", int),
                ("Smoothness", float), ("Alpha", str), ("MappedAt", str), ("File", str)]

    def _candidates(self, vram):
        blk = 0x1000
        tiled = {}
        try:
            for a in discovery.address_spaces(self.ctx):
                for r in coalesce(a.mappings()):
                    if r["first"].aperture == VID and r["first"].kind:
                        for page in range(r["pa"], r["pa"] + r["size"], blk):
                            tiled[page] = r["size"]
        except Exception:
            pass
        runs, cur = [], None
        for start, length in vram.ranges():
            for off in range(start, start + length, blk):
                d = vram.read(off, blk, pad=True)
                a = self._alpha_kind(d)
                if a is not None:
                    if cur and cur[1] == off and cur[2] == a:
                        cur[1] = off + blk
                    else:
                        cur = [off, off + blk, a]
                        runs.append(cur)
                else:
                    cur = None
        return [(s, e - s, tiled.get(s), a) for s, e, a in runs if e - s >= 0x2000]

    @staticmethod
    def _alpha_kind(d: bytes):
        """0xFF (opaque) or 0x00 (XRGB) when every 4th byte holds that constant and the colour bytes vary."""
        alpha = d[3::4]
        if d.count(0xFF) >= len(d) * 0.9 or d.count(0) >= len(d) * 0.9:
            return None
        if alpha.count(0xFF) >= len(alpha) * 0.9:
            return 0xFF
        if alpha.count(0) >= len(alpha) * 0.9:
            colour = bytes(b for i, b in enumerate(d) if i % 4 != 3)
            # XRGB needs real colour content: many distinct values, not small integers padded with zeros
            if len(set(colour)) >= 32 and colour.count(0) < len(colour) * 0.5:
                return 0x00
        return None

    def _auto(self, vram):
        rows = []
        for pa, size, tiled_size, alpha in self._candidates(vram):
            data = vram.read(pa, size, pad=True)
            best = None
            w = imaging.guess_width(data[:min(len(data), 4096 * 4 * 64)])
            if w:
                s = imaging.smoothness(data, w, rows=64)
                best = (s, w, "pitch", 0)
            if tiled_size is not None:
                for bh in (1, 2, 4, 8, 16, 32):
                    for cw in COMMON_WIDTHS:
                        rows_needed = 8 * bh * 2
                        if cw * 4 * rows_needed > size:
                            continue
                        px = imaging.deswizzle(data[:imaging.surface_size(cw * 4, rows_needed, bh)], cw * 4,
                                               rows_needed, bh)
                        s = imaging.smoothness(px, cw, rows=rows_needed - 1)
                        if best is None or s < best[0] - 0.5:
                            best = (s, cw, "blocklinear", bh)
            if best is None or best[0] > self.opts["max_smoothness"]:
                continue
            s, w, layout, bh = best
            h = size // (w * 4) if layout == "pitch" else max(8 * bh, (size // imaging.surface_size(w * 4, 8 * bh, bh))
                                                              * 8 * bh)
            if layout == "blocklinear":
                while h > 8 * bh and imaging.surface_size(w * 4, h, bh) > size:
                    h -= 8 * bh
            px = self._decode(data, w, h, layout, bh)
            if alpha == 0:  # XRGB: write opaque PNGs
                px = bytes(b if i % 4 != 3 else 0xFF for i, b in enumerate(px))
            rows.append((0, (Address(pa), w, h, layout, bh, round(s, 2), "0x%02x" % alpha, owner_of(self.ctx, pa),
                             self._save(px, w, h, pa, layout))))
        return rows


class VBios(Plugin):
    NAME = "nvidia.vbios"
    CATEGORY = "nvidia.artifacts"
    DESCRIPTION = ("Finds and parses GPU option ROM / VBIOS images (also from a 'rom' segment of the container): "
                   "vendor/device, code types, NVIDIA BIT table, VBIOS version, checksums, strings and SHA-256 - "
                   "for firmware-implant (GPU bootkit) hunting.")
    METHOD = ("Scans for 'PCIR' structures, finds the owning 0x55AA image (512-byte aligned, pointer at +0x18), "
              "follows the image chain via image length and last-image bit, locates the BIT table "
              "(FF B8 'BIT' 00) and reads the version from BIT token 'i'.")
    ANALOG = "windows.mbrscan"

    def run(self):
        layers = [self.ctx.primary] + ([self.ctx.layers["rom"]] if "rom" in self.ctx.layers and
                                       self.ctx.layers["rom"] is not self.ctx.primary else [])

        def rows():
            seen = set()
            for layer in layers:
                for off, _ in scan(layer, BytesScanner(b"PCIR")):
                    for start in range(off - off % 512, max(off - 0x10000, layer.minimum_address) - 1, -512):
                        head = layer.read(start, 0x1A, pad=True)
                        if head[:2] == b"\x55\xaa" and struct.unpack_from("<H", head, 0x18)[0] == off - start:
                            break
                    else:
                        continue
                    if (layer.name, start) in seen:
                        continue
                    seen.add((layer.name, start))
                    window = layer.read(start, 0x100000, pad=True)
                    chain = vbios.parse_chain(window, 0)
                    if not chain:
                        continue
                    total = sum(img.length for img in chain) or 0x10000
                    rom = window[:total]
                    version = na("no BIT table")
                    bpos = rom.find(vbios.BIT_SIG)
                    if bpos >= 0:
                        bit = vbios.parse_bit(rom, bpos)
                        if bit:
                            version = vbios.vbios_version(rom, bit, 0) or na("no 'i' token")
                    first = chain[0]
                    yield 0, (layer.name, Address(start), total, "0x%04x:0x%04x" % (first.vendor, first.device),
                              first.vendor == 0x10DE, version, len(chain),
                              ",".join(i.code_type_name for i in chain),
                              "ok" if all(i.checksum_ok is not False for i in chain) else "BAD",
                              hashlib.sha256(rom).hexdigest(), " | ".join(vbios.rom_strings(rom, 4)))
        return TreeGrid([("Layer", str), ("Offset", Address), ("Size", int), ("VendorDevice", str), ("NVIDIA", bool),
                         ("Version", str), ("Images", int), ("CodeTypes", str), ("Checksum", str), ("SHA256", str),
                         ("Strings", str)], rows())


class AesKeys(Plugin):
    NAME = "nvidia.aeskeys"
    CATEGORY = "nvidia.artifacts"
    DESCRIPTION = ("Finds AES-128/192/256 key schedules in GPU memory (GPU-accelerated encryption, disk or "
                   "ransomware crypto offloaded to the GPU) and recovers the keys.")
    METHOD = ("At every --align offset, checks the AES key-expansion recurrence for the first derived word, "
              "then verifies the whole schedule; both FIPS byte order and little-endian 32-bit word order "
              "(OpenSSL-style AES_KEY) are tried; zero/low-entropy pages are skipped.")
    ANALOG = "windows.truecrypt (cached key recovery)"
    REQUIREMENTS = [Requirement("align", int, 4, "alignment of candidate schedules (4 = thorough, 16 = fast)"),
                    Requirement("reveal", bool, False, "print full keys (default: redacted)")]

    def run(self):
        layer = self.ctx.primary

        def rows():
            seen = set()
            for off, data, payload in layer.iter_chunks(4 << 20, 256):
                for o, bits, order, key in aes.find_key_schedules(data, off, self.opts["align"]):
                    if o >= off + payload or o in seen:
                        continue
                    seen.add(o)
                    k = key.hex()
                    yield 0, (Address(o), bits, order, k if self.opts["reveal"] else secret_ind.redact(k, 6),
                              owner_of(self.ctx, o))
        return TreeGrid([("Offset", Address), ("Bits", int), ("ByteOrder", str), ("Key", str), ("MappedAt", str)],
                        rows())


class Secrets(Plugin):
    NAME = "nvidia.secrets"
    CATEGORY = "nvidia.artifacts"
    DESCRIPTION = ("Finds credentials and secrets that ended up in GPU memory: private keys, cloud/API tokens, "
                   "JWTs, password hashes, password assignments. Redacted unless --reveal.")
    METHOD = ("Runs a curated set of credential regexes (PEM blocks, AWS/GitHub/Slack/Google key formats, JWT, "
              "crypt(3) and pwdump hashes, bearer headers) over the primary layer and any host image, and maps "
              "each hit to the GPU address spaces that map it.")
    ANALOG = "windows.registry.hashdump / lsadump / cachedump"
    REQUIREMENTS = [Requirement("reveal", bool, False, "print secrets unredacted"),
                    Requirement("kind", str, None, "only this pattern name")]

    def run(self):
        layers = [self.ctx.primary] + ([self.ctx.layers["sysmem"]] if "sysmem" in self.ctx.layers else [])

        def rows():
            for layer in layers:
                for off, data, payload in layer.iter_chunks(4 << 20, secret_ind.MAX_LEN):
                    for o, name, text in secret_ind.find(data, off):
                        if o >= off + payload or (self.opts["kind"] and name != self.opts["kind"]):
                            continue
                        shown = text if self.opts["reveal"] else secret_ind.redact(text.replace("\n", " "), 6)
                        yield 0, (layer.name, Address(o), name, len(text), shown[:160],
                                  owner_of(self.ctx, o) if layer.name == "vram" else "-")
        return TreeGrid([("Layer", str), ("Offset", Address), ("Kind", str), ("Length", int), ("Value", str),
                         ("MappedAt", str)], rows())


class DumpFiles(Plugin):
    NAME = "nvidia.dumpfiles"
    CATEGORY = "nvidia.artifacts"
    DESCRIPTION = ("Extracts every recoverable object in one pass: cubins, decompressed fatbin entries, PTX, "
                   "VBIOS images, host executables, and recovered surfaces, with a manifest.json of hashes.")
    METHOD = ("Re-uses the cubin/fatbin/PTX/VBIOS/host-code/surface scanners, writes each object to the output "
              "directory and records offset, size and SHA-256 per file in manifest.json.")
    ANALOG = "windows.dumpfiles"

    def run(self):
        from keto.formats.elf import elf_extent
        from keto.indicators.hostcode import exe_scanner, identify_executable
        out = []

        def save(kind, off, data, ext):
            path = self.ctx.output_path("%s_%x.%s" % (kind, off, ext))
            with open(path, "wb") as fh:
                fh.write(data)
            out.append({"kind": kind, "offset": off, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                        "file": path})

        for r in CubinDump(self.ctx, {}).run().rows:
            kind, off, size, digest, path = r[1]
            out.append({"kind": kind, "offset": int(off), "size": size, "sha256": digest, "file": path})
        for r in VBios(self.ctx, {}).run().rows:
            layer_name, off, size = r[1][0], int(r[1][1]), r[1][2]
            save("vbios", off, self.ctx.layers[layer_name].read(off, size, pad=True), "rom")
        layer = self.ctx.primary
        for off, _ in scan(layer, exe_scanner()):
            head = layer.read(off, 0x1000, pad=True)
            info = identify_executable(head)
            if not info:
                continue
            window = layer.read(off, 1 << 20, pad=True)
            size = (elf_extent(window) if info["format"].startswith("ELF") else None) or \
                (len(window.rstrip(b"\x00")) if len(window.rstrip(b"\x00")) < (1 << 20) else 1 << 20)
            save("hostexe_%s" % info["format"].replace(" ", ""), off, window[:max(size, 64)], "bin")
        if self.ctx.vram is not None:
            for r in Surfaces(self.ctx, {}).run().rows:
                vals = r[1]
                if isinstance(vals[7], str):
                    out.append({"kind": "surface", "offset": int(vals[0]), "size": vals[1] * vals[2] * 4,
                                "sha256": "-", "file": vals[7]})
        mpath = self.ctx.output_path("manifest.json")
        with open(mpath, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        return TreeGrid([("Kind", str), ("Offset", Address), ("Size", int), ("SHA256", str), ("File", str)],
                        [(0, (o["kind"], Address(o["offset"]), o["size"], o["sha256"], o["file"])) for o in out])
