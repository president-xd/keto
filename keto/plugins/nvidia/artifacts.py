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
MAX_DIM = 32768                  # largest 2D texture / render target of any NVIDIA GPU
MAX_MANUAL_BYTES = 256 << 20     # manual-mode decode limit (an 8K BGRA frame is 127 MiB)
MIN_WIDTH = MIN_HEIGHT = 32      # auto mode: smaller "images" are tables of integers far more often than pictures
MIN_PIXELS = 4096
MAX_XRGB_ROUGHNESS = 16.0        # auto mode, alpha 0x00: neighbouring pixels of real images are similar


def pe_extent(data: bytes):
    """File size of the PE image at ``data[0]`` (headers, section table, raw section data, certificate table),
    rounded up to FileAlignment; None if ``data`` holds no PE header."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if e + 24 > len(data) or data[e:e + 4] != b"PE\x00\x00":
        return None
    nsec, opt_size = struct.unpack_from("<H", data, e + 6)[0], struct.unpack_from("<H", data, e + 20)[0]
    opt = e + 24
    sec = opt + opt_size
    end = sec + 40 * nsec
    align = 512
    if opt_size >= 64 and opt + 64 <= len(data):
        falign, headers = struct.unpack_from("<I", data, opt + 36)[0], struct.unpack_from("<I", data, opt + 60)[0]
        if 512 <= falign <= 0x10000 and not falign & (falign - 1):
            align = falign
        end = max(end, headers)
        magic = struct.unpack_from("<H", data, opt)[0]
        cert = opt + (128 if magic == 0x10B else 144)  # IMAGE_DIRECTORY_ENTRY_SECURITY (a file offset)
        if cert + 8 <= opt + opt_size and cert + 8 <= len(data):
            caddr, csize = struct.unpack_from("<II", data, cert)
            if caddr and csize:
                end = max(end, caddr + csize)
    for i in range(nsec):
        o = sec + 40 * i
        if o + 40 > len(data):
            break
        raw_size, raw_ptr = struct.unpack_from("<II", data, o + 16)
        if raw_ptr and raw_size:
            end = max(end, raw_ptr + raw_size)
    return -(-end // align) * align


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
                   "them as PNG: a screenshot of what the GPU was drawing. Also works on CUDA residual captures "
                   "(acquire --method cuda), where PA is the GPU virtual address of the captured allocation.")
    METHOD = ("Auto mode: finds 4 KiB blocks whose every 4th byte is constant 0xFF (opaque BGRA/RGBA) or 0x00 "
              "(XRGB, e.g. browser textures) while the colour bytes vary, "
              "merges runs, and finds the row width by autocorrelation of the colour bytes (any width 16..8192 px; "
              "falls back to the width that minimises vertical pixel difference); regions mapped "
              "with a non-pitch PTE kind are also tried as NVIDIA block-linear (64Bx8 GOBs, block height 1..32 "
              "GOBs) and de-tiled. Candidates smaller than 32x32 px or 4096 px, rougher than --max-smoothness "
              "vertically, or (alpha 0x00, which tables of 24-bit integers also show) rougher than 16 horizontally "
              "are dropped. Manual mode decodes --offset/--width/--height/--layout exactly (up to 32768 px per side "
              "and 256 MiB).")
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

    def _layer(self):
        """Physical VRAM, or a CUDA residual capture (layer 'residual', addressed by GPU VA)."""
        if self.ctx.vram is not None:
            return self.ctx.vram
        if "residual" in self.ctx.layers:
            return self.ctx.layers["residual"]
        return self.ctx.require_vram()  # raises the usual "needs a VRAM image" error

    def run(self):
        vram = self._layer()
        if self.opts["offset"] is not None:
            w, h, bh = self.opts["width"], self.opts["height"], self.opts["block_height"]
            if not w or not h:
                raise RequirementError("manual mode needs --width and --height")
            if not (1 <= w <= MAX_DIM and 1 <= h <= MAX_DIM):
                raise RequirementError("--width and --height must be 1..%d (the largest NVIDIA texture)" % MAX_DIM)
            if self.opts["layout"] == "blocklinear" and bh not in (1, 2, 4, 8, 16, 32):
                raise RequirementError("--block-height must be 1, 2, 4, 8, 16 or 32 GOBs")
            size = w * h * 4 if self.opts["layout"] == "pitch" else imaging.surface_size(w * 4, h, bh)
            if size > MAX_MANUAL_BYTES or not vram.minimum_address <= self.opts["offset"] <= \
                    vram.maximum_address + 1 - size:
                raise RequirementError("a %dx%d surface (%d bytes) at 0x%x does not fit in the image (limit %d MiB)"
                                       % (w, h, size, self.opts["offset"], MAX_MANUAL_BYTES >> 20))
            px = self._decode(vram.read(self.opts["offset"], size, pad=True), w, h, self.opts["layout"], bh)
            return TreeGrid(self._cols(), [(0, (Address(self.opts["offset"]), w, h, self.opts["layout"],
                                                self.opts["block_height"], round(imaging.smoothness(px, w), 2),
                                                "manual", self._owner(vram, self.opts["offset"]),
                                                self._save(px, w, h, self.opts["offset"], self.opts["layout"])))])
        return TreeGrid(self._cols(), self._auto(vram))

    def _owner(self, layer, pa):
        if layer is not self.ctx.vram:
            return "residual allocation (GPU VA)"
        return owner_of(self.ctx, pa)

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
            if w < MIN_WIDTH or h < MIN_HEIGHT or w * h < MIN_PIXELS:
                continue
            px = self._decode(data, w, h, layout, bh)
            if alpha == 0:  # XRGB: must be smooth along rows too; write opaque PNGs
                if imaging.horizontal_smoothness(px) > MAX_XRGB_ROUGHNESS:
                    continue
                px = bytes(b if i % 4 != 3 else 0xFF for i, b in enumerate(px))
            rows.append((0, (Address(pa), w, h, layout, bh, round(s, 2), "0x%02x" % alpha, self._owner(vram, pa),
                             self._save(px, w, h, pa, layout))))
        return rows


class VBios(Plugin):
    NAME = "nvidia.vbios"
    CATEGORY = "nvidia.artifacts"
    DESCRIPTION = ("Finds and parses GPU option ROM / VBIOS images (also from a 'rom' segment of the container): "
                   "vendor/device, code types, NVIDIA BIT table, VBIOS version, checksums, strings and SHA-256, and "
                   "reports structural anomalies (broken image chain, inconsistent PCIR/header fields, vendor/device "
                   "mismatch between images, data after the last image, BIT table out of bounds or disagreeing with "
                   "the sign-on version, bad checksums) and any difference from a known-good ROM or SHA-256 list "
                   "(--known-good). A modification that keeps the ROM structurally valid is only caught by "
                   "--known-good; NVIDIA's firmware signatures are not verified.")
    METHOD = ("Scans for 'PCIR' structures, finds the owning 0x55AA image (512-byte aligned, pointer at +0x18), "
              "follows the image chain via image length and last-image bit, locates the BIT table "
              "(FF B8 'BIT' 00) and reads the version from BIT token 'i'. Checks every image's PCIR (inside the "
              "image, length >= 0x18, revision 0/3), the x86 header size byte against the PCIR length, the "
              "checksum of x86 images, that all images carry image 0's vendor/device id, that the chain ends with "
              "the last-image flag, that BIT tokens lie inside the ROM, the 'i' version against the 'Version "
              "xx.xx.xx.xx.xx' sign-on string, and the 4 KiB after the last image for non-padding bytes; "
              "--known-good takes a ROM file or a text file of SHA-256 values.")
    ANALOG = "windows.mbrscan"
    REQUIREMENTS = [Requirement("known_good", str, None, "known-good ROM file, or a text file of SHA-256 values")]
    TRAILING_WINDOW = 0x1000

    def run(self):
        layers = [self.ctx.primary] + ([self.ctx.layers["rom"]] if "rom" in self.ctx.layers and
                                       self.ctx.layers["rom"] is not self.ctx.primary else [])
        known = None
        if self.opts["known_good"]:
            try:
                known = vbios.load_known_good(self.opts["known_good"])
            except OSError as exc:
                raise RequirementError("cannot read --known-good %s: %s" % (self.opts["known_good"], exc))
            if not known[0] and not known[1]:
                raise RequirementError("--known-good %s holds no SHA-256 values and no option ROM"
                                       % self.opts["known_good"])

        def rows():
            covered = []  # (layer, start, end) of chains already reported: later images are not new ROMs
            for layer in layers:
                for off, _ in scan(layer, BytesScanner(b"PCIR")):
                    for start in range(off - off % 512, max(off - 0x10000, layer.minimum_address) - 1, -512):
                        head = layer.read(start, 0x1A, pad=True)
                        if head[:2] == b"\x55\xaa" and struct.unpack_from("<H", head, 0x18)[0] == off - start:
                            break
                    else:
                        continue
                    if any(n == layer.name and s <= start < e for n, s, e in covered):
                        continue
                    available = layer.maximum_address + 1 - start
                    window = layer.read(start, min(0x100000, available), pad=True)
                    chain = vbios.parse_chain(window, 0)
                    if not chain:
                        continue
                    total = sum(img.length for img in chain) or 0x10000
                    covered.append((layer.name, start, start + total))
                    rom = window[:total]
                    version = na("no BIT table")
                    bpos = rom.find(vbios.BIT_SIG)
                    if bpos >= 0:
                        bit = vbios.parse_bit(rom, bpos)
                        if bit:
                            version = vbios.vbios_version(rom, bit, 0) or na("no 'i' token")
                    problems = vbios.anomalies(rom, chain, available)
                    if chain[-1].last and start + total <= layer.maximum_address:
                        extra = vbios.trailing_bytes(layer.read(start + total, min(self.TRAILING_WINDOW,
                                                                                   available - total), pad=True))
                        if extra:
                            problems.append("trailing data: %d non-padding byte(s) in the %d bytes after the last "
                                            "image" % (extra, self.TRAILING_WINDOW))
                    good = na("no --known-good")
                    if known is not None:
                        good, note = vbios.compare_known_good(rom, *known)
                        if not good:
                            problems.append("known-good: " + note)
                    first = chain[0]
                    yield 0, (layer.name, Address(start), total, "0x%04x:0x%04x" % (first.vendor, first.device),
                              first.vendor == 0x10DE, version, len(chain),
                              ",".join(i.code_type_name for i in chain),
                              "ok" if all(i.checksum_ok is not False for i in chain) else "BAD",
                              hashlib.sha256(rom).hexdigest(), good, "; ".join(problems) or "none",
                              " | ".join(vbios.rom_strings(rom, 4)))
        return TreeGrid([("Layer", str), ("Offset", Address), ("Size", int), ("VendorDevice", str), ("NVIDIA", bool),
                         ("Version", str), ("Images", int), ("CodeTypes", str), ("Checksum", str), ("SHA256", str),
                         ("KnownGood", bool), ("Finding", str), ("Strings", str)], rows())


class AesKeys(Plugin):
    NAME = "nvidia.aeskeys"
    CATEGORY = "nvidia.artifacts"
    DESCRIPTION = ("Finds AES-128/192/256 key schedules in GPU memory (GPU-accelerated encryption, disk or "
                   "ransomware crypto offloaded to the GPU) and recovers the keys.")
    METHOD = ("Linear prefilter: for most schedule words W[i] = W[i-Nk] ^ W[i-1], so XOR-ing each 4 MiB chunk with "
              "itself shifted by 4 and 4*Nk bytes (big-integer arithmetic) leaves zero runs exactly where schedules "
              "may start; runs of 64+ zero data bytes (which satisfy the recurrence trivially and can hold no "
              "schedule) are masked out, a regex finds the remaining runs and each candidate is verified by full key "
              "expansion, in FIPS byte order and as little-endian 32-bit words (OpenSSL-style AES_KEY). Low-entropy "
              "keys are ignored.")
    ANALOG = "windows.truecrypt (cached key recovery)"
    REQUIREMENTS = [Requirement("align", int, 4, "alignment of candidate schedules (4 = thorough, 16 = fast)"),
                    Requirement("reveal", bool, False, "print full keys (default: redacted)")]

    def run(self):
        if self.opts["align"] < 1:
            raise RequirementError("--align must be at least 1")
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

    #: patterns that only frame a value (a header or an assignment): when a typed secret (JWT, API key...) lies
    #: inside one of their hits, the typed hit is reported and the framing hit is not
    GENERIC = ("bearer-token", "password-assignment")

    @classmethod
    def _dedupe(cls, hits):
        """One row per secret: overlapping hits collapse to the typed one (else the longest)."""
        hits = sorted(hits, key=lambda h: (h[0], -len(h[2])))
        out = []
        for h in hits:
            o, name, text = h
            clash = [k for k, (o2, n2, t2) in enumerate(out) if o < o2 + len(t2) and o2 < o + len(text)]
            if not clash:
                out.append(h)
                continue
            k = clash[0]
            if out[k][1] in cls.GENERIC and name not in cls.GENERIC:
                out[k] = h
        return out

    def run(self):
        layers = [self.ctx.primary] + ([self.ctx.layers["sysmem"]] if "sysmem" in self.ctx.layers else [])

        def rows():
            for layer in layers:
                for off, data, payload in layer.iter_chunks(4 << 20, secret_ind.MAX_LEN):
                    hits = [(o, name, text) for o, name, text in secret_ind.find(data, off)
                            if o < off + payload and (not self.opts["kind"] or name == self.opts["kind"])]
                    for o, name, text in self._dedupe(hits):
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
              "directory and records offset, size and SHA-256 per file in manifest.json (for surfaces: of the PNG "
              "written). ELF images are sized from their section/program headers, PE images from their section "
              "table and certificate directory.")
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
            size = (elf_extent(window) if info["format"].startswith("ELF") else
                    pe_extent(window) if info["format"] == "PE" else None) or \
                (len(window.rstrip(b"\x00")) if len(window.rstrip(b"\x00")) < (1 << 20) else 1 << 20)
            save("hostexe_%s" % info["format"].replace(" ", ""), off, window[:max(size, 64)], "bin")
        if self.ctx.vram is not None or "residual" in self.ctx.layers:
            for r in Surfaces(self.ctx, {}).run().rows:
                vals = r[1]
                path = vals[8]  # File column (the PNG written by nvidia.surfaces)
                if isinstance(path, str):
                    with open(path, "rb") as fh:
                        png = fh.read()
                    out.append({"kind": "surface", "offset": int(vals[0]), "size": len(png),
                                "sha256": hashlib.sha256(png).hexdigest(), "file": path,
                                "width": vals[1], "height": vals[2], "layout": vals[3]})
        mpath = self.ctx.output_path("manifest.json")
        with open(mpath, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        return TreeGrid([("Kind", str), ("Offset", Address), ("Size", int), ("SHA256", str), ("File", str)],
                        [(0, (o["kind"], Address(o["offset"]), o["size"], o["sha256"], o["file"])) for o in out])
