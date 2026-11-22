"""GPU VBIOS / PCI option ROM parsing (bootkit/firmware-implant hunting).

* PCI expansion ROM images: ``0x55AA`` signature, pointer at +0x18 to a ``PCIR``
  data structure (vendor/device id, class code, image length in 512-byte units,
  code type, last-image indicator).
* NVIDIA BIT table: ``FF B8 'B' 'I' 'T' 00`` header followed by tokens
  ``{u8 id, u8 version, u16 size, u16 offset}``. Token ``'i'`` holds the VBIOS
  version (printed as bytes 3.2.1.0.4, the format ``nvidia-smi`` shows).
"""

from __future__ import annotations

import hashlib
import re
import struct
from typing import List, Optional

CODE_TYPES = {0: "x86 PC-AT", 1: "Open Firmware", 2: "PA-RISC", 3: "EFI", 0x70: "NVIDIA (vendor)"}
BIT_SIG = b"\xff\xb8BIT\x00"


class RomImage:
    def __init__(self, offset: int, length: int, vendor: int, device: int, class_code: int, code_type: int,
                 last: bool, revision: int, checksum_ok: Optional[bool], pcir: int = 0, pcir_length: int = 0x18,
                 header_size: int = 0):
        self.offset, self.length, self.vendor, self.device = offset, length, vendor, device
        self.class_code, self.code_type, self.last, self.revision = class_code, code_type, last, revision
        self.checksum_ok = checksum_ok
        self.pcir, self.pcir_length, self.header_size = pcir, pcir_length, header_size

    @property
    def code_type_name(self):
        return CODE_TYPES.get(self.code_type, "type 0x%x" % self.code_type)


def parse_image(data: bytes, off: int) -> Optional[RomImage]:
    if data[off:off + 2] != b"\x55\xaa" or off + 0x1A > len(data):
        return None
    pcir = off + struct.unpack_from("<H", data, off + 0x18)[0]
    if pcir + 0x18 > len(data) or data[pcir:pcir + 4] != b"PCIR":
        return None
    vendor, device = struct.unpack_from("<HH", data, pcir + 4)
    pcir_length = struct.unpack_from("<H", data, pcir + 0x0A)[0]
    revision = data[pcir + 0x0C]
    class_code = data[pcir + 0x0D] | (data[pcir + 0x0E] << 8) | (data[pcir + 0x0F] << 16)
    length = struct.unpack_from("<H", data, pcir + 0x10)[0] * 512
    code_type = data[pcir + 0x14]
    last = bool(data[pcir + 0x15] & 0x80)
    checksum_ok = None
    if code_type == 0 and length and off + length <= len(data):
        checksum_ok = sum(data[off:off + length]) % 256 == 0
    return RomImage(off, length, vendor, device, class_code, code_type, last, revision, checksum_ok,
                    pcir - off, pcir_length, data[off + 2] * 512)


def parse_chain(data: bytes, off: int, max_images: int = 8) -> List[RomImage]:
    out = []
    pos = off
    for _ in range(max_images):
        img = parse_image(data, pos)
        if img is None:
            break
        out.append(img)
        if img.last or not img.length:
            break
        pos += img.length
    return out


class BitTable:
    def __init__(self, offset: int, version: int, tokens: List[dict]):
        self.offset, self.version, self.tokens = offset, version, tokens


def parse_bit(data: bytes, off: int) -> Optional[BitTable]:
    if data[off:off + 6] != BIT_SIG or off + 12 > len(data):
        return None
    version, hsize, tsize, count, _ = struct.unpack_from("<HBBBB", data, off + 6)
    if tsize < 6 or count == 0 or count > 64:
        return None
    tokens = []
    pos = off + hsize
    for _ in range(count):
        if pos + 6 > len(data):
            break
        tid, tver, size, toff = struct.unpack_from("<BBHH", data, pos)
        tokens.append({"id": chr(tid) if 0x20 < tid < 0x7F else "0x%02x" % tid, "version": tver, "size": size,
                       "offset": toff})
        pos += tsize
    return BitTable(off, version, tokens)


def vbios_version(data: bytes, bit: BitTable, image_base: int) -> Optional[str]:
    for t in bit.tokens:
        if t["id"] == "i" and t["size"] >= 5:
            o = image_base + t["offset"]
            if o + 5 <= len(data):
                d = data[o:o + 5]
                return "%02X.%02X.%02X.%02X.%02X" % (d[3], d[2], d[1], d[0], d[4])
    return None


def rom_strings(data: bytes, limit: int = 40) -> List[str]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{8,}", data):
        s = m.group().decode("ascii").strip()
        if s:
            out.append(s)
        if len(out) >= limit:
            break
    return out


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


#: the sign-on banner of NVIDIA ROMs repeats the BIT version ("Version 95.07.2D.00.5F")
SIGNON_VERSION_RE = re.compile(rb"Version ([0-9A-Fa-f]{2}(?:\.[0-9A-Fa-f]{2}){4})\b")


def anomalies(rom: bytes, chain: List[RomImage], available: int, max_images: int = 8) -> List[str]:
    """Structural inconsistencies of an option-ROM image chain. ``rom`` holds the chain from its first image;
    ``available`` is how many bytes of memory exist from there (an image may not extend past it)."""
    out = []
    first = chain[0]
    for i, img in enumerate(chain):
        if not img.length:
            out.append("chain: image %d has length 0" % i)
        elif img.offset + img.length > available:
            out.append("chain: image %d (%d bytes) extends past the end of memory" % (i, img.length))
        if (img.length and img.pcir + 0x18 > img.length) or img.pcir_length < 0x18 or img.revision not in (0, 3):
            out.append("chain: image %d PCIR malformed (at +0x%x, length 0x%x, revision %d)"
                       % (i, img.pcir, img.pcir_length, img.revision))
        if img.code_type == 0 and img.length and img.header_size != img.length:
            out.append("chain: image %d header size %d != PCIR image length %d" % (i, img.header_size, img.length))
        if img.checksum_ok is False:
            out.append("checksum BAD in image %d" % i)
        if img.vendor != first.vendor:
            out.append("vendor mismatch: image %d is %04x:%04x, image 0 %04x:%04x"
                       % (i, img.vendor, img.device, first.vendor, first.device))
        elif img.device != first.device:
            out.append("device mismatch: image %d is %04x:%04x, image 0 %04x:%04x"
                       % (i, img.vendor, img.device, first.vendor, first.device))
    if not chain[-1].last and chain[-1].length:
        out.append("chain: %s" % ("more than %d images" % max_images if len(chain) >= max_images else
                                  "image %d is not flagged last but no valid image follows" % (len(chain) - 1)))
    bpos = rom.find(BIT_SIG)
    bit = parse_bit(rom, bpos) if bpos >= 0 else None
    if first.vendor == 0x10DE and bpos < 0:
        out.append("BIT: no BIT table in an NVIDIA ROM")
    elif bpos >= 0 and bit is None:
        out.append("BIT: malformed header at +0x%x" % bpos)
    elif bit is not None:
        outside = [t["id"] for t in bit.tokens if t["size"] and t["offset"] + t["size"] > len(rom)]
        if outside:
            out.append("BIT: token(s) %s point outside the ROM" % ", ".join(outside))
        version = vbios_version(rom, bit, 0)
        if version is None and first.vendor == 0x10DE:
            out.append("BIT: no version ('i') token")
        signon = {m.group(1).decode().upper() for m in SIGNON_VERSION_RE.finditer(rom)}
        if version and signon and version not in signon:
            out.append("BIT: version %s but the sign-on banner says %s" % (version, ", ".join(sorted(signon))))
    return out


def trailing_bytes(after: bytes) -> int:
    """Non-padding (not 0x00 / 0xFF) bytes in the memory that follows the last image."""
    return len(after) - after.count(0) - after.count(0xFF)


_SHA256_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")


def load_known_good(path: str):
    """``(hashes, roms)`` from ``path``: a text file of SHA-256 values (``<sha256> [label]`` per line, '#' comments)
    or a ROM file (its image chain, wherever the first 0x55AA image with a PCIR structure starts)."""
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    hashes = {}
    if text is not None and "\x00" not in text:
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            m = _SHA256_RE.search(line)
            if m:
                hashes[m.group(1).lower()] = line[m.end():].strip() or path
        if hashes:
            return hashes, []
    roms = []
    for m in re.finditer(rb"\x55\xaa", data):
        chain = parse_chain(data, m.start())
        if chain:
            total = sum(i.length for i in chain)
            roms.append((path, data[m.start():m.start() + total]))
            break
    return hashes, roms


def compare_known_good(rom: bytes, hashes: dict, roms: list):
    """``(matches, note)``: whether ``rom`` equals a known-good image, and where it first differs otherwise."""
    h = digest(rom)
    if h in hashes:
        return True, "matches %s" % hashes[h]
    for label, ref in roms:
        if ref == rom:
            return True, "matches %s" % label
    notes = []
    for label, ref in roms:
        diff = next((i for i, (a, b) in enumerate(zip(rom, ref)) if a != b), min(len(rom), len(ref)))
        notes.append("differs from %s at +0x%x (%d vs %d bytes)" % (label, diff, len(rom), len(ref)))
    if hashes and not roms:
        notes.append("SHA-256 not in the known-good list")
    return False, "; ".join(notes)


def build_rom(vendor: int = 0x10DE, device: int = 0x28A1, version=(0x95, 0x07, 0x2D, 0x00, 0x5F),
              strings=(b"NVIDIA Corp", b"GeForce RTX 4050 Laptop GPU VGA BIOS")) -> bytes:
    """A small, structurally valid option ROM with a BIT table (synthetic tests)."""
    rom = bytearray(0x1000)
    rom[0:2] = b"\x55\xaa"
    rom[2] = len(rom) // 512
    struct.pack_into("<H", rom, 0x18, 0x40)
    rom[0x40:0x44] = b"PCIR"
    struct.pack_into("<HH", rom, 0x44, vendor, device)
    struct.pack_into("<H", rom, 0x4A, 0x18)
    rom[0x4D:0x50] = bytes((0x00, 0x00, 0x03))  # VGA compatible controller
    struct.pack_into("<H", rom, 0x50, len(rom) // 512)
    rom[0x54] = 0x00
    rom[0x55] = 0x80
    pos = 0x100
    for s in strings:
        rom[pos:pos + len(s)] = s
        pos += len(s) + 16
    bit = 0x200
    rom[bit:bit + 6] = BIT_SIG
    struct.pack_into("<HBBBB", rom, bit + 6, 0x0100, 12, 6, 2, 0)
    struct.pack_into("<BBHH", rom, bit + 12, ord("i"), 1, 5, 0x300)
    struct.pack_into("<BBHH", rom, bit + 18, ord("B"), 1, 4, 0x320)
    v = version
    rom[0x300:0x305] = bytes((v[3], v[2], v[1], v[0], v[4]))
    rom[-1] = (-sum(rom[:-1])) % 256
    return bytes(rom)
