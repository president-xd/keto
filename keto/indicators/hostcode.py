"""Host (CPU) executables and script payloads hidden in GPU memory.

GPU memory is invisible to host anti-malware scanners, which has made it a
storage location for malware payloads (e.g. the 2021 proof-of-concept sold on
underground forums that kept code in VRAM). Any host executable format or
script stager in VRAM is worth an analyst's attention.
"""

from __future__ import annotations

import re
import struct
from typing import Optional

from keto.formats.elf import EM_NAMES

PE_MACHINES = {0x14C: "i386", 0x8664: "x86-64", 0xAA64: "ARM64", 0x1C0: "ARM", 0x1C4: "ARMv7"}
MACHO_MAGICS = {b"\xcf\xfa\xed\xfe": "Mach-O 64", b"\xce\xfa\xed\xfe": "Mach-O 32", b"\xca\xfe\xba\xbe": "Mach-O fat"}

# (name, lower-case anchors, regex, look-back from anchor)
SCRIPT_PATTERNS = [
    ("powershell-encoded", [b"powershell"],
     re.compile(rb"(?i)powershell(?:\.exe)?\b[^\x00\n]{0,80}?\s-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}"), 0),
    ("powershell-download", [b"new-object"],
     re.compile(rb"(?i)(?:IEX|Invoke-Expression)\s*\(?\s*\(?New-Object\s+Net\.WebClient\)?\.Download(?:String|File)"),
     40),
    ("reverse-shell-bash", [b"/dev/tcp/"], re.compile(rb"bash -i\s*>&\s*/dev/tcp/[\w.\-]+/\d+"), 24),
    ("reverse-shell-nc", [b" -e /bin/"], re.compile(rb"\b(?:nc|ncat|netcat)\b[^\x00\n]{0,40}\s-e\s+/bin/(?:ba)?sh"), 64),
    ("python-socket-shell", [b"import socket"],
     re.compile(rb"python[23]?\s+-c\s+['\"]import socket[^\x00]{0,200}subprocess"), 24),
    ("curl-pipe-shell", [b"| sh", b"|sh", b"| bash", b"|bash"],
     re.compile(rb"(?:curl|wget)\s+[^\x00\n|]{4,200}\|\s*(?:ba)?sh\b"), 220),
    ("certutil-download", [b"certutil"], re.compile(rb"(?i)certutil(?:\.exe)?\s+-urlcache\s+-split\s+-f\s+http"), 0),
    ("mshta-rundll", [b"mshta", b"rundll32", b"regsvr32"],
     re.compile(rb"(?i)\b(?:mshta|rundll32|regsvr32)(?:\.exe)?\s+[^\x00\n]{0,40}(?:http|javascript:|scrobj)"), 0),
]

EXE_ANCHORS = [b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"]

# Position-independent shellcode idioms: PEB access to find loaded modules, and the ROR-13 API-hash loop and
# hash immediates of the widely reused Metasploit block_api (x86 and x64).
SHELLCODE_PATTERNS = [
    ("peb-walk-x86 (xor edx,edx; mov edx,fs:[edx+30h]; mov edx,[edx+0Ch])", b"\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c"),
    ("peb-walk-x64 (xor rdx,rdx; mov rdx,gs:[rdx+60h]; mov rdx,[rdx+18h])",
     b"\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18"),
    ("peb-access-x86 (mov eax,fs:[30h])", b"\x64\xa1\x30\x00\x00\x00"),
    ("peb-access-x64 (mov rax,gs:[60h])", b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"),
    ("ror13-hash-loop-x86 (ror edi,0Dh; add edi,eax)", b"\xc1\xcf\x0d\x01\xc7"),
    ("ror13-hash-loop-x64 (ror r9d,0Dh; add r9d,eax)", b"\x41\xc1\xc9\x0d\x41\x01\xc1"),
    ("api-hash LoadLibraryA x86 (push 0726774Ch)", b"\x68\x4c\x77\x26\x07"),
    ("api-hash LoadLibraryA x64 (mov r10d,0726774Ch)", b"\x41\xba\x4c\x77\x26\x07"),
]

# Filesystem / archive containers: whole file trees parked in VRAM (VRAM block devices, payload stashes)
CONTAINER_MAGICS = [
    (b"\xebR\x90NTFS    ", "NTFS boot sector", 0),
    (b"\xebv\x90EXFAT   ", "exFAT boot sector", 0),
    (b"FAT32   ", "FAT32 boot sector", 0x52),
    (b"hsqs", "squashfs superblock", 0),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", 0),
    (b"Rar!\x1a\x07", "RAR archive", 0),
    (b"MSCF\x00\x00\x00\x00", "Microsoft cabinet", 0),
    (b"\x01CD001\x01", "ISO 9660 volume descriptor", 0x8001),
    (b"PK\x03\x04", "ZIP archive", 0),
]
EXT_MAGIC_OFFSET = 0x38  # s_magic inside the ext2/3/4 superblock


def shellcode_scanner():
    from keto.framework.scanners import AnchoredScanner
    return AnchoredScanner([p for _, p in SHELLCODE_PATTERNS])


SHELLCODE_NAMES = {p: n for n, p in SHELLCODE_PATTERNS}


def container_scanner():
    from keto.framework.scanners import AnchoredScanner
    return AnchoredScanner([m for m, _, _ in CONTAINER_MAGICS])


def identify_container(magic: bytes, data: bytes) -> Optional[str]:
    """``data`` starts at the structure start (magic offset already subtracted); returns a description."""
    for m, name, off in CONTAINER_MAGICS:
        if m != magic:
            continue
        if name == "FAT32 boot sector" and data[0x1FE:0x200] != b"\x55\xaa":
            return None
        if name == "squashfs superblock" and (len(data) < 30 or struct.unpack_from("<H", data, 28)[0] != 4):
            return None
        if name == "ZIP archive":
            if len(data) < 30:
                return None
            ver, flags, method = struct.unpack_from("<HHH", data, 4)
            nlen = struct.unpack_from("<H", data, 26)[0]
            if ver > 63 or flags & 0xF000 or method not in (0, 8, 9, 12, 14, 93, 95, 98, 99) or not 0 < nlen < 1024:
                return None
            fname = data[30:30 + nlen]
            if not fname or any(c < 0x20 for c in fname):
                return None
            return "%s (first entry %s)" % (name, fname.decode("utf-8", "replace"))
        if name == "NTFS boot sector" and data[0x1FE:0x200] != b"\x55\xaa":
            return None
        return name
    return None


def is_ext_superblock(sb: bytes) -> Optional[str]:
    """Validate an ext2/3/4 superblock (``sb`` = 1024 bytes from the superblock start)."""
    if len(sb) < 0x100 or struct.unpack_from("<H", sb, 0x38)[0] != 0xEF53:
        return None
    inodes, blocks = struct.unpack_from("<II", sb, 0)
    log_bs = struct.unpack_from("<I", sb, 0x18)[0]
    state = struct.unpack_from("<H", sb, 0x3A)[0]
    rev = struct.unpack_from("<I", sb, 0x4C)[0]
    if not (inodes and blocks and log_bs <= 6 and 1 <= state <= 7 and rev in (0, 1)):
        return None
    incompat = struct.unpack_from("<I", sb, 0x60)[0] if rev else 0
    kind = "ext4" if incompat & 0x40 else ("ext3" if struct.unpack_from("<I", sb, 0x5C)[0] & 0x4 else "ext2")
    label = sb[0x78:0x88].split(b"\x00", 1)[0].decode("utf-8", "replace")
    return "%s superblock, %d blocks of %d bytes%s" % (kind, blocks, 1024 << log_bs,
                                                       ", label %r" % label if label else "")


def script_scanners():
    from keto.framework.scanners import AnchoredScanner
    return [(name, AnchoredScanner(anchors, rx, before=back, after=600, ignore_case=True))
            for name, anchors, rx, back in SCRIPT_PATTERNS]


def exe_scanner():
    from keto.framework.scanners import AnchoredScanner
    return AnchoredScanner(EXE_ANCHORS)


def identify_executable(data: bytes) -> Optional[dict]:
    """Return a description if ``data`` starts with a host executable header."""
    if data[:4] == b"\x7fELF" and len(data) >= 20:
        machine = struct.unpack_from("<H", data, 18)[0]
        if machine == 190:  # EM_CUDA: GPU code, handled by the cubin plugins
            return None
        etype = struct.unpack_from("<H", data, 16)[0]
        if etype not in (1, 2, 3, 4) or machine not in EM_NAMES:
            return None
        return {"format": "ELF%d" % (64 if data[4] == 2 else 32), "machine": EM_NAMES[machine],
                "type": {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}[etype]}
    if data[:2] == b"MZ" and len(data) >= 0x40:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if 0x40 <= e_lfanew < len(data) - 6 and e_lfanew < 0x1000 and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
            machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
            return {"format": "PE", "machine": PE_MACHINES.get(machine, "0x%x" % machine), "type": "image"}
        return None
    if data[:4] in MACHO_MAGICS:
        if data[:4] == b"\xca\xfe\xba\xbe":
            n = struct.unpack_from(">I", data, 4)[0]
            if not 0 < n < 8:  # Java class files share this magic
                return None
        return {"format": MACHO_MAGICS[data[:4]], "machine": "-", "type": "image"}
    return None
