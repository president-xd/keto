"""GPFIFO entries and pushbuffer (command stream) decoding.

Header format (``NVC56F_DMA_*``)::

    SEC_OP 31:29  1 INC_METHOD  3 NON_INC_METHOD  4 IMMD_DATA_METHOD  5 ONE_INC
                  0 GRP0_USE_TERT (TERT_OP 17:16)  2 GRP2_USE_TERT  7 END_PB_SEGMENT
    COUNT / IMMD_DATA 28:16   SUBCHANNEL 15:13   METHOD_ADDRESS 11:0 (dword address)

GPFIFO entry (``NVC56F_GP_ENTRY*``)::

    ENTRY0: FETCH 0, GET 31:2           ENTRY1: GET_HI 7:0, LEVEL 9, LENGTH 30:10 (dwords), SYNC 31
            (LENGTH == 0 -> control entry, OPCODE 7:0)

The ``CommandInterpreter`` turns raw methods into forensic events: engine class
bindings, copy-engine DMA transfers, compute kernel launches (QMD addresses),
semaphore operations, interrupts and inline-to-memory uploads.
"""

from __future__ import annotations

import re
import struct
from typing import Dict, Iterator, List, Optional

SEC_OPS = {0: "GRP0", 1: "INC", 2: "GRP2", 3: "NON_INC", 4: "IMMD", 5: "ONE_INC", 6: "RESERVED", 7: "END_SEG"}
SEM_EXEC_OPS = {0: "ACQUIRE", 1: "RELEASE", 2: "ACQ_STRICT_GEQ", 3: "ACQ_CIRC_GEQ", 4: "ACQ_AND",
                5: "ACQ_NOR", 6: "REDUCTION"}
CE_TRANSFER = {0: "NONE", 1: "PIPELINED", 2: "NON_PIPELINED"}
CE_SEMAPHORE = {0: "NONE", 1: "RELEASE_ONE_WORD", 2: "RELEASE_FOUR_WORD", 3: "RELEASE_CONDITIONAL_INTR"}
CE_INTERRUPT = {0: "NONE", 1: "BLOCKING", 2: "NON_BLOCKING"}
CE_PHYS_TARGET = {0: "LOCAL_FB", 1: "COHERENT_SYSMEM", 2: "NONCOHERENT_SYSMEM", 3: "PEERMEM"}


class GpEntry:
    __slots__ = ("index", "va", "length", "level", "sync", "fetch", "opcode", "raw")

    def __init__(self, index, e0, e1):
        self.index = index
        self.raw = (e0, e1)
        self.fetch = e0 & 1
        self.va = (e0 & 0xFFFFFFFC) | ((e1 & 0xFF) << 32)
        self.level = "SUBROUTINE" if (e1 >> 9) & 1 else "MAIN"
        self.length = (e1 >> 10) & 0x1FFFFF
        self.sync = "WAIT" if e1 >> 31 else "PROCEED"
        self.opcode = (e1 & 0xFF) if self.length == 0 else None

    @property
    def is_control(self):
        return self.length == 0

    @property
    def nbytes(self):
        return self.length * 4


def decode_gpfifo(data: bytes, entries: Optional[int] = None) -> List[GpEntry]:
    n = len(data) // 8 if entries is None else min(entries, len(data) // 8)
    out = []
    for i in range(n):
        e0, e1 = struct.unpack_from("<II", data, i * 8)
        out.append(GpEntry(i, e0, e1))
    return out


def encode_gp_entry(va: int, length_dwords: int, sync: bool = False, subroutine: bool = False) -> bytes:
    e0 = va & 0xFFFFFFFC
    e1 = ((va >> 32) & 0xFF) | (int(subroutine) << 9) | ((length_dwords & 0x1FFFFF) << 10) | (int(sync) << 31)
    return struct.pack("<II", e0, e1)


class Method:
    __slots__ = ("offset", "subch", "method", "value", "op")

    def __init__(self, offset, subch, method, value, op):
        self.offset, self.subch, self.method, self.value, self.op = offset, subch, method, value, op

    def __repr__(self):
        return "<Method @0x%x sc%d 0x%04x=0x%08x %s>" % (self.offset, self.subch, self.method, self.value, self.op)


class DecodeStats:
    def __init__(self):
        self.headers = 0
        self.methods = 0
        self.invalid = 0
        self.end_segment = False


def decode_methods(data: bytes, base: int = 0, stats: Optional[DecodeStats] = None,
                   stop_on_invalid: bool = True, max_count: int = 8191) -> Iterator[Method]:
    """Decode a pushbuffer into individual method writes."""
    st = stats or DecodeStats()
    n = len(data) // 4
    words = struct.unpack_from("<%dI" % n, data) if n else ()
    i = 0
    while i < n:
        hdr = words[i]
        off = base + i * 4
        sec = hdr >> 29
        subch = (hdr >> 13) & 7
        addr = (hdr & 0xFFF) << 2
        count = (hdr >> 16) & 0x1FFF
        i += 1
        if hdr == 0:
            st.headers += 1  # NOP header (padding)
            continue
        st.headers += 1
        if sec in (1, 3, 5):
            if count == 0 or count > max_count or i + count > n:
                st.invalid += 1
                if stop_on_invalid:
                    return
                continue
            for k in range(count):
                if sec == 1:
                    m = addr + 4 * k
                elif sec == 3:
                    m = addr
                else:
                    m = addr if k == 0 else addr + 4
                st.methods += 1
                yield Method(base + (i + k) * 4, subch, m, words[i + k], SEC_OPS[sec])
            i += count
        elif sec == 4:
            st.methods += 1
            yield Method(off, subch, addr, count, "IMMD")
        elif sec == 0:
            tert = (hdr >> 16) & 3
            if tert == 0:  # legacy incrementing method: count 28:18, address 12:2
                lcount = (hdr >> 18) & 0x7FF
                laddr = hdr & 0x1FFC
                if lcount == 0 or i + lcount > n:
                    st.invalid += 1
                    if stop_on_invalid:
                        return
                    continue
                for k in range(lcount):
                    st.methods += 1
                    yield Method(base + (i + k) * 4, subch, laddr + 4 * k, words[i + k], "INC_OLD")
                i += lcount
            # tert 1..3: sub-device mask operations, no payload
        elif sec == 2:
            lcount = (hdr >> 18) & 0x7FF
            laddr = hdr & 0x1FFC
            if lcount == 0 or i + lcount > n:
                st.invalid += 1
                if stop_on_invalid:
                    return
                continue
            for k in range(lcount):
                st.methods += 1
                yield Method(base + (i + k) * 4, subch, laddr, words[i + k], "NON_INC_OLD")
            i += lcount
        elif sec == 7:
            st.end_segment = True
            return
        else:
            st.invalid += 1
            if stop_on_invalid:
                return


def encode_methods(subch: int, method: int, values: List[int], op: str = "INC") -> bytes:
    secs = {"INC": 1, "NON_INC": 3, "ONE_INC": 5}
    if op == "IMMD":
        hdr = (4 << 29) | ((values[0] & 0x1FFF) << 16) | (subch << 13) | (method >> 2)
        return struct.pack("<I", hdr)
    hdr = (secs[op] << 29) | (len(values) << 16) | (subch << 13) | (method >> 2)
    return struct.pack("<I%dI" % len(values), hdr, *values)


class Event:
    __slots__ = ("kind", "offset", "subch", "class_id", "details")

    def __init__(self, kind, offset, subch, class_id, details):
        self.kind, self.offset, self.subch, self.class_id, self.details = kind, offset, subch, class_id, details

    def __repr__(self):
        return "<Event %s @0x%x %r>" % (self.kind, self.offset, self.details)


class CommandInterpreter:
    """Stateful interpreter producing high-level events from a method stream."""

    def __init__(self, classdb, bindings: Optional[Dict[int, int]] = None):
        self.classdb = classdb
        self.bind: Dict[int, int] = dict(bindings or {})  # subchannel -> class id
        self.state: Dict[int, Dict[int, int]] = {}
        self._inline: Optional[dict] = None
        self.host = {}

    def family(self, subch: int) -> Optional[str]:
        return self.classdb.family(self.bind.get(subch))

    def method_name(self, m: Method) -> str:
        return self.classdb.method_name(self.family(m.subch), m.method)

    def _flush_inline(self) -> Optional[Event]:
        inl, self._inline = self._inline, None
        if inl and inl["data"]:
            data = b"".join(struct.pack("<I", v) for v in inl["data"])
            return Event("inline", inl["offset"], inl["subch"], inl["class_id"],
                         {"dst": inl["dst"], "length": inl["length"], "data": data[: inl["length"] or len(data)]})
        return None

    def feed(self, m: Method) -> Iterator[Event]:
        fam = self.family(m.subch)
        st = self.state.setdefault(m.subch, {})
        cid = self.bind.get(m.subch)
        if self._inline and not (m.method == 0x1B4 and fam in ("compute", "i2m") and m.subch == self._inline["subch"]):
            ev = self._flush_inline()
            if ev:
                yield ev
        # --- host methods (any subchannel, method < 0x100) ---
        if m.method < 0x100:
            if m.method == 0x0000:
                new_id = m.value & 0xFFFF
                self.bind[m.subch] = new_id
                yield Event("bind", m.offset, m.subch, new_id,
                            {"class": self.classdb.class_name(new_id), "family": self.classdb.family(new_id),
                             "engine_id": (m.value >> 16) & 0x1F})
                return
            self.host[m.method] = m.value
            if m.method == 0x006C:  # SEM_EXECUTE (Volta+): OPERATION 2:0, PAYLOAD_SIZE 24, RELEASE_TIMESTAMP 25
                addr = ((self.host.get(0x60, 0) & 0x1FFFFFF) << 32) | (self.host.get(0x5C, 0) & 0xFFFFFFFC)
                payload = self.host.get(0x64, 0) | (self.host.get(0x68, 0) << 32)
                op = SEM_EXEC_OPS.get(m.value & 7, "op%d" % (m.value & 7))
                yield Event("semaphore", m.offset, m.subch, cid,
                            {"engine": "host", "op": op, "address": addr, "payload": payload, "raw": m.value,
                             "payload_bits": 64 if m.value >> 24 & 1 else 32,
                             "timestamped": op in ("RELEASE", "REDUCTION") and bool(m.value >> 25 & 1)})
            elif m.method == 0x001C:  # SEMAPHORED (pre-Volta): OPERATION 4:0, RELEASE_SIZE 24 (0 = 16 byte)
                addr = ((self.host.get(0x10, 0) & 0xFF) << 32) | (self.host.get(0x14, 0) & 0xFFFFFFFC)
                op = {1: "ACQUIRE", 2: "RELEASE", 4: "ACQ_GEQ", 8: "ACQ_AND", 0x10: "REDUCTION"}.get(
                    m.value & 0x1F, "op0x%x" % (m.value & 0x1F))
                yield Event("semaphore", m.offset, m.subch, cid,
                            {"engine": "host-legacy", "op": op, "address": addr, "payload": self.host.get(0x18, 0),
                             "raw": m.value, "payload_bits": 32,
                             "timestamped": op == "RELEASE" and not m.value >> 24 & 1})
            elif m.method == 0x0020:
                yield Event("interrupt", m.offset, m.subch, cid, {"engine": "host", "type": "NON_STALL_INTERRUPT",
                                                                  "handle": m.value})
            return
        st[m.method] = m.value
        if fam == "copy" and m.method == 0x0300:
            yield self._copy_event(m, st, cid)
        elif fam == "compute" and m.method == 0x02B4:
            # Kepler..Pascal QMDs hold a 32-bit PROGRAM_OFFSET relative to SET_PROGRAM_REGION_A/B (0x1608 7:0 /
            # 0x160c); the region is latched per subchannel and carried with the launch
            region = None
            if 0x160C in st or 0x1608 in st:
                region = ((st.get(0x1608, 0) & 0xFF) << 32) | st.get(0x160C, 0)
            yield Event("launch", m.offset, m.subch, cid, {"qmd_va": m.value << 8, "signaling": st.get(0x02BC),
                                                           "program_region": region})
        elif fam in ("compute", "i2m") and m.method == 0x01B0:
            dst = ((st.get(0x188, 0) & 0x1FFFF) << 32) | st.get(0x18C, 0)
            self._inline = {"offset": m.offset, "subch": m.subch, "class_id": cid, "dst": dst,
                            "length": st.get(0x180, 0) * max(st.get(0x184, 1), 1), "data": []}
        elif fam in ("compute", "i2m") and m.method == 0x01B4 and self._inline:
            self._inline["data"].append(m.value)
        elif fam == "compute" and m.method == 0x1B0C:
            addr = ((st.get(0x1B00, 0) & 0x1FFFFFF) << 32) | st.get(0x1B04, 0)
            op = {0: "RELEASE", 3: "TRAP"}.get(m.value & 3, "op%d" % (m.value & 3))
            ev = Event("semaphore", m.offset, m.subch, cid,
                       {"engine": "compute", "op": op, "address": addr, "payload": st.get(0x1B08, 0), "raw": m.value,
                        "awaken": bool(m.value >> 20 & 1), "payload_bits": 32,
                        # SET_REPORT_SEMAPHORE_D_STRUCTURE_SIZE 28:28: FOUR_WORDS 0 (payload + timestamp)
                        "timestamped": op == "RELEASE" and not m.value >> 28 & 1})
            yield ev
            if ev.details["awaken"]:
                yield Event("interrupt", m.offset, m.subch, cid, {"engine": "compute", "type": "AWAKEN",
                                                                  "handle": addr})

    def _copy_event(self, m: Method, st: Dict[int, int], cid) -> Event:
        v = m.value
        multi = bool(v >> 9 & 1)
        src = ((st.get(0x400, 0) & 0x1FFFF) << 32) | st.get(0x404, 0)
        dst = ((st.get(0x408, 0) & 0x1FFFF) << 32) | st.get(0x40C, 0)
        line = st.get(0x418, 0)
        lines = st.get(0x41C, 1) if multi else 1
        d = {"src": src, "dst": dst, "line_length": line, "line_count": lines, "bytes": line * lines,
             "pitch_in": st.get(0x410), "pitch_out": st.get(0x414),
             "transfer": CE_TRANSFER.get(v & 3, "?"), "flush": bool(v >> 2 & 1),
             "semaphore": CE_SEMAPHORE[(v >> 3) & 3], "interrupt": CE_INTERRUPT.get((v >> 5) & 3, "?"),
             "src_layout": "PITCH" if v >> 7 & 1 else "BLOCKLINEAR",
             "dst_layout": "PITCH" if v >> 8 & 1 else "BLOCKLINEAR",
             "remap": bool(v >> 10 & 1),
             "src_type": "PHYSICAL" if v >> 12 & 1 else "VIRTUAL",
             "dst_type": "PHYSICAL" if v >> 13 & 1 else "VIRTUAL", "raw": v}
        if d["src_type"] == "PHYSICAL":
            d["src_target"] = CE_PHYS_TARGET[st.get(0x260, 0) & 3]
        if d["dst_type"] == "PHYSICAL":
            d["dst_target"] = CE_PHYS_TARGET[st.get(0x264, 0) & 3]
        if d["semaphore"] != "NONE":
            d["semaphore_address"] = ((st.get(0x240, 0) & 0x1FFFFFF) << 32) | st.get(0x244, 0)
            d["semaphore_payload"] = st.get(0x248, 0) | (st.get(0x24C, 0) << 32)
            # SEMAPHORE_TYPE 2 = RELEASE_FOUR_WORD_SEMAPHORE / RELEASE_SEMAPHORE_WITH_TIMESTAMP (C7B5+ alias)
            d["semaphore_timestamped"] = (v >> 3) & 3 == 2
        return Event("copy", m.offset, m.subch, cid, d)

    def finish(self) -> Iterator[Event]:
        ev = self._flush_inline()
        if ev:
            yield ev


def interpret(data: bytes, base: int, classdb, bindings: Optional[Dict[int, int]] = None,
              stats: Optional[DecodeStats] = None):
    """Decode + interpret a buffer. Returns ``(methods, events, interpreter)``."""
    ci = CommandInterpreter(classdb, bindings)
    methods, events = [], []
    for m in decode_methods(data, base, stats):
        methods.append(m)
        events.extend(ci.feed(m))
    events.extend(ci.finish())
    return methods, events, ci


# SET_OBJECT written with an INC/NON_INC/ONE_INC header of count 1 to method 0:
#   header = sec<<29 | 1<<16 | subch<<13 | 0  followed by a 16-bit class id.
SET_OBJECT_RE = re.compile(rb"\x00[\x00\x20\x40\x60\x80\xa0\xc0\xe0]\x01[\x20\x60\xa0](..)[\x00-\x1f]\x00",
                           re.DOTALL)


def score_stream(data: bytes, base: int, classdb) -> dict:
    """Heuristic quality of a candidate pushbuffer region (for raw scanning)."""
    st = DecodeStats()
    ci = CommandInterpreter(classdb)
    known = total = 0
    events = 0
    for m in decode_methods(data, base, st):
        total += 1
        events += sum(1 for _ in ci.feed(m))
        if not ci.method_name(m).startswith("0x"):
            known += 1
    return {"methods": total, "known": known, "invalid": st.invalid, "events": events,
            "ratio": (known / total) if total else 0.0, "end_segment": st.end_segment}
