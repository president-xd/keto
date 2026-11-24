"""Volatility 3 Intermediate Symbol Format (ISF) reader, so existing Volatility Windows symbol packs work.

An ISF file is JSON (optionally .xz / .gz / .bz2): ``base_types`` {name: {size, signed, kind}}, ``user_types``
{name: {kind: struct|union|class, size, fields: {name: {offset, type}}}}, ``enums`` {name: {size, base,
constants}}, ``symbols`` {name: {address}} (RVAs for Windows tables) and ``metadata.windows.pdb`` {GUID, age,
database, machine_type}. A type descriptor is ``{"kind": "base"|"pointer"|"array"|"struct"|"union"|"class"|
"enum"|"bitfield"|"function", ...}`` with ``subtype``, ``count``, ``name``, ``bit_position``, ``bit_length`` and
``type`` as applicable (volatility3 ``schemas/schema-6.2.0.json``).
"""

from __future__ import annotations

import bz2
import gzip
import json
import lzma
import os
from typing import Dict, Optional

from keto.winmem.symtab import (ARRAY, BASE, BITFIELD, ENUM, FUNCTION, POINTER, STRUCT, UNION, VOID, SymbolError,
                                SymbolTable, Type)


class IsfSymbols(SymbolTable):
    def __init__(self, doc: dict, source: str = ""):
        super().__init__(source=source)
        if not isinstance(doc, dict) or "user_types" not in doc:
            raise SymbolError("%s is not an ISF symbol file (no user_types)" % (source or "document"))
        meta = (doc.get("metadata") or {}).get("windows", {}).get("pdb", {}) or {}
        self.pdb_name = meta.get("database", "")
        self.guid = (meta.get("GUID") or "").replace("-", "").upper()
        self.age = int(meta.get("age") or 0)
        self.machine = {0x8664: "x64", 0x14C: "x86", 0xAA64: "arm64"}.get(meta.get("machine_type"), "")
        self._base = doc.get("base_types") or {}
        self._user = doc.get("user_types") or {}
        self._enums = doc.get("enums") or {}
        self._ptr = int((self._base.get("pointer") or {}).get("size", 8))
        for name, sym in (doc.get("symbols") or {}).items():
            if isinstance(sym, dict) and "address" in sym:
                self.symbols[name] = int(sym["address"])
        self._cache: Dict[str, Type] = {}

    def _named(self, name: str) -> Optional[Type]:
        if name in self._cache:
            return self._cache[name]
        u = self._user.get(name)
        if u is not None:
            kind = UNION if u.get("kind") == "union" else STRUCT
            t = Type(kind, name=name, size=int(u.get("size", 0)))
            self._cache[name] = t  # before fields: self-referential types
            t.fields = [(fname, int(f.get("offset", 0)), f.get("type")) for fname, f in (u.get("fields") or {}).items()]
            return t
        e = self._enums.get(name)
        if e is not None:
            base = self._base.get(e.get("base", "int")) or {}
            t = Type(ENUM, name=name, size=int(e.get("size", 4)), signed=bool(base.get("signed", True)),
                     constants={k: int(v) for k, v in (e.get("constants") or {}).items()})
            self._cache[name] = t
            return t
        return None

    def _ref(self, desc) -> Optional[Type]:
        if not isinstance(desc, dict):
            raise SymbolError("bad ISF type descriptor %r" % (desc,))
        kind = desc.get("kind")
        if kind == "base":
            name = desc.get("name", "")
            b = self._base.get(name)
            if b is None:
                raise SymbolError("ISF base type %s missing" % name)
            size = int(b.get("size", 0))
            return Type(VOID if b.get("kind") == "void" or size == 0 else BASE, name=name, size=size,
                        signed=bool(b.get("signed", False)))
        if kind == "pointer":
            return Type(POINTER, size=self._ptr, target=desc.get("subtype"))
        if kind == "array":
            count = int(desc.get("count", 0))
            sub = desc.get("subtype")
            return Type(ARRAY, size=count * self.sizeof(sub), target=sub, count=count)
        if kind in ("struct", "union", "class", "enum"):
            t = self._named(desc.get("name", ""))
            if t is None:
                raise SymbolError("ISF type %s missing" % desc.get("name"))
            return t
        if kind == "bitfield":
            sub = desc.get("type")
            return Type(BITFIELD, size=self.sizeof(sub), target=sub, bit_pos=int(desc.get("bit_position", 0)),
                        bit_len=int(desc.get("bit_length", 0)))
        if kind == "function":
            return Type(FUNCTION)
        raise SymbolError("unknown ISF type kind %r" % kind)


def load(path: str) -> IsfSymbols:
    opener = {".xz": lzma.open, ".gz": gzip.open, ".bz2": bz2.open}.get(os.path.splitext(path)[1].lower(), open)
    try:
        with opener(path, "rt", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (ValueError, OSError, EOFError, lzma.LZMAError) as e:
        raise SymbolError("cannot read ISF file %s: %s" % (path, e))
    return IsfSymbols(doc, source=path)
