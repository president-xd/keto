"""Type and symbol model shared by the PDB and ISF loaders.

A :class:`SymbolTable` maps symbol names to RVAs (relative to the module's load address) and resolves type
references lazily. A reference is a :class:`Type`, a PDB type index (``int``), a struct/union/enum name
(``str``) or a Volatility ISF type descriptor (``dict``); the loader that created the table knows how to turn
its own references into :class:`Type` objects. Member paths (``"Pcb.DirectoryTableBase"``) descend through
nested structs and unions, never through pointers.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from keto.framework.exceptions import KetoError

BASE, POINTER, ARRAY, STRUCT, UNION, ENUM, BITFIELD, FUNCTION, VOID = (
    "base", "pointer", "array", "struct", "union", "enum", "bitfield", "function", "void")


class SymbolError(KetoError):
    """A symbol file is malformed, or a symbol, type or member is missing from it."""


class Type:
    __slots__ = ("kind", "name", "size", "signed", "target", "count", "fields", "bit_pos", "bit_len",
                 "constants", "incomplete")

    def __init__(self, kind: str, name: str = "", size: int = 0, signed: bool = False, target=None,
                 count: int = 0, fields: Optional[List[Tuple[str, int, object]]] = None, bit_pos: int = 0,
                 bit_len: int = 0, constants: Optional[Dict[str, int]] = None, incomplete: bool = False):
        self.kind, self.name, self.size, self.signed, self.target = kind, name, size, signed, target
        self.count, self.fields, self.bit_pos, self.bit_len = count, fields or [], bit_pos, bit_len
        self.constants, self.incomplete = constants or {}, incomplete

    def __repr__(self):
        return "<Type %s %s size=%d>" % (self.kind, self.name or "?", self.size)


class SymbolTable:
    """Symbols and types of one module (e.g. ``ntkrnlmp.pdb``)."""

    def __init__(self, pdb_name: str = "", guid: str = "", age: int = 0, machine: str = "", source: str = ""):
        self.pdb_name, self.guid, self.age, self.machine, self.source = pdb_name, guid, age, machine, source
        self.symbols: Dict[str, int] = {}
        self.warnings: List[str] = []
        self._struct_cache: Dict[str, Type] = {}

    @property
    def key(self) -> str:
        """Symbol-server key: GUID followed by the age in hex."""
        return "%s%X" % (self.guid, self.age)

    # -- loader hooks ------------------------------------------------------------------------------------
    def _named(self, name: str) -> Optional[Type]:  # pragma: no cover - implemented by loaders
        raise NotImplementedError

    def _ref(self, ref) -> Optional[Type]:  # pragma: no cover - implemented by loaders
        raise NotImplementedError

    # -- types ---------------------------------------------------------------------------------------------
    def resolve(self, ref) -> Optional[Type]:
        if ref is None or isinstance(ref, Type):
            return ref
        if isinstance(ref, str):
            return self._named(ref)
        return self._ref(ref)

    def has_struct(self, name: str) -> bool:
        return self._named(name) is not None

    def struct(self, name: str) -> Type:
        t = self._named(name)
        if t is None:
            raise SymbolError("type %s is not in %s" % (name, self.pdb_name or self.source or "the symbol table"))
        return t

    def sizeof(self, ref) -> int:
        t = self.resolve(ref)
        return t.size if t is not None else 0

    def member(self, struct, path: str) -> Tuple[int, Type]:
        """``(byte offset, Type)`` of ``a.b.c`` inside ``struct`` (a Type or a type name). A bitfield's Type has
        kind BITFIELD with ``bit_pos``/``bit_len`` and the storage type as ``target``."""
        t = self.struct(struct) if isinstance(struct, str) else struct
        top = t.name or "<anon>"
        off = 0
        ft = t
        for part in path.split("."):
            if ft is None or ft.kind not in (STRUCT, UNION):
                raise SymbolError("%s.%s: %s is not a struct or union" % (top, path, part))
            hit = self._find_member(ft, part)
            if hit is None:
                raise SymbolError("%s has no member %s" % (top, path))
            moff, ft = hit
            off += moff
        return off, ft

    def _find_member(self, t: Type, name: str):
        for fname, foff, fref in t.fields:
            if fname == name:
                return foff, self.resolve(fref)
        for fname, foff, fref in t.fields:  # anonymous struct/union members
            if not fname or fname.startswith("<") or fname.startswith("__unnamed"):
                sub_t = self.resolve(fref)
                if sub_t is not None and sub_t.kind in (STRUCT, UNION):
                    sub = self._find_member(sub_t, name)
                    if sub is not None:
                        return foff + sub[0], sub[1]
        return None

    def offsetof(self, struct, path: str) -> int:
        off, t = self.member(struct, path)
        if t is not None and t.kind == BITFIELD:
            raise SymbolError("%s is a bitfield" % path)
        return off

    def has_member(self, struct, path: str) -> bool:
        try:
            self.member(struct, path)
            return True
        except SymbolError:
            return False

    def enum(self, name: str) -> Dict[str, int]:
        t = self.struct(name)
        if t.kind != ENUM:
            raise SymbolError("%s is not an enum" % name)
        return dict(t.constants)

    # -- symbols ---------------------------------------------------------------------------------------------
    def rva(self, name: str) -> int:
        if name not in self.symbols:
            raise SymbolError("symbol %s is not in %s" % (name, self.pdb_name or self.source))
        return self.symbols[name]

    def describe(self) -> str:
        return "%s %s (%s)" % (self.pdb_name, self.key, self.source)
