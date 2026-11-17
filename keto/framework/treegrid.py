"""TreeGrid: the tabular/tree result every plugin returns (as in Volatility 3).

A TreeGrid is a list of typed columns plus rows of ``(depth, values)``. Depth
lets a plugin express parent/child relationships (pstree-style output) while
remaining flat for CSV/JSON consumers.
"""

from __future__ import annotations

import datetime as _dt
from typing import Iterable, List, Sequence, Tuple


class Hex(int):
    """An integer rendered as hex (offsets, raw register values)."""

    def __new__(cls, value):
        return int.__new__(cls, value)


class Address(Hex):
    """A memory address (physical or GPU virtual)."""


class Bytes(bytes):
    """Raw bytes rendered as a hexdump in text renderers, hex in JSON/CSV."""


class Disassembly(str):
    """Multi-line text block (disassembly, hexdump, decoded commands)."""


class NotAvailableValue:
    """A value that could not be obtained, with a short reason."""

    __slots__ = ("reason",)

    def __init__(self, reason: str = "N/A"):
        self.reason = reason

    def __repr__(self):
        return "NotAvailableValue(%r)" % self.reason

    def __str__(self):
        if self.reason == "":
            return "-"
        return "N/A" if self.reason == "N/A" else "N/A (%s)" % self.reason

    def __eq__(self, other):
        return isinstance(other, NotAvailableValue)

    def __hash__(self):
        return 0


NA = NotAvailableValue()


def na(reason: str) -> NotAvailableValue:
    return NotAvailableValue(reason)


class TreeGrid:
    def __init__(self, columns: Sequence[Tuple[str, type]], rows: Iterable[Tuple[int, Sequence]]):
        self.columns: List[Tuple[str, type]] = list(columns)
        self._rows = rows
        self._materialised = None

    @property
    def rows(self) -> List[Tuple[int, tuple]]:
        if self._materialised is None:
            out = []
            ncol = len(self.columns)
            for depth, values in self._rows:
                values = tuple(values)
                if len(values) != ncol:
                    raise ValueError("row has %d values, grid has %d columns: %r" % (len(values), ncol, values))
                out.append((depth, values))
            self._materialised = out
        return self._materialised

    def column_index(self, name: str) -> int:
        for i, (n, _) in enumerate(self.columns):
            if n == name:
                return i
        raise KeyError(name)

    def as_dicts(self) -> List[dict]:
        names = [c for c, _ in self.columns]
        return [dict(zip(names, vals), __depth=d) for d, vals in self.rows]

    def __len__(self):
        return len(self.rows)


def to_plain(value):
    """Convert a cell to a JSON-friendly primitive."""
    if isinstance(value, NotAvailableValue):
        return None
    if isinstance(value, Bytes):
        return value.hex()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, (list, tuple)):
        return [to_plain(v) for v in value]
    if isinstance(value, dict):
        return {str(k): to_plain(v) for k, v in value.items()}
    return value
