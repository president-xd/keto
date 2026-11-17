"""Output renderers: quick (default), pretty, csv, json, jsonl, none."""

from __future__ import annotations

import csv
import datetime as _dt
import io
import json
from typing import Dict, Type

from keto.framework.treegrid import (Address, Bytes, Disassembly, Hex, NotAvailableValue, TreeGrid,
                                          to_plain)
from keto.framework.util import hexdump


def format_cell(value, multiline: bool = True) -> str:
    if value is None:
        return "-"
    if isinstance(value, NotAvailableValue):
        return str(value)
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (Address, Hex)):
        return "0x%x" % int(value)
    if isinstance(value, Bytes):
        if multiline:
            return "\n" + hexdump(value)
        return bytes(value).hex()
    if isinstance(value, Disassembly):
        return ("\n" + value) if multiline else value.replace("\n", " | ")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            return value.isoformat(sep=" ")
        return value.astimezone(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f UTC")
    if isinstance(value, float):
        return "%.3f" % value
    if isinstance(value, (list, tuple)):
        return ",".join(format_cell(v, False) for v in value)
    if isinstance(value, dict):
        return ";".join("%s=%s" % (k, format_cell(v, False)) for k, v in value.items())
    return str(value)


class Renderer:
    name = "abstract"

    def render(self, grid: TreeGrid, out) -> None:
        raise NotImplementedError


class QuickTextRenderer(Renderer):
    """Tab separated, tree depth shown with leading ``*`` (Volatility style)."""

    name = "quick"

    def render(self, grid, out):
        out.write("\t".join(c for c, _ in grid.columns) + "\n\n")
        for depth, values in grid.rows:
            prefix = ("*" * depth + " ") if depth else ""
            cells = [format_cell(v) for v in values]
            out.write(prefix + "\t".join(cells) + "\n")


class PrettyRenderer(Renderer):
    """Aligned columns; multi-line cells (hexdumps, disassembly) printed below the row."""

    name = "pretty"

    def render(self, grid, out):
        headers = [c for c, _ in grid.columns]
        table, extras = [], []
        for depth, values in grid.rows:
            row, extra = [], []
            for (name, _), v in zip(grid.columns, values):
                text = format_cell(v, multiline=True)
                if "\n" in text:
                    extra.append((name, text.strip("\n")))
                    text = "<see below>"
                row.append(text)
            if depth:
                row[0] = "*" * depth + " " + row[0]
            table.append(row)
            extras.append(extra)
        widths = [len(h) for h in headers]
        for row in table:
            for i, cell in enumerate(row):
                widths[i] = min(max(widths[i], len(cell)), 80)
        sep = "+".join("-" * (w + 2) for w in widths)
        out.write(" | ".join(h.ljust(w) for h, w in zip(headers, widths)) + "\n")
        out.write(sep + "\n")
        for row, extra in zip(table, extras):
            out.write(" | ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() + "\n")
            for name, text in extra:
                out.write("    [%s]\n" % name)
                for line in text.splitlines():
                    out.write("    " + line + "\n")


class CSVRenderer(Renderer):
    name = "csv"

    def render(self, grid, out):
        w = csv.writer(out, lineterminator="\n")
        w.writerow(["TreeDepth"] + [c for c, _ in grid.columns])
        for depth, values in grid.rows:
            w.writerow([depth] + [format_cell(v, multiline=False) for v in values])


class JSONRenderer(Renderer):
    name = "json"

    def render(self, grid, out):
        names = [c for c, _ in grid.columns]
        rows = []
        for depth, values in grid.rows:
            d = {"__depth": depth}
            for n, v in zip(names, values):
                d[n] = to_plain(v)
            rows.append(d)
        json.dump(rows, out, indent=2, default=str)
        out.write("\n")


class JSONLinesRenderer(Renderer):
    name = "jsonl"

    def render(self, grid, out):
        names = [c for c, _ in grid.columns]
        for depth, values in grid.rows:
            d = {"__depth": depth}
            d.update({n: to_plain(v) for n, v in zip(names, values)})
            out.write(json.dumps(d, default=str) + "\n")


class NoneRenderer(Renderer):
    name = "none"

    def render(self, grid, out):
        _ = grid.rows  # force evaluation (side effects such as dumping files)


RENDERERS: Dict[str, Type[Renderer]] = {r.name: r for r in
                                        (QuickTextRenderer, PrettyRenderer, CSVRenderer, JSONRenderer,
                                         JSONLinesRenderer, NoneRenderer)}


def render_to_string(grid: TreeGrid, renderer: str = "quick") -> str:
    buf = io.StringIO()
    RENDERERS[renderer]().render(grid, buf)
    return buf.getvalue()
