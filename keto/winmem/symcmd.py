"""``keto pdb``: identify, find and (explicitly) fetch the PDB a Windows module or memory image needs."""

from __future__ import annotations

import os
import sys

from keto.framework.exceptions import RequirementError
from keto.winmem import pe, symbols


def add_parser(sub):
    sp = sub.add_parser("pdb", help="find or fetch the Windows PDB/ISF symbols a kernel image or module needs")
    sp.add_argument("action", choices=("info", "find", "fetch"),
                    help="info: describe the symbols needed (or a --file); find: look in local stores; "
                         "fetch: download from the symbol server (the only Keto command that uses the network)")
    sp.add_argument("--pe", help="a PE module on disk (e.g. C:\\Windows\\System32\\ntoskrnl.exe)")
    sp.add_argument("--name", help="PDB file name, with --key (e.g. ntkrnlmp.pdb)")
    sp.add_argument("--key", help="symbol-server key: GUID followed by the age in hex")
    sp.add_argument("--symbol-file", help="with 'info': a PDB or ISF file to describe")
    sp.add_argument("--symbols-dir", action="append", default=[], help="extra local symbol directory (repeatable)")
    sp.add_argument("--dest", help="cache directory for 'fetch' (default: %s)" % symbols.default_cache())
    sp.add_argument("--server", default=symbols.SYMBOL_SERVER, help="symbol server URL for 'fetch'")
    return sp


def _identity(args):
    if args.name and args.key:
        return args.name, args.key.upper()
    if args.pe:
        cv = pe.from_file(args.pe).codeview()
        if cv is None:
            raise RequirementError("%s has no CodeView (RSDS) debug record" % args.pe)
        return cv.pdb_name, cv.key
    image, host = getattr(args, "file", None), getattr(args, "host_image", None)
    if image or host:
        from keto.framework.context import Context
        from keto.winmem.kernel import locate_codeview
        ctx = Context(image=image, host_image=host)
        try:
            cv = locate_codeview(ctx)
        finally:
            ctx.close()
        return cv.pdb_name, cv.key
    raise RequirementError("give --pe FILE, --name and --key, or a memory image with -f / --host-image")


def run(args, out) -> int:
    if args.action == "info" and args.symbol_file:
        table = symbols.load(args.symbol_file)
        out.write("file      %s\npdb       %s\nkey       %s\nmachine   %s\nsymbols   %d\n" % (
            args.symbol_file, table.pdb_name, table.key, table.machine, len(table.symbols)))
        for w in table.warnings:
            out.write("warning   %s\n" % w)
        return 0
    name, key = _identity(args)
    found = symbols.find_local(name, key, symbols.search_dirs(args.symbols_dir))
    if args.action == "info":
        out.write("pdb       %s\nkey       %s\nlocal     %s\nurl       %s/%s/%s/%s\n" % (
            name, key, found or "(not found)", args.server.rstrip("/"), name, key, name))
        return 0
    if args.action == "find":
        if not found:
            out.write("not found locally: %s %s (run 'keto pdb fetch' with the same arguments)\n" % (name, key))
            return 1
        out.write("%s\n" % found)
        return 0
    if found:
        out.write("already available: %s\n" % found)
        return 0

    def progress(n):
        sys.stderr.write("\r  %.1f MB" % (n / 1e6))
        sys.stderr.flush()

    path = symbols.fetch(name, key, dest=args.dest, server=args.server, progress=progress)
    sys.stderr.write("\n")
    out.write("stored %s (%d bytes)\n" % (path, os.path.getsize(path)))
    return 0
