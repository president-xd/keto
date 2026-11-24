"""``keto``: the Keto command line (modelled on Volatility's ``vol``).

    keto -f image.keto nvidia.chanscan
    keto -f vram.raw -p ada -r pretty nvidia.mappings --pid ...
    keto --live nvidia.pslist
    keto list
    keto acquire --method snapshot -o triage.keto
    keto synth -o demo/
"""

from __future__ import annotations

import argparse
import io
import logging
import os
import sys
import time
from typing import List, Optional

from keto import __version__
from keto.framework.exceptions import KetoError
from keto.framework.plugin import PLUGINS, load_plugins
from keto.framework.renderers import RENDERERS
from keto.framework.util import parse_size

BANNER = "Keto %s - GPU memory forensics (NVIDIA)" % __version__
SPECIAL = ("list", "acquire", "synth", "report", "sigma", "shell", "pdb")


def _convert(kind):
    if kind in (int, "address"):
        return lambda s: int(s, 0)
    if kind == "size":
        return parse_size
    if kind is float:
        return float
    return str


def _add_output_options(parser):
    """Output options are accepted before the plugin name (global) and after it; SUPPRESS keeps a value given
    before the plugin name when the plugin's parser does not see the option."""
    parser.add_argument("-r", "--renderer", choices=sorted(RENDERERS), default=argparse.SUPPRESS)
    parser.add_argument("-o", "--output-dir", default=argparse.SUPPRESS,
                        help="directory for files written by plugins (dumps, PNGs, reports)")
    parser.add_argument("--output-file", default=argparse.SUPPRESS,
                        help="write the rendered result to this file instead of stdout")
    parser.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS,
                        help="no banner / progress on stderr")
    parser.add_argument("-v", "--verbose", action="count", default=argparse.SUPPRESS)


def plugin_aliases():
    """Unambiguous short names (``chanscan`` for ``nvidia.chanscan``) -> full plugin names."""
    counts = {}
    for name in PLUGINS:
        counts.setdefault(name.rsplit(".", 1)[-1], []).append(name)
    return {short: names[0] for short, names in counts.items()
            if len(names) == 1 and short != names[0] and short not in SPECIAL and short not in PLUGINS}


def build_parser() -> argparse.ArgumentParser:
    load_plugins()
    from keto.framework.profiles import registry
    p = argparse.ArgumentParser(prog="keto", description=BANNER, allow_abbrev=False,
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog="Run 'keto list' to see every plugin with what it does and how.")
    p.add_argument("-f", "--file", help="memory image: .keto container, raw VRAM dump, or LiME file")
    p.add_argument("--live", action="store_true", help="query the running system (NVML, CUDA, /proc, /sys)")
    p.add_argument("--snapshot", help="replay a live snapshot JSON instead of the running system")
    p.add_argument("--host-image", help="host RAM image (raw/LiME/.keto) used to resolve sysmem-aperture mappings")
    p.add_argument("-p", "--profile", help="architecture profile (%s); default: detected from the evidence"
                   % ", ".join(sorted(registry([]).profiles)))
    p.add_argument("--profile-dir", action="append", default=[], help="extra directory of profile JSON files")
    p.add_argument("--vram-size", type=parse_size, help="override the VRAM size used for sanity checks")
    p.add_argument("--workers", type=int, default=None,
                   help="processes for scanning large images (default: up to 8 cores; 0 or 1 = single process)")
    p.add_argument("--big-page", type=parse_size, choices=[64 << 10, 128 << 10], metavar="{64K,128K}",
                   help="big page size for VER1 page tables (Kepler keeps it in a register, not in memory; "
                        "default: the instance block's setting, or 128K on Kepler)")
    p.add_argument("--pdb", action="append", default=[], type=lambda s: int(s, 0),
                   help="add a page directory base (physical address) to analyse as an address space")
    p.add_argument("--reference", action="append", default=[],
                   help="reference binary/cubin/fatbin whose kernels are used for code identification")
    p.add_argument("-r", "--renderer", default="quick", choices=sorted(RENDERERS))
    p.add_argument("-o", "--output-dir", help="directory for files written by plugins (dumps, PNGs, reports)")
    p.add_argument("--output-file", help="write the rendered result to this file instead of stdout")
    p.add_argument("-v", "--verbose", action="count", default=0, help="more logging; -v also prints tracebacks")
    p.add_argument("-q", "--quiet", action="store_true", help="no banner / progress on stderr")
    p.add_argument("--version", action="version", version=BANNER)
    sub = p.add_subparsers(dest="command", metavar="<plugin>")

    lp = sub.add_parser("list", help="list plugins")
    lp.add_argument("--category")
    lp.add_argument("--details", action="store_true", help="include the METHOD (how) text")
    _add_output_options(lp)

    from keto.acquire.cli import add_acquire_parser
    add_acquire_parser(sub)
    sp = sub.add_parser("synth", help="build a synthetic NVIDIA VRAM image with ground truth (demo / tests)")
    sp.add_argument("-o", "--out", required=True, help="output directory")
    sp.add_argument("--real-cubin", help="also embed this real cubin (e.g. one JIT-compiled by your driver)")
    rp = sub.add_parser("report", help="run every applicable detector and write report.json + report.html "
                                       "(severity, MITRE ATT&CK) to -o/--output-dir")
    rp.add_argument("--baseline", help="kernel baseline JSON used by the artifact/process sweeps")
    rp.add_argument("--image-only", action="store_true", help="skip live detectors even if live state is available")
    _add_output_options(rp)
    sg = sub.add_parser("sigma", help="write the Sigma rules for host-observable GPU abuse (ATT&CK-tagged) as YAML")
    sg.add_argument("--out", required=True, help="output directory")
    sh = sub.add_parser("shell", help="interactive Python shell with the analysis context loaded")
    sh.add_argument("--command", dest="shell_command", help="run this Python statement instead of an interactive shell")
    from keto.winmem.symcmd import add_parser as add_symbols_parser
    add_symbols_parser(sub)

    def esc(text):  # argparse %-formats help strings (and validates them on Python >= 3.14)
        return str(text).replace("%", "%%")

    aliases = {}
    for short, full in plugin_aliases().items():
        aliases.setdefault(full, []).append(short)
    for name in sorted(PLUGINS):
        cls = PLUGINS[name]
        sp = sub.add_parser(name, aliases=aliases.get(name, []), help=esc(cls.DESCRIPTION.split(". ")[0][:100]),
                            description="%s\n\nHow: %s\nVolatility analogue: %s" % (cls.DESCRIPTION, cls.METHOD,
                                                                                     cls.ANALOG or "-"),
                            formatter_class=argparse.RawDescriptionHelpFormatter)
        for r in cls.REQUIREMENTS:
            kw = {"help": esc(r.help + (" (default: %s)" % r.default if r.default not in (None, False) else ""))}
            if r.kind is bool:
                # default None: an option left out keeps the plugin's own default instead of forcing False
                kw.update(action="store_true", default=None)
                if r.default is True:
                    sp.add_argument("--no-" + r.flag[2:], dest=r.name, action="store_false", default=None,
                                    help=esc("do not " + r.help[:1].lower() + r.help[1:]))
            else:
                kw["type"] = _convert(r.kind)
                if r.choices:
                    kw["choices"] = r.choices
                if r.multiple:
                    kw["action"] = "append"
            sp.add_argument(r.flag, dest=r.name, **kw)
        _add_output_options(sp)
    return p


def make_context(args):
    from keto.framework.context import Context
    for ref in args.reference or []:  # checked before anything is opened
        if not os.path.isfile(ref):
            raise KetoError("--reference file not found: %s" % ref)
    ctx = Context(image=args.file, live=args.live, host_image=args.host_image, profile=args.profile,
                  output_dir=args.output_dir, profile_dirs=args.profile_dir, snapshot=args.snapshot,
                  vram_size=args.vram_size)
    if args.pdb:
        ctx.cache["extra_pdbs"] = list(args.pdb)
    if args.big_page:
        ctx.cache["big_page_override"] = args.big_page
    if getattr(args, "workers", None) is not None:
        os.environ["KETO_WORKERS"] = str(args.workers)
    if args.reference:
        ctx.cache["reference_files"] = list(args.reference)
    return ctx


def cmd_list(args, out):
    from keto.framework.treegrid import TreeGrid
    rows = []
    for name in sorted(PLUGINS):
        cls = PLUGINS[name]
        if args.category and not cls.CATEGORY.startswith(args.category):
            continue
        vals = [name, cls.CATEGORY, "/".join(cls.SOURCES), cls.ANALOG or "-", cls.DESCRIPTION]
        if args.details:
            vals.append(cls.METHOD)
        rows.append((0, vals))
    cols = [("Plugin", str), ("Category", str), ("Needs", str), ("Volatility analogue", str), ("What it does", str)]
    if args.details:
        cols.append(("How it does it", str))
    RENDERERS[args.renderer if args.renderer != "quick" else "pretty"]().render(TreeGrid(cols, rows), out)
    out.write("\n%d plugins\n" % len(rows))
    return 0


def cmd_synth(args, out):
    from keto.testing.synth import build_all
    manifest = build_all(args.out, real_cubin=args.real_cubin)
    out.write("synthetic evidence written to %s\n" % os.path.abspath(args.out))
    for k, v in manifest["files"].items():
        out.write("  %-10s %s\n" % (k, v))
    return 0


def cmd_shell(args, out):
    ctx = make_context(args)
    from keto.gpu import discovery
    ns = {"ctx": ctx, "discovery": discovery, "PLUGINS": PLUGINS}

    def run(name, **opts):
        from keto.framework.plugin import get_plugin
        from keto.framework.renderers import render_to_string
        print(render_to_string(get_plugin(name)(ctx, opts).run(), "pretty"))

    ns["run"] = run
    if args.shell_command:
        exec(args.shell_command, ns)  # noqa: S102 - analyst-supplied statement, local shell
        return 0
    import code
    code.interact(banner=BANNER + "\nobjects: ctx (Context), discovery, run('nvidia.chanscan')", local=ns)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # never die on a console that cannot encode a character
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    args.command = plugin_aliases().get(args.command, args.command)
    level = logging.WARNING - 10 * min(args.verbose or 0, 2)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    try:
        out = open(args.output_file, "w", encoding="utf-8", newline="") if args.output_file else sys.stdout
    except OSError as exc:
        sys.stderr.write("error: cannot write --output-file %s: %s\n" % (args.output_file, exc.strerror or exc))
        return 2
    try:
        if args.command is None:
            parser.print_help()
            return 1
        if args.command == "list":
            return cmd_list(args, out)
        if args.command == "synth":
            return cmd_synth(args, out)
        if args.command == "shell":
            return cmd_shell(args, out)
        if args.command == "report":
            from keto import report
            if not args.output_dir:
                sys.stderr.write("error: report needs -o/--output-dir\n")
                return 2
            ctx = make_context(args)
            try:
                rep = report.build(ctx, baseline=args.baseline, include_live=not args.image_only)
            finally:
                ctx.close()
            paths = report.write(rep, args.output_dir)
            out.write("findings: %s\n" % ", ".join("%s=%d" % kv for kv in rep["summary"].items()))
            out.write("evidence integrity: %s\n" % rep["integrity"])
            skipped = [c for c in rep["coverage"] if c["status"] != "ok"]
            if skipped:
                out.write("detectors not run: %s\n" % ", ".join("%s (%s)" % (c["plugin"], c["status"])
                                                              for c in skipped))
            for k, p in paths.items():
                out.write("  %-4s %s\n" % (k, p))
            return 0
        if args.command == "acquire":
            from keto.acquire.cli import run_acquire
            return run_acquire(args, out)
        if args.command == "pdb":
            from keto.winmem.symcmd import run as run_symbols
            return run_symbols(args, out)
        if args.command == "sigma":
            from keto.rules import sigma
            for p in sigma.write_all(args.out):
                out.write("%s\n" % p)
            return 0
        cls = PLUGINS[args.command]
        ctx = make_context(args)
        opts = {r.name: getattr(args, r.name, None) for r in cls.REQUIREMENTS}
        if not args.quiet:
            sys.stderr.write("%s\n" % BANNER)
        t0 = time.time()
        try:
            grid = cls(ctx, opts).run()
            buf = io.StringIO()
            RENDERERS[args.renderer]().render(grid, buf)
        finally:
            ctx.close()
        out.write(buf.getvalue())
        if not args.quiet:
            extra = (" | profile: %s (%s)" % (ctx._profile.name, ctx.profile_reason)) if ctx._profile else ""
            sys.stderr.write("[%s: %d row(s) in %.2fs%s]\n" % (cls.NAME, len(grid), time.time() - t0, extra))
        return 0
    except KetoError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("interrupted\n")
        return 130
    except Exception as exc:  # never end an analysis with a bare traceback; -v keeps it for bug reports
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.stderr.write("error: internal error in %s: %s: %s%s\n" % (
            args.command, type(exc).__name__, exc, "" if args.verbose else " (run with -v for the traceback)"))
        return 3
    finally:
        if out is not sys.stdout:
            out.close()


if __name__ == "__main__":
    sys.exit(main())
