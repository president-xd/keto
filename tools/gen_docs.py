#!/usr/bin/env python3
"""Generate docs/PLUGIN_REFERENCE.md and docs/VOLATILITY_MAPPING.md from the
plugins' own metadata, so documentation cannot drift from the code.

    python tools/gen_docs.py [--volatility-reference <plugin list .md>]

The Volatility 3 plugin list (names and deprecated aliases) is kept in tools/volatility3_plugins.md, so both
documents can be regenerated from the repository alone.
"""

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from keto import __version__  # noqa: E402
from keto.framework.plugin import PLUGINS, load_plugins  # noqa: E402

CATEGORY_TITLES = [
    ("framework", "Framework / vendor-independent plugins"),
    ("nvidia.system", "System information"),
    ("nvidia.processes", "GPU processes (live / snapshot)"),
    ("nvidia.channels", "Channels, TSGs and scheduling (the GPU's processes)"),
    ("nvidia.memory", "Address spaces, page tables and physical memory"),
    ("nvidia.code", "CUDA code: cubins, fatbins, PTX, kernels"),
    ("nvidia.commands", "Command streams: pushbuffers, launches, DMA"),
    ("nvidia.artifacts", "Artefact recovery"),
    ("nvidia.driver", "Driver, firmware, configuration"),
    ("nvidia.malware", "Malware, rootkit and abuse detection"),
    ("host", "Host kernel memory: Linux / WSL2 RAM images or /proc/kcore (types from the kernel's BTF)"),
    ("windows", "Windows live triage"),
    ("nvidia.services", "GPU services, loader configuration and persistence"),
]

# Role-based mappings for Volatility plugins whose OS structure has no literal GPU twin:
# the Keto plugin(s) answering the same forensic question, and why.
MANUAL = {
    "windows.getsids": (["nvidia.pslist", "nvidia.devnodes"], "who owns GPU work: process UIDs and GPU device-node ownership"),
    "windows.getservicesids": (["nvidia.daemons"], "identity/state of GPU service processes"),
    "windows.mftscan.MFTScan": (["nvidia.computecache", "nvidia.strings"], "file-system records of GPU use (JIT/shader cache entries) and file paths left in VRAM"),
    "windows.registry.hivelist": (["nvidia.params", "nvidia.autostart"], "the driver's configuration stores (module parameters / registry dwords, loader configs)"),
    "windows.registry.hivescan": (["nvidia.params", "nvidia.autostart"], "as hivelist: every configuration source of the GPU stack"),
    "windows.registry.userassist": (["nvidia.accounting", "nvidia.computecache"], "evidence of program execution on the GPU"),
    "windows.registry.lsadump": (["nvidia.secrets", "nvidia.aeskeys"], "secrets and key material present in GPU memory"),
    "windows.registry.cachedump": (["nvidia.secrets"], "cached credential material in GPU memory"),
    "windows.sessions": (["nvidia.sessions"], "encoder / frame-buffer-capture sessions per process"),
    "windows.windowstations": (["nvidia.surfaces", "nvidia.sessions"], "what was on screen: render targets and capture sessions"),
    "windows.desktops": (["nvidia.surfaces"], "recovered framebuffers / render targets"),
    "windows.deskscan": (["nvidia.surfaces"], "carving surfaces, including unreferenced ones"),
    "windows.malware.svcdiff": (["nvidia.daemons"], "running GPU daemons vs installed service units"),
    "linux.kthreads": (["nvidia.privileges", "nvidia.chantree"], "kernel-owned (privileged) GPU channels"),
    "linux.boottime": (["timeliner", "nvidia.info"], "time anchors: acquisition time, process start times, Xid timestamps"),
    "linux.pagecache.Files": (["nvidia.computecache"], "files cached by the GPU stack (JIT/shader caches)"),
    "linux.pagecache.InodePages": (["nvidia.cubindump", "nvidia.dumpfiles"], "extract cached content to files"),
    "linux.pagecache.RecoverFs": (["nvidia.dumpfiles"], "bulk recovery of every carvable object with a manifest"),
    "linux.sockscan": (["nvidia.sysmemmap", "nvidia.copies"], "channels through which data leaves the GPU (host-memory windows, DMA)"),
    "linux.ip.Addr": (["nvidia.devicetree", "nvidia.nvlink"], "the GPU's interconnect endpoints (PCIe, NVLink peers)"),
    "linux.ip.Link": (["nvidia.nvlink", "nvidia.devicetree"], "link state and speed"),
    "linux.module_extract": (["nvidia.cubindump"], "rebuild loaded GPU modules (cubins) as files"),
    "linux.kallsyms": (["nvidia.symbols"], "symbol tables of loaded GPU code"),
    "linux.iomem": (["nvidia.physmap", "nvidia.devicetree"], "physical memory map: VRAM ownership, BARs"),
    "linux.vmcoreinfo": (["nvidia.info", "configwriter"], "identity table of the image (device, driver, layout)"),
    "linux.ebpf": (["nvidia.kernels", "nvidia.launches"], "programs loaded into and executed by the device"),
    "linux.malware.check_syscall": (["nvidia.malware.libhooks", "nvidia.classes"], "hooked dispatch paths: CUDA/NVML entry points, engine class bindings"),
    "linux.malware.check_idt": (["nvidia.notifiers"], "interrupt / notification paths from the GPU"),
    "linux.malware.check_afinfo": (["nvidia.malware.libhooks", "nvidia.malware.integrity"], "tampering with the user-mode stack used to hide activity (e.g. NVML hiding miners)"),
    "linux.malware.check_creds": (["nvidia.malware.ptcheck"], "isolation failures: physical pages shared across GPU contexts"),
    "linux.malware.keyboard_notifiers": (["nvidia.malware.capture"], "input/output spying via the GPU (screen capture sessions)"),
    "linux.malware.netfilter": (["nvidia.malware.exfil"], "traffic leaving the device"),
    "linux.malware.tty_check": (["nvidia.malware.capture"], "terminal/screen sniffing via frame-buffer capture"),
    "linux.tracing.ftrace": (["nvidia.profiling", "nvidia.malware.injection"], "function tracing / interposition (CUPTI, injection hooks)"),
    "linux.tracing.tracepoints": (["nvidia.profiling"], "probes attached to GPU execution (profilers, perf counters)"),
    "mac.pslist": (["nvidia.pslist", "nvidia.runlist"], "process / channel lists"),
    "mac.pstree": (["nvidia.pstree", "nvidia.chantree"], "process / channel trees"),
    "mac.psaux": (["nvidia.cmdline"], "command lines"),
    "mac.bash": (["nvidia.pushbuf"], "command history"),
    "mac.malfind": (["nvidia.malware.malfind"], "injected code"),
    "mac.lsof": (["nvidia.handles"], "open device handles"),
    "mac.list_files": (["nvidia.computecache", "nvidia.cubinscan"], "cached files / code objects"),
    "mac.mount": (["nvidia.containers"], "namespaces / containers with GPU access"),
    "mac.netstat": (["nvidia.nvlink", "nvidia.copies"], "communication endpoints and transfers"),
    "mac.ifconfig": (["nvidia.nvlink", "nvidia.devicetree"], "interfaces and links"),
    "mac.dmesg": (["nvidia.xid"], "kernel log (NVRM / Xid)"),
    "mac.lsmod": (["nvidia.modules"], "loaded kernel modules"),
    "mac.check_syscall": (["nvidia.malware.libhooks"], "hooked entry points"),
    "mac.check_trap_table": (["nvidia.malware.libhooks", "nvidia.notifiers"], "hooked trap / notification paths"),
    "mac.check_sysctl": (["nvidia.params"], "tunables and their handlers"),
    "mac.kauth_scopes": (["nvidia.malware.injection", "nvidia.profiling"], "authorisation / interposition hooks"),
    "mac.kauth_listeners": (["nvidia.malware.injection", "nvidia.profiling"], "listeners attached to GPU processes"),
    "mac.kevents": (["nvidia.semaphores", "nvidia.notifiers"], "event / synchronisation objects"),
    "mac.socket_filters": (["nvidia.malware.exfil"], "filters on data leaving the device"),
    "mac.trustedbsd": (["nvidia.privileges", "nvidia.malware.ptcheck"], "policy / privilege enforcement"),
    "mac.vfsevents": (["nvidia.profiling", "nvidia.malware.capture"], "processes watching GPU activity"),
}


def esc(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def categories():
    cats = {}
    for name, cls in PLUGINS.items():
        cats.setdefault(cls.CATEGORY, []).append(cls)
    order = [c for c, _ in CATEGORY_TITLES] + sorted(set(cats) - {c for c, _ in CATEGORY_TITLES})
    return [(c, dict(CATEGORY_TITLES).get(c, c), sorted(cats[c], key=lambda k: k.NAME)) for c in order if c in cats]


def plugin_reference():
    lines = ["# Keto: Complete Plugin Reference", "",
             "Every plugin with a two-line summary of **what it does** and **how it does it**, plus the Volatility 3 "
             "plugin it is the GPU counterpart of. Generated from the plugins' own metadata by `tools/gen_docs.py` "
             "(Keto %s, %d plugins)." % (__version__, len(PLUGINS)), "",
             "- **Usage:** `keto -f <image> <plugin> [options]` for memory images, `keto --live <plugin>` on a running "
             "system, `keto -f <snapshot.keto> <plugin>` to replay a captured live snapshot offline.",
             "- **Needs:** `image` = a GPU memory image (`.keto` container, raw VRAM dump, LiME); `live` = the running "
             "system or a recorded snapshot; `file` = only the files named in its options, or for the `host.*` / "
             "`wsl.*` plugins a host RAM image (`-f` or `--host-image`, plus `--btf`/`--kallsyms` for images from "
             "other tools) or the running kernel (`--kcore`, root).",
             "- Output formats: `-r quick|pretty|csv|json|jsonl`; files go to `-o <dir>`.", ""]
    for cat, title, classes in categories():
        lines += ["## %s (%d)" % (title, len(classes)), "",
                  "| Plugin | Needs | Volatility analogue | What it does | How it does it |", "|---|---|---|---|---|"]
        for c in classes:
            lines.append("| `%s` | %s | %s | %s | %s |" % (c.NAME, "/".join(c.SOURCES), esc(c.ANALOG or "-"),
                                                          esc(c.DESCRIPTION), esc(c.METHOD)))
        lines.append("")
        for c in classes:
            if c.REQUIREMENTS:
                opts = ", ".join("`%s`" % r.flag for r in c.REQUIREMENTS)
                lines.append("- `%s` options: %s" % (c.NAME, opts))
        lines.append("")
    return "\n".join(lines)


def volatility_names(path):
    names = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"\|\s*`([\w.]+)`\s*\|", line)
            if m:
                names.append(m.group(1))
    return names


def analog_index():
    idx = {}
    for name, cls in PLUGINS.items():
        for token in re.findall(r"[a-z][\w.]*\w", (cls.ANALOG or "").lower()):
            idx.setdefault(token, set()).add(name)
    return idx


def mapping(vol_ref):
    names = volatility_names(vol_ref)
    idx = analog_index()
    deprecated = {}
    with open(vol_ref, encoding="utf-8") as fh:
        text = fh.read()
    for old, new in re.findall(r"\|\s*`([\w.]+)`\s*\|\s*`([\w.]+)`\s*\|", text):
        deprecated[old] = new
    rows, direct, role, missing = [], 0, 0, []
    for n in names:
        if n in deprecated:
            continue
        candidates = set(idx.get(n.lower(), set()))
        short = n.split(".")[-1].lower()
        for token, plugs in idx.items():
            if token.split(".")[-1] == short and token.split(".")[0] == n.split(".")[0]:
                candidates |= plugs
        if candidates:
            direct += 1
            rows.append("| `%s` | %s | declared analogue |" % (n, ", ".join("`%s`" % c for c in sorted(candidates))))
        elif n in MANUAL:
            plugs, why = MANUAL[n]
            unknown = [p for p in plugs if p not in PLUGINS]
            if unknown:
                raise SystemExit("MANUAL mapping for %s names unknown plugins %s" % (n, unknown))
            role += 1
            rows.append("| `%s` | %s | by role: %s |" % (n, ", ".join("`%s`" % p for p in plugs), why))
        else:
            missing.append(n)
            rows.append("| `%s` | **unmapped** | |" % n)
    total = len([n for n in names if n not in deprecated])
    head = ["# Volatility 3 -> Keto coverage map", "",
            "Every working Volatility 3 plugin listed in the supplied reference (%d), with the Keto plugin(s) "
            "that answer the same forensic question on an NVIDIA GPU." % total, "",
            "- **declared analogue** (%d): the Keto plugin names this Volatility plugin as its counterpart." % direct,
            "- **by role** (%d): the OS structure has no literal GPU twin (Windows desktops, Linux page cache, macOS "
            "kauth...), so the mapping is to the plugin that fills the same investigative role, with the reason." % role,
            "- **unmapped** (%d)." % len(missing),
            "- The %d deprecated Volatility alias names forward to the plugins above." % len(deprecated),
            "- A mapping says which Keto plugin answers the same question; it does not mean the Keto plugin runs on "
            "that Volatility plugin's OS. NVIDIA ships no driver for current macOS, so every `mac.*` row is a role "
            "analogy, and many `linux.*`/`windows.*` live analogues run only on that OS "
            "(docs/PLUGIN_REFERENCE.md says which).", "",
            "| Volatility 3 plugin | Keto counterpart(s) | Basis |", "|---|---|---|"]
    return "\n".join(head + rows + [""])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--volatility-reference", default=os.path.join(ROOT, "tools", "volatility3_plugins.md"),
                    help="Volatility 3 plugin list (names and deprecated aliases); default: the copy in tools/")
    args = ap.parse_args()
    load_plugins()
    os.makedirs(os.path.join(ROOT, "docs"), exist_ok=True)
    with open(os.path.join(ROOT, "docs", "PLUGIN_REFERENCE.md"), "w", encoding="utf-8") as fh:
        fh.write(plugin_reference() + "\n")
    if os.path.exists(args.volatility_reference):
        with open(os.path.join(ROOT, "docs", "VOLATILITY_MAPPING.md"), "w", encoding="utf-8") as fh:
            fh.write(mapping(args.volatility_reference) + "\n")
    print("wrote docs for %d plugins" % len(PLUGINS))


if __name__ == "__main__":
    main()
