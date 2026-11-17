"""Incident report: run every applicable detector, normalise findings, map to MITRE ATT&CK.

``keto -f evidence.keto report -o out/`` (or ``--live``) writes ``report.json`` (for a
SIEM / case-management system) and ``report.html`` (self-contained, no external
resources, safe to open on an isolated analysis machine).
"""

from __future__ import annotations

import datetime as _dt
import html
import json
import os
import time
from typing import Callable, Dict, List, Optional

from keto import __version__
from keto.framework.exceptions import KetoError
from keto.framework.plugin import PLUGINS, load_plugins
from keto.framework.treegrid import to_plain

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

ATTACK = {
    "T1005": "Data from Local System",
    "T1014": "Rootkit",
    "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading",
    "T1055": "Process Injection",
    "T1068": "Exploitation for Privilege Escalation",
    "T1070.004": "Indicator Removal: File Deletion",
    "T1113": "Screen Capture",
    "T1496": "Resource Hijacking",
    "T1547.006": "Boot or Logon Autostart Execution: Kernel Modules and Extensions",
    "T1552": "Unsecured Credentials",
    "T1552.004": "Unsecured Credentials: Private Keys",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1564": "Hide Artifacts",
    "T1574": "Hijack Execution Flow",
    "T1574.006": "Hijack Execution Flow: Dynamic Linker Hijacking",
    "T1611": "Escape to Host",
    "T1620": "Reflective Code Loading",
}


class Rule:
    def __init__(self, plugin: str, title: str, attack: List[str], severity="medium",
                 when: Optional[Callable[[dict], bool]] = None, sev_col: Optional[str] = None,
                 detail_cols: Optional[List[str]] = None, recommendation: str = "", opts: Optional[dict] = None,
                 evidence: str = "any"):
        self.plugin, self.title, self.attack, self.severity = plugin, title, attack, severity
        self.evidence = evidence  # "vram": GPU memory images only; "host": host RAM / process dumps only; "any"
        self.when, self.sev_col, self.detail_cols = when, sev_col, detail_cols
        self.recommendation, self.opts = recommendation, opts or {}

    def sev(self, row: dict) -> str:
        if self.sev_col:
            v = str(row.get(self.sev_col) or "").lower()
            return v if v in SEV_ORDER else self.severity
        return self.severity(row) if callable(self.severity) else self.severity


def _txt(row, *cols):
    return " ".join(str(row.get(c) or "") for c in cols)


RULES = [
    # ---- memory images (VRAM, host RAM, process dumps)
    Rule("nvidia.malware.malfind", "Executable GPU code in writable GPU memory", ["T1620", "T1055"], "high",
         recommendation="Extract the region (nvidia.memmap --dump) and compare with the application's shipped kernels."),
    Rule("nvidia.malware.suspiciouslaunch", "GPU kernel launched from unknown or unsafe code", ["T1620"], "high",
         recommendation="Identify the launching channel/process; recover the code with nvidia.memmap."),
    Rule("nvidia.malware.sassfind", "GPU machine code outside any known module", ["T1564", "T1620"], "medium"),
    Rule("nvidia.malware.hostcode", "Host executable, script stager, shellcode or file system hidden in GPU memory", ["T1564", "T1027"], "high",
         recommendation="Dump with nvidia.dumpfiles and analyse the payload in a sandbox."),
    Rule("nvidia.malware.codeintegrity", "GPU kernel code differs from its reference", ["T1055"], "high",
         when=lambda r: str(r.get("Verdict", "")).startswith(("MODIFIED", "DIFFERS"))),
    Rule("nvidia.malware.cubinxview", "GPU launch of code with no backing module", ["T1620", "T1564"], "high",
         when=lambda r: str(r.get("Kernel", "")).startswith("<")),
    Rule("nvidia.malware.ptcheck", "GPU page-table / isolation anomaly", ["T1068", "T1014"],
         lambda r: "high" if str(r.get("Finding", "")).startswith(("exposes", "privileged")) else "medium"),
    Rule("nvidia.malware.chanxview", "GPU channel present in memory but absent from the scheduler", ["T1564", "T1014"],
         "medium", when=lambda r: r.get("Runlist") is False),
    Rule("nvidia.malware.exfil", "GPU DMA moving data out of VRAM", ["T1005"],
         lambda r: "high" if "host RAM" in str(r.get("Why")) or "window" in str(r.get("Why")) else "low"),
    Rule("nvidia.malware.miner", "Cryptomining / password-cracking GPU workload", ["T1496"], "high"),
    Rule("nvidia.secrets", "Credential material present in GPU memory", ["T1552"], "medium",
         recommendation="Rotate the exposed credentials; GPU memory is not cleared by most host tools."),
    Rule("nvidia.aeskeys", "AES key schedule present in GPU memory", ["T1552.004"], "medium"),
    Rule("nvidia.artifactscan", "GPU payload in host/process memory", ["T1620", "T1027"], "medium",
         sev_col="Severity", when=lambda r: r.get("Severity") in ("high", "medium", "low"),
         recommendation="Re-run with --baseline from a known-clean process of the same application/driver."),
    Rule("nvidia.timeslices", "GPU scheduling timeslice far above default", ["T1496"], "medium",
         when=lambda r: bool(r.get("Suspicious"))),
    # ---- live system / snapshot
    Rule("nvidia.malware.gpuxview", "GPU process visible to some sources but not others", ["T1564", "T1014"], "medium",
         when=lambda r: bool(r.get("Note")) and not str(r.get("Note")).startswith(("this Keto", "NVML view only"))),
    Rule("nvidia.malware.rawioctl", "Process drives the GPU kernel driver without the user-mode driver", ["T1068"], "high"),
    Rule("nvidia.malware.libhooks", "NVIDIA user-mode library patched in memory", ["T1562.001", "T1574"], "high",
         when=lambda r: str(r.get("Status", "")).lower() not in ("clean", "") and
         not str(r.get("Status", "")).lower().startswith(("unreadable", "skipped", "n/a"))),
    Rule("nvidia.malware.injection", "Code injection into a GPU process", ["T1574.006", "T1055"], "high", sev_col="Severity"),
    Rule("nvidia.malware.masquerade", "GPU process masquerading", ["T1036"], "medium"),
    Rule("nvidia.malware.deletedexe", "GPU process running from deleted / fileless code", ["T1070.004", "T1620"], "high"),
    Rule("nvidia.malware.integrity", "NVIDIA file modified on disk", ["T1562.001"], "high",
         when=lambda r: str(r.get("Result", "")).startswith("MODIFIED")),
    Rule("nvidia.malware.capture", "Screen capture / encoding through the GPU", ["T1113"], "medium", sev_col="Severity"),
    Rule("nvidia.malware.cryptojack", "Cryptojacking on the GPU", ["T1496"], "high", sev_col="Severity"),
    Rule("nvidia.procscan", "GPU payload in a running process", ["T1620", "T1027"], "medium", sev_col="Severity",
         when=lambda r: r.get("Severity") in ("high", "medium", "low")),
    Rule("nvidia.envars", "Loader/injection variable in a GPU process", ["T1574.006"], "high",
         when=lambda r: bool(r.get("Suspicious"))),
    Rule("nvidia.autostart", "GPU API loader configuration hijack", ["T1574"], "high", when=lambda r: bool(r.get("Suspicious"))),
    Rule("nvidia.params", "Insecure NVIDIA driver parameter", [], "medium", sev_col="Severity",
         when=lambda r: str(r.get("Severity", "")).lower() in ("high", "medium")),
    Rule("nvidia.containers", "Vulnerable NVIDIA container stack", ["T1611"], "high", sev_col="Severity",
         when=lambda r: str(r.get("Severity", "")).lower() in ("high", "medium", "critical")),
    Rule("nvidia.modules", "Unexpected kernel module bound to the NVIDIA driver", ["T1547.006", "T1014"], "high",
         when=lambda r: bool(r.get("Suspicious"))),
    Rule("nvidia.devnodes", "Suspicious GPU device node", ["T1014"], "medium", when=lambda r: bool(r.get("Suspicious"))),
    Rule("nvidia.debugger", "GPU debugger attached to a process", ["T1055"], "low"),
    Rule("nvidia.profiling", "GPU profiling / instrumentation exposure", [], "medium",
         when=lambda r: str(r.get("Risk", "")).lower() == "high"),
    Rule("nvidia.malware.unaccounted", "GPU memory or activity owned by no listed process", ["T1564", "T1496"],
         "medium", when=lambda r: "no listed process" in str(r.get("Finding")) or "no process listed" in
         str(r.get("Finding"))),
    Rule("nvidia.malware.rawaccess", "GPU driven outside the NVIDIA driver (VFIO / raw BAR access)", ["T1564"],
         "medium", when=lambda r: isinstance(r.get("Finding"), str) and bool(r.get("Finding"))),
    Rule("nvidia.malware.watchdog", "GPU watchdog weakened (unlimited GPU execution)", ["T1562.001", "T1496"],
         lambda r: "medium" if str(r.get("Finding", "")).startswith("RM registry") else "high",
         when=lambda r: isinstance(r.get("Finding"), str) and bool(r.get("Finding"))),
    Rule("windows.gpuprocs", "GPU use that does not fit the process (loader, windowless compute, miner)",
         ["T1027", "T1496"], "medium", sev_col="Severity", when=lambda r: r.get("Severity") in ("high", "medium")),
    # ---- host kernel memory (Linux / WSL2 RAM image or /proc/kcore)
    Rule("wsl.dxgprocs", "GPU process hidden from the task list or unlinked from the GPU driver", ["T1564", "T1014"],
         "high", when=lambda r: "hidden" in str(r.get("Attention")) or "unlinked" in str(r.get("Attention")),
         evidence="kernel"),
    Rule("wsl.dxgallocs", "GPU payload in guest pages shared with the GPU", ["T1620", "T1027"], "high",
         when=lambda r: isinstance(r.get("Artefacts"), str) and bool(r.get("Artefacts")), evidence="kernel"),
]


# which evidence each image detector is meaningful for: VRAM-centric checks would drown a host/process
# dump in false positives (driver code in the heap, the program's own ELF libraries), while the
# provenance-aware sweep is the right tool there.
EVIDENCE = {name: "vram" for name in (
    "nvidia.malware.malfind", "nvidia.malware.suspiciouslaunch", "nvidia.malware.sassfind", "nvidia.malware.hostcode",
    "nvidia.malware.codeintegrity", "nvidia.malware.cubinxview", "nvidia.malware.ptcheck", "nvidia.malware.chanxview",
    "nvidia.malware.exfil", "nvidia.secrets", "nvidia.aeskeys", "nvidia.timeslices")}
EVIDENCE["nvidia.artifactscan"] = "host"
for _r in RULES:
    _r.evidence = EVIDENCE.get(_r.plugin, _r.evidence)


def evidence_kind(ctx) -> str:
    if not ctx.has_image():
        return "none"
    return "vram" if ctx.vram is not None else "host"


def _has_kernel(ctx) -> bool:
    phys = ctx.layers.get("sysmem") or ctx.layers.get("physical")
    meta = (getattr(ctx, "host_metadata", None) or {}).get("kernel") or (ctx.metadata or {}).get("kernel")
    return phys is not None and bool(meta)


def _applicable(rule: Rule, ctx) -> bool:
    cls = PLUGINS.get(rule.plugin)
    if cls is None:
        return False
    if rule.evidence == "kernel":
        return _has_kernel(ctx)
    if "image" in cls.SOURCES and rule.evidence != "any" and rule.evidence != evidence_kind(ctx):
        return False
    if "image" in cls.SOURCES and ctx.has_image():
        return True
    if "live" in cls.SOURCES and ctx.has_live():
        return True
    return False


def build(ctx, baseline: Optional[str] = None, include_live: bool = True) -> dict:
    load_plugins()
    findings, coverage = [], []
    started = time.time()
    for rule in RULES:
        if not _applicable(rule, ctx) or (not include_live and "image" not in PLUGINS[rule.plugin].SOURCES
                                          and rule.evidence != "kernel"):
            continue
        opts = dict(rule.opts)
        if baseline and rule.plugin in ("nvidia.artifactscan", "nvidia.procscan"):
            opts["baseline"] = baseline
        t0 = time.time()
        try:
            grid = PLUGINS[rule.plugin](ctx, opts).run()
            rows = grid.as_dicts()
            n = 0
            for row in rows:
                if rule.when is not None and not rule.when(row):
                    continue
                n += 1
                findings.append({"severity": rule.sev(row), "title": rule.title, "plugin": rule.plugin,
                                 "attack": [{"id": t, "name": ATTACK.get(t, "")} for t in rule.attack],
                                 "evidence": {k: to_plain(v) for k, v in row.items() if k != "__depth"},
                                 "recommendation": rule.recommendation})
            coverage.append({"plugin": rule.plugin, "status": "ok", "rows": len(rows), "findings": n,
                             "seconds": round(time.time() - t0, 2)})
        except KetoError as exc:
            coverage.append({"plugin": rule.plugin, "status": "not applicable", "detail": str(exc)})
        except Exception as exc:  # a broken detector must not lose the rest of the report
            coverage.append({"plugin": rule.plugin, "status": "error", "detail": "%s: %s" % (type(exc).__name__, exc)})
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["title"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    techniques = {}
    for f in findings:
        for t in f["attack"]:
            techniques.setdefault(t["id"], {"id": t["id"], "name": t["name"], "findings": 0})["findings"] += 1
    case = {"image": ctx.image_path, "evidence": evidence_kind(ctx), "live": ctx.has_live() and not ctx.has_image(),
            "device": ctx.metadata.get("device"), "acquisition": {k: v for k, v in (ctx.metadata.get("acquisition") or {})
                                                                  .items() if k not in ("chunks",)},
            "process": {k: v for k, v in (ctx.metadata.get("process") or {}).items() if k not in ("mappings", "skipped")}}
    if ctx.has_image():
        try:
            case["profile"] = "%s (%s)" % (ctx.profile.name, ctx.profile_reason)
        except Exception:
            pass
    if ctx.container is not None:
        case["integrity"] = [{"segment": r["segment"], "space": r["space"], "ok": r["ok"]} for r in ctx.container.verify()]
    return {"format": "keto-report/1", "tool": "Keto %s" % __version__,
            "generated_utc": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
            "duration_s": round(time.time() - started, 1), "case": to_plain(case), "summary": counts,
            "attack": sorted(techniques.values(), key=lambda t: -t["findings"]), "findings": findings,
            "coverage": coverage}


def to_html(rep: dict) -> str:
    e = html.escape
    colors = {"critical": "#7f1d1d", "high": "#b91c1c", "medium": "#b45309", "low": "#1d4ed8", "info": "#4b5563"}
    out = ["<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' "
           "content='width=device-width, initial-scale=1'><title>Keto report</title><style>",
           "body{font:14px/1.45 system-ui,Segoe UI,sans-serif;margin:0;padding:16px 24px;color:#111;background:#fff}"
           "h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px;border-bottom:1px solid #ddd}"
           "table{border-collapse:collapse;width:100%;margin:6px 0}td,th{border:1px solid #e5e7eb;padding:4px 6px;"
           "text-align:left;vertical-align:top}th{background:#f3f4f6}.sev{color:#fff;border-radius:4px;padding:1px 6px;"
           "font-weight:600;font-size:12px}.muted{color:#6b7280}code{font-size:12px;word-break:break-all}"
           ".cards{display:flex;gap:10px;flex-wrap:wrap}.card{border:1px solid #e5e7eb;border-radius:6px;"
           "padding:8px 14px;min-width:90px}.card b{font-size:20px;display:block}"
           "@media (prefers-color-scheme: dark){body{background:#111;color:#e5e7eb}th{background:#1f2937}"
           "td,th,.card{border-color:#374151}h2{border-color:#374151}}</style></head><body>"]
    out.append("<h1>Keto GPU forensics report</h1><div class='muted'>%s &middot; generated %s &middot; %ss</div>"
               % (e(rep["tool"]), e(rep["generated_utc"]), rep["duration_s"]))
    out.append("<h2>Summary</h2><div class='cards'>")
    for s, n in rep["summary"].items():
        out.append("<div class='card'><b style='color:%s'>%d</b>%s</div>" % (colors[s], n, s))
    out.append("</div>")
    case = rep["case"]
    out.append("<h2>Case</h2><table>")
    for k in ("image", "live", "profile", "device", "acquisition", "process", "integrity"):
        if case.get(k) not in (None, {}, [], False):
            out.append("<tr><th>%s</th><td><code>%s</code></td></tr>" % (e(k), e(json.dumps(case[k], default=str))))
    out.append("</table>")
    if rep["attack"]:
        out.append("<h2>MITRE ATT&amp;CK</h2><table><tr><th>Technique</th><th>Name</th><th>Findings</th></tr>")
        for t in rep["attack"]:
            out.append("<tr><td>%s</td><td>%s</td><td>%d</td></tr>" % (e(t["id"]), e(t["name"]), t["findings"]))
        out.append("</table>")
    out.append("<h2>Findings (%d)</h2>" % len(rep["findings"]))
    if not rep["findings"]:
        out.append("<p>No findings from the detectors that applied to this evidence.</p>")
    else:
        out.append("<table><tr><th>Severity</th><th>Finding</th><th>ATT&amp;CK</th><th>Evidence</th><th>Plugin</th></tr>")
        for f in rep["findings"]:
            ev = "; ".join("%s=%s" % (k, v) for k, v in f["evidence"].items() if v not in (None, "", "-"))
            out.append("<tr><td><span class='sev' style='background:%s'>%s</span></td><td>%s%s</td><td>%s</td>"
                       "<td><code>%s</code></td><td>%s</td></tr>" % (
                           colors.get(f["severity"], "#555"), e(f["severity"]), e(f["title"]),
                           ("<div class='muted'>%s</div>" % e(f["recommendation"])) if f["recommendation"] else "",
                           e(", ".join(t["id"] for t in f["attack"]) or "-"), e(ev[:600]), e(f["plugin"])))
        out.append("</table>")
    out.append("<h2>Detector coverage</h2><table><tr><th>Plugin</th><th>Status</th><th>Rows</th><th>Findings</th>"
               "<th>Detail</th></tr>")
    for c in rep["coverage"]:
        out.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class='muted'>%s</td></tr>" % (
            e(c["plugin"]), e(c["status"]), c.get("rows", "-"), c.get("findings", "-"), e(c.get("detail", ""))))
    out.append("</table></body></html>")
    return "".join(out)


def write(rep: dict, out_dir: str) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    paths = {"json": os.path.join(out_dir, "report.json"), "html": os.path.join(out_dir, "report.html")}
    with open(paths["json"], "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1, default=str)
    with open(paths["html"], "w", encoding="utf-8") as fh:
        fh.write(to_html(rep))
    return paths
