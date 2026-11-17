"""GPU architecture profiles: the GPU equivalent of Volatility's ISF symbol tables.

A profile is a JSON document in ``keto/symbols/<vendor>/<name>.json`` that
describes, for one GPU architecture, everything the analysis code must not
hard-code: page-table format and VA width, structure layouts (instance block,
RAMFC, USERD, runlist), launch-descriptor (QMD) version, engine class ids, and
the provenance of each fact. Users can drop extra profiles into any directory
passed with ``--profile-dir``.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

from keto.framework.exceptions import FormatError

SYMBOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "symbols")

REQUIRED_KEYS = ("format", "name", "vendor", "architecture", "mmu", "layout", "classes", "provenance")


def _intify(obj):
    """Recursively convert "0x..." strings to ints (JSON has no hex literals)."""
    if isinstance(obj, dict):
        return {k: _intify(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_intify(v) for v in obj]
    if isinstance(obj, str) and obj.lower().startswith("0x"):
        try:
            return int(obj, 16)
        except ValueError:
            return obj
    return obj


def _resolve_layout(raw: dict, name: str, depth: int = 0) -> dict:
    """Expand ``inherit`` / ``drop`` so a generation only states what changed from its predecessor."""
    doc = raw[name]
    if "inherit" not in doc:
        return doc
    if depth > 8:
        raise FormatError("layout inheritance too deep at %s" % name)
    base = _resolve_layout(raw, doc["inherit"], depth + 1)
    out = {"provenance": list(base.get("provenance", [])) + list(doc.get("provenance", []))}
    for part in ("ramin", "ramfc", "userd", "runlist"):
        merged = dict(base.get(part, {}))
        for k in doc.get("drop", {}).get(part, []):
            merged.pop(k, None)
        merged.update(doc.get(part, {}))
        out[part] = merged
    return out


class Layout:
    def __init__(self, name: str, doc: dict):
        self.name = name
        self.provenance = doc.get("provenance", [])
        self.ramin = _intify(doc.get("ramin", {}))
        self.ramfc = _intify(doc.get("ramfc", {}))
        self.userd = _intify(doc.get("userd", {}))
        self.runlist = _intify(doc.get("runlist", {}))


class Profile:
    def __init__(self, doc: dict, layout: Layout, path: str):
        self.doc = doc
        self.path = path
        self.name = doc["name"]
        self.vendor = doc["vendor"]
        self.architecture = doc["architecture"]
        self.family = doc.get("family", "")
        self.nvml_arch = doc.get("nvml_arch")
        self.compute_capabilities: List[str] = doc.get("compute_capabilities", [])
        self.chipsets: Dict[int, str] = {int(k, 16): v for k, v in doc.get("chipsets", {}).items()}
        self.name_patterns: List[str] = doc.get("name_patterns", [])
        self.mmu = doc["mmu"]
        self.mmu_format: str = self.mmu["format"]
        self.va_bits: int = self.mmu.get("va_bits", 49)
        self.qmd: Optional[str] = doc.get("qmd")
        self.classes = {k: int(v, 16) for k, v in doc.get("classes", {}).items()}
        self.big_page_sizes = list(self.mmu.get("big_page_sizes", [65536]))
        self.provenance: List[str] = doc.get("provenance", []) + layout.provenance
        self.layout = layout
        self.ramin, self.ramfc, self.userd, self.runlist = layout.ramin, layout.ramfc, layout.userd, layout.runlist

    def __repr__(self):
        return "<Profile %s (%s, MMU %s)>" % (self.name, self.architecture, self.mmu_format)


class ClassDatabase:
    def __init__(self, doc: dict):
        self.classes = {int(k, 16): v for k, v in doc.get("classes", {}).items()}
        self.methods = {fam: {int(k, 16): v for k, v in tbl.items()} for fam, tbl in doc.get("methods", {}).items()}
        self.provenance = doc.get("provenance", {})

    def class_name(self, class_id: int) -> str:
        c = self.classes.get(class_id)
        return c["name"] if c else "CLASS_%04X" % class_id

    def family(self, class_id: Optional[int]) -> Optional[str]:
        if class_id is None:
            return None
        c = self.classes.get(class_id)
        if c:
            return c["family"]
        # fall back on NVIDIA's class-number suffix convention
        suffix = class_id & 0xFF
        return {0x6F: "host", 0xB5: "copy", 0xC0: "compute", 0x97: "3d", 0x2D: "2d", 0x40: "i2m"}.get(suffix)

    def method_name(self, family: Optional[str], method: int) -> str:
        if method < 0x100:
            name = self.methods.get("host", {}).get(method)
            if name:
                return name
        name = self.methods.get(family or "", {}).get(method)
        return name or "0x%04x" % method


class ProfileRegistry:
    def __init__(self, extra_dirs: Optional[List[str]] = None):
        self.dirs = [os.path.join(SYMBOLS_DIR, "nvidia")] + list(extra_dirs or [])
        self.profiles: Dict[str, Profile] = {}
        self.errors: Dict[str, str] = {}
        self.layouts: Dict[str, Layout] = {}
        self.classes: Optional[ClassDatabase] = None
        self._load()

    def _load(self):
        for d in self.dirs:
            lp = os.path.join(d, "_layouts.json")
            if os.path.exists(lp):
                with open(lp, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)["layouts"]
                for name in raw:
                    self.layouts[name] = Layout(name, _resolve_layout(raw, name))
            cp = os.path.join(d, "_classes.json")
            if os.path.exists(cp):
                with open(cp, "r", encoding="utf-8") as fh:
                    self.classes = ClassDatabase(json.load(fh))
        for d in self.dirs:
            if not os.path.isdir(d):
                continue
            for fn in sorted(os.listdir(d)):
                if not fn.endswith(".json") or fn.startswith("_"):
                    continue
                path = os.path.join(d, fn)
                try:
                    p = self.load_file(path)
                    self.profiles[p.name] = p
                except (OSError, ValueError, KeyError, FormatError) as exc:
                    self.errors[path] = str(exc)

    def validate(self, doc: dict) -> List[str]:
        problems = [k for k in REQUIRED_KEYS if k not in doc]
        problems = ["missing key: %s" % k for k in problems]
        if doc.get("format") != "keto-profile/1":
            problems.append("unknown format %r" % doc.get("format"))
        mmu = doc.get("mmu", {})
        if mmu.get("format") not in ("v1", "v2", "v3"):
            problems.append("mmu.format must be v1, v2 or v3")
        if doc.get("layout") not in self.layouts:
            problems.append("unknown layout %r" % doc.get("layout"))
        return problems

    def load_file(self, path: str) -> Profile:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        problems = self.validate(doc)
        if problems:
            raise FormatError("; ".join(problems))
        return Profile(doc, self.layouts[doc["layout"]], path)

    # -- lookups ----------------------------------------------------------------
    def get(self, name: str) -> Profile:
        if name not in self.profiles:
            raise KeyError("unknown profile %r (available: %s)" % (name, ", ".join(sorted(self.profiles))))
        return self.profiles[name]

    def by_chipset(self, chipset: int) -> Optional[Profile]:
        for p in self.profiles.values():
            if chipset in p.chipsets:
                return p
        return None

    def by_nvml_arch(self, arch: int) -> Optional[Profile]:
        for p in self.profiles.values():
            if p.nvml_arch == arch:
                return p
        return None

    def by_compute_capability(self, cc: str) -> Optional[Profile]:
        for p in self.profiles.values():
            if cc in p.compute_capabilities:
                return p
        return None

    def by_device_name(self, name: str) -> Optional[Profile]:
        best, best_len = None, 0
        upper = name.upper()
        for p in self.profiles.values():
            for pat in p.name_patterns:
                if pat.upper() in upper and len(pat) > best_len:
                    best, best_len = p, len(pat)
        return best


_registry: Optional[ProfileRegistry] = None


def registry(extra_dirs: Optional[List[str]] = None) -> ProfileRegistry:
    global _registry
    if _registry is None or extra_dirs:
        _registry = ProfileRegistry(extra_dirs)
    return _registry
