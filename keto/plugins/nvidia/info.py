"""Image-level information."""

from __future__ import annotations

import json

from keto.framework.exceptions import UnsupportedError
from keto.framework.plugin import Plugin
from keto.framework.treegrid import TreeGrid
from keto.framework.util import human_size
from keto.gpu import discovery


class Info(Plugin):
    NAME = "nvidia.info"
    CATEGORY = "nvidia.system"
    DESCRIPTION = ("Shows what the memory image is: device identity, architecture profile and why it was chosen, "
                   "VRAM size, acquisition method/notes, loaded layers, and a census of GPU structures found.")
    METHOD = ("Reads container metadata (device, acquisition), runs profile detection (chipset/NVML arch/compute "
              "capability/banners), and counts instance blocks, runlists, address spaces, cubins and launches.")
    ANALOG = "windows.info / windows.crashinfo"

    def run(self):
        ctx = self.ctx
        meta = ctx.metadata
        rows = []

        def add(k, v, depth=0):
            rows.append((depth, (k, v if isinstance(v, str) else json.dumps(v, default=str))))

        add("Image", ctx.image_path or "-")
        add("Format", "Keto container v%d" % ctx.container.version if ctx.container else
            ("LiME" if ctx.primary_name == "physical" else "raw"))
        prof = ctx.profile
        add("Profile", "%s (%s, %s MMU, layout %s)" % (prof.name, prof.architecture, prof.mmu_format.upper(),
                                                       prof.layout.name))
        add("Profile reason", ctx.profile_reason)
        add("VRAM size", human_size(ctx.vram_size) if ctx.vram_size else "-")
        for k, v in (meta.get("device") or {}).items():
            add("Device." + k, str(v))
        acq = meta.get("acquisition") or {}
        for k in ("method", "examiner", "notes", "captured", "nonzero_bytes", "source_file"):
            if k in acq:
                add("Acquisition." + k, str(acq[k]))
        if meta.get("created_utc"):
            add("Acquired (UTC)", meta["created_utc"])
        if "live_snapshot" in meta:
            add("Live snapshot", "%d recorded queries" % len(meta["live_snapshot"].get("records", {})))
        for name, layer in sorted(ctx.layers.items()):
            add("Layer " + name, layer.describe())
        if ctx.vram is not None:
            census = [("Instance blocks", lambda: len(discovery.instance_blocks(ctx))),
                      ("Runlists", lambda: len(discovery.runlists(ctx))),
                      ("Address spaces", lambda: len(discovery.address_spaces(ctx))),
                      ("Cubins", lambda: len(discovery.cubins(ctx))),
                      ("PTX modules", lambda: len(discovery.ptx_modules(ctx))),
                      ("Kernel launches", lambda: len(discovery.launches(ctx)))]
            for label, fn in census:
                try:
                    add(label, str(fn()))
                except UnsupportedError as exc:
                    add(label, "n/a (%s)" % exc)
        return TreeGrid([("Variable", str), ("Value", str)], rows)
