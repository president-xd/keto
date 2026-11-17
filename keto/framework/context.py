"""The analysis context: opened layers, chosen profile, live source, output
directory and a cache shared by plugins (so ``psxview``-style cross-view
plugins and ``timeliner`` reuse results instead of rescanning)."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from keto.framework.exceptions import RequirementError, UnsupportedError
from keto.framework.layers import DataLayer, FileLayer
from keto.framework.profiles import Profile, registry

log = logging.getLogger("keto.context")


class Context:
    def __init__(self, image: Optional[str] = None, live: bool = False, host_image: Optional[str] = None,
                 profile: Optional[str] = None, output_dir: Optional[str] = None,
                 profile_dirs: Optional[List[str]] = None, snapshot: Optional[str] = None,
                 vram_size: Optional[int] = None):
        self.image_path = image
        self.layers: Dict[str, DataLayer] = {}
        self.primary_name: Optional[str] = None
        self.metadata: Dict[str, Any] = {}
        self.container = None
        self.cache: Dict[str, Any] = {}
        self.output_dir = output_dir
        self.registry = registry(profile_dirs)
        self.classdb = self.registry.classes
        self._profile_name = profile
        self._profile: Optional[Profile] = None
        self.profile_reason = ""
        self._live_requested = live
        self._snapshot_path = snapshot
        self._live = None
        self._vram_size_override = vram_size
        self.host_metadata: Dict[str, Any] = {}
        if image:
            self._open_image(image)
        if host_image:
            self._open_host(host_image)

    # -- image handling -------------------------------------------------------
    def _open_image(self, path: str):
        from keto.formats.container import Container, is_container, is_lime, open_lime
        if not os.path.exists(path):
            raise RequirementError("image not found: %s" % path)
        if is_container(path):
            self.container = Container(path)
            self.metadata = self.container.metadata
            self.layers.update(self.container.layers())
            for name in ("vram", "residual", "process", "gpuva", "sysmem", "bar1", "rom"):
                if name in self.layers:
                    self.primary_name = name
                    break
        elif is_lime(path):
            self.layers["physical"] = open_lime("physical", path)
            self.primary_name = "physical"
        else:
            self.layers["vram"] = FileLayer("vram", path)
            self.primary_name = "vram"
            side = path + ".json"
            if os.path.exists(side):
                with open(side, "r", encoding="utf-8") as fh:
                    self.metadata = json.load(fh)

    def _open_host(self, path: str):
        from keto.formats.container import Container, is_container, is_lime, open_lime
        if is_lime(path):
            self.layers["sysmem"] = open_lime("sysmem", path)
        elif is_container(path):
            cont = Container(path)
            layers = cont.layers()
            if "sysmem" not in layers:
                raise RequirementError("container %s has no sysmem segments" % path)
            self.layers["sysmem"] = layers["sysmem"]
            if "kbtf" in layers:
                self.layers["kbtf"] = layers["kbtf"]
            self.host_metadata = cont.metadata
        else:
            self.layers["sysmem"] = FileLayer("sysmem", path)

    def has_image(self) -> bool:
        return self.primary_name is not None

    @property
    def primary(self) -> DataLayer:
        if self.primary_name is None:
            raise RequirementError("no memory image loaded (use -f)")
        return self.layers[self.primary_name]

    @property
    def vram(self) -> Optional[DataLayer]:
        """The physical VRAM layer when the image is a VRAM dump (None otherwise)."""
        return self.layers.get("vram")

    @property
    def vram_size(self) -> Optional[int]:
        if self._vram_size_override:
            return self._vram_size_override
        dev = self.metadata.get("device", {})
        if dev.get("vram_size"):
            return int(dev["vram_size"])
        v = self.vram
        return (v.maximum_address + 1) if v is not None else None

    def aperture_layers(self) -> Dict[str, Optional[DataLayer]]:
        from keto.gpu.gmmu import SYS_COH, SYS_NCOH, VID
        sysmem = self.layers.get("sysmem")
        return {VID: self.vram, SYS_COH: sysmem, SYS_NCOH: sysmem, "sysmem": sysmem}

    # -- profile ------------------------------------------------------------------
    @property
    def profile(self) -> Profile:
        if self._profile is None:
            from keto.framework.automagic import choose_profile
            self._profile, self.profile_reason = choose_profile(self, self._profile_name)
        return self._profile

    # -- live source ----------------------------------------------------------------
    def has_live(self) -> bool:
        return self._live_requested or bool(self._snapshot_path) or "live_snapshot" in self.metadata

    @property
    def live(self):
        if self._live is None:
            from keto.live.source import ReplaySource, SystemSource
            if self._snapshot_path:
                with open(self._snapshot_path, "r", encoding="utf-8") as fh:
                    self._live = ReplaySource(json.load(fh))
            elif self._live_requested:
                self._live = SystemSource()
            elif "live_snapshot" in self.metadata:
                self._live = ReplaySource(self.metadata["live_snapshot"])
            else:
                raise RequirementError("no live source: use --live or an image that contains a snapshot")
        return self._live

    def set_live_source(self, source):
        self._live = source
        self._live_requested = True

    # -- output -------------------------------------------------------------------------
    def output_path(self, name: str) -> str:
        if not self.output_dir:
            raise RequirementError("this plugin writes files: pass an output directory with -o/--output-dir")
        os.makedirs(self.output_dir, exist_ok=True)
        safe = re.sub(r"[^\w.\-]+", "_", name)[:180]
        path = os.path.join(self.output_dir, safe)
        base, ext = os.path.splitext(path)
        i = 1
        while os.path.exists(path):
            path = "%s.%d%s" % (base, i, ext)
            i += 1
        return path

    def close(self):
        """Release file handles / memory maps (needed on Windows before deleting images)."""
        for layer in list(self.layers.values()):
            if hasattr(layer, "close"):
                try:
                    layer.close()
                except (OSError, ValueError):
                    pass
        if self.container is not None:
            self.container.file_layer().close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def cached(self, key: str, factory):
        if key not in self.cache:
            self.cache[key] = factory()
        return self.cache[key]

    def require_vram(self) -> DataLayer:
        if self.vram is None:
            loaded = ", ".join(sorted(self.layers)) or "none"
            raise UnsupportedError("this analysis needs a physical VRAM image (layer 'vram'); loaded layers: %s"
                                   % loaded)
        return self.vram
