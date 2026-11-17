"""Plugin interface and registry.

Every plugin documents, as class attributes, the same three things the
Volatility 3 reference documents for each of its plugins:

* ``DESCRIPTION`` - what it does
* ``METHOD``      - how it does it (which structures / signatures / APIs)
* ``ANALOG``      - the Volatility 3 plugin(s) it is the GPU counterpart of

``SOURCES`` declares whether it needs a memory image (``"image"``), a live or
snapshotted system (``"live"``), or works with either.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import Dict, Iterator, List, Optional, Sequence, Tuple, Type

from keto.framework.exceptions import RequirementError
from keto.framework.treegrid import TreeGrid

log = logging.getLogger("keto.plugin")

PLUGINS: Dict[str, Type["Plugin"]] = {}


class Requirement:
    """A plugin option, turned into a command line flag by the CLI."""

    def __init__(self, name: str, kind=str, default=None, help: str = "", choices: Optional[Sequence] = None,
                 multiple: bool = False):
        self.name = name
        self.kind = kind          # str, int, bool, float, "size" (512M), "address" (0x...)
        self.default = default
        self.help = help
        self.choices = choices
        self.multiple = multiple

    @property
    def flag(self) -> str:
        return "--" + self.name.replace("_", "-")


class Plugin:
    NAME: str = ""
    CATEGORY: str = "misc"
    DESCRIPTION: str = ""
    METHOD: str = ""
    ANALOG: str = ""
    SOURCES: Tuple[str, ...] = ("image",)
    REQUIREMENTS: List[Requirement] = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.NAME:
            if cls.NAME in PLUGINS and PLUGINS[cls.NAME] is not cls:
                raise RuntimeError("duplicate plugin name %s" % cls.NAME)
            PLUGINS[cls.NAME] = cls

    def __init__(self, context, options: Optional[dict] = None):
        self.context = self.ctx = context
        opts = {r.name: r.default for r in self.REQUIREMENTS}
        opts.update({k: v for k, v in (options or {}).items() if v is not None})
        self.opts = opts
        self.log = logging.getLogger("keto." + self.NAME)
        self.check_sources()

    # -- environment checks --------------------------------------------------
    def check_sources(self):
        if "file" in self.SOURCES:
            return  # works from files named in its own options
        has_image = self.ctx.has_image()
        has_live = self.ctx.has_live()
        if "image" in self.SOURCES and "live" in self.SOURCES:
            if not (has_image or has_live):
                raise RequirementError("%s needs a memory image (-f) or a live/snapshot source (--live)" % self.NAME)
        elif "image" in self.SOURCES and not has_image:
            raise RequirementError("%s needs a memory image: use -f <image>" % self.NAME)
        elif "live" in self.SOURCES and not has_live:
            raise RequirementError("%s needs a live system (--live) or a snapshot image containing live state"
                                   % self.NAME)

    # -- interface ------------------------------------------------------------
    def run(self) -> TreeGrid:
        raise NotImplementedError

    @classmethod
    def describe(cls) -> dict:
        return {"name": cls.NAME, "category": cls.CATEGORY, "description": cls.DESCRIPTION,
                "method": cls.METHOD, "analog": cls.ANALOG, "sources": list(cls.SOURCES),
                "options": [{"flag": r.flag, "help": r.help, "default": r.default} for r in cls.REQUIREMENTS]}


class TimeLinerInterface:
    """Plugins that can contribute events to ``timeliner``."""

    def generate_timeline(self) -> Iterator[Tuple[str, str, object]]:
        """Yield ``(description, event_type, datetime)``."""
        raise NotImplementedError


_loaded = False
LOAD_ERRORS: Dict[str, str] = {}


def load_plugins() -> Dict[str, Type[Plugin]]:
    """Import every module under ``keto.plugins`` so plugins self-register.
    A module that fails to import is recorded in ``LOAD_ERRORS`` and skipped, so one
    broken plugin cannot take the whole tool down."""
    global _loaded
    if not _loaded:
        import keto.plugins as pkg
        for mod in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
            try:
                importlib.import_module(mod.name)
            except Exception as exc:
                LOAD_ERRORS[mod.name] = "%s: %s" % (type(exc).__name__, exc)
                log.error("failed to load plugin module %s: %s", mod.name, exc)
        _loaded = True
    return PLUGINS


def get_plugin(name: str) -> Type[Plugin]:
    load_plugins()
    if name in PLUGINS:
        return PLUGINS[name]
    # allow unambiguous suffix match: "chanscan" -> "nvidia.chanscan"
    matches = [n for n in PLUGINS if n.endswith("." + name) or n == name]
    if len(matches) == 1:
        return PLUGINS[matches[0]]
    raise KeyError(name if not matches else "ambiguous plugin %s: %s" % (name, ", ".join(sorted(matches))))
