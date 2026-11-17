"""Helpers shared by NVIDIA plugins."""

from __future__ import annotations

from typing import Optional

from keto.framework.treegrid import NA, na
from keto.gpu import discovery


def channel_label(ctx, ib) -> str:
    """A stable human label for a channel: chid hint + instance block address."""
    chid = ib.chid_hint
    for rl in _safe_runlists(ctx):
        for c in rl.channels():
            if c.inst_addr == ib.pa:
                chid = c.chid
    return "ch%s@0x%x" % (chid if chid is not None else "?", ib.pa)


def _safe_runlists(ctx):
    try:
        return discovery.runlists(ctx)
    except Exception:
        return []


def runlist_membership(ctx):
    """``inst_pa -> (runlist_pa, tsgid, chid)`` for every channel in any runlist."""
    out = {}
    for rl in _safe_runlists(ctx):
        for g in rl.groups:
            for c in g.channels:
                out[c.inst_addr] = (rl.pa, g.header.tsgid, c.chid)
    return out


def aspace_name(aspace) -> str:
    return aspace.name if aspace is not None else "-"


def ap_short(aperture: Optional[str]) -> str:
    return aperture or "-"


def opt_or_na(value, reason="unknown"):
    return value if value is not None else na(reason)


def first(seq, default=None):
    for x in seq:
        return x
    return default


__all__ = ["channel_label", "runlist_membership", "aspace_name", "ap_short", "opt_or_na", "first", "NA", "na"]
