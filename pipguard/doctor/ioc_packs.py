"""Built-in IOC packs registry (re-exports from detectors.ioc_detector)."""

from __future__ import annotations

from pipguard.detectors.ioc_detector import IOC_PACKS, get_pack, list_packs

__all__ = ["IOC_PACKS", "get_pack", "list_packs"]
