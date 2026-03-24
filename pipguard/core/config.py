"""Global configuration for pipguard."""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(slots=True)
class ScanConfig:
    """Runtime configuration for a scan pass."""

    policy: str = "block"  # block | warn
    allow_high: bool = False
    allow_critical: bool = False
    json_out: str | None = None
    ioc_pack: str | None = None
    verbose: bool = False
