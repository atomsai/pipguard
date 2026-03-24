"""Install packages from a local directory (post-scan)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def install_from_local(spec: str, find_links: Path) -> tuple[bool, str]:
    """Install *spec* using only local artifacts from *find_links*.

    Returns (success, output_text).
    """
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--no-index",
        "--find-links",
        str(find_links),
        spec,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    output = result.stdout + result.stderr
    return result.returncode == 0, output
