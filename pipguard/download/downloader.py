"""Download packages using pip."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def download_packages(spec: str, dest: Path) -> tuple[bool, str]:
    """Download *spec* and its dependencies into *dest*.

    Returns (success, output_text).
    """
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "-d",
        str(dest),
        spec,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    output = result.stdout + result.stderr
    return result.returncode == 0, output
