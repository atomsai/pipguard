"""Package allowlist support (future extension point)."""

from __future__ import annotations


class Allowlist:
    """In-memory allowlist for packages that have been manually reviewed."""

    def __init__(self) -> None:
        self._entries: set[str] = set()

    def add(self, package_name: str) -> None:
        self._entries.add(package_name.lower())

    def is_allowed(self, package_name: str) -> bool:
        return package_name.lower() in self._entries
