"""AST analysis context for a single Python file."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ASTContext:
    """Per-file AST analysis context used by detectors."""

    path: Path
    source: str = ""
    tree: ast.AST | None = None
    imports: list[str] = field(default_factory=list)
    function_calls: list[str] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    detected_sources: list[str] = field(default_factory=list)
    detected_sinks: list[str] = field(default_factory=list)
    is_top_level: bool = True

    @classmethod
    def from_file(cls, path: Path) -> "ASTContext":
        """Build an ASTContext from a Python source file."""
        ctx = cls(path=path)
        try:
            ctx.source = path.read_text(errors="replace")
        except OSError:
            return ctx

        try:
            ctx.tree = ast.parse(ctx.source, filename=str(path))
        except SyntaxError:
            return ctx

        for node in ast.walk(ctx.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    ctx.imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    ctx.imports.append(node.module)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                ctx.string_literals.append(node.value)

        return ctx
