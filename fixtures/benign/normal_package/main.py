"""A completely benign Python package for testing."""


def hello(name: str = "world") -> str:
    """Return a greeting."""
    return f"Hello, {name}!"


def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
