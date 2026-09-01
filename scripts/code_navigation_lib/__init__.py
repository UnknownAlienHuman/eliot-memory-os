"""Repository-owned crate/module/logical-block navigation primitives."""

from .common import NavigationError
from .registry import build_registry
from .routing import (
    check,
    render_blocks,
    render_crates,
    render_modules,
    render_route,
    route_payload,
)
from .selftest import self_test

__all__ = [
    "NavigationError",
    "build_registry",
    "check",
    "render_blocks",
    "render_crates",
    "render_modules",
    "render_route",
    "route_payload",
    "self_test",
]
