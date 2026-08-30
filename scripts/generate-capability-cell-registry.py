#!/usr/bin/env python3
"""Compile non-authoritative, scope-explicit capability-cell evidence."""

from capability_cell_registry import RegistryError, compile_registry, fixture, source_identity
from capability_cell_registry.cli import run

__all__ = ["RegistryError", "compile_registry", "fixture", "source_identity"]

if __name__ == "__main__":
    run()
