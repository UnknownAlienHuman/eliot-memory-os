"""Public compiler API used by the CLI and independent verifier."""

from .compiler import compile_registry
from .fixtures import fixture
from .model import RegistryError, source_identity

__all__ = ["RegistryError", "compile_registry", "fixture", "source_identity"]
