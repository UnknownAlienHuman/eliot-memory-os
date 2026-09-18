"""Metadata-python check for 837 integration (non-Rust observation shape)."""


def check_metadata(payload: dict) -> bool:
    return isinstance(payload, dict) and payload.get("mode") == "metadata-python"
