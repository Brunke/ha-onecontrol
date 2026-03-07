"""Shared test fixtures.

Stubs optional dependencies only when they are unavailable in the active
environment so tests can run both with and without Home Assistant installed.
"""

import importlib
import sys
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ── Stub out homeassistant and friends so __init__.py can be imported ────


class _StubModule(MagicMock):
    """A MagicMock that acts as a module for `from X import Y` support."""

    def __repr__(self) -> str:
        return f"<StubModule {self._mock_name!r}>"


_STUBS = [
    "homeassistant",
    "homeassistant.config_entries",
    "homeassistant.core",
    "homeassistant.const",
    "homeassistant.helpers",
    "homeassistant.helpers.update_coordinator",
    "homeassistant.helpers.device_registry",
    "homeassistant.helpers.entity_platform",
    "homeassistant.components",
    "homeassistant.components.bluetooth",
    "homeassistant.components.sensor",
    "voluptuous",
    "bleak",
    "bleak.exc",
]

for _name in _STUBS:
    try:
        importlib.import_module(_name)
    except Exception:  # noqa: BLE001
        sys.modules.setdefault(_name, _StubModule(name=_name))
