"""File loading helpers for AppSec rules pack validation."""

from pathlib import Path
from typing import Any

import yaml


def load_yaml_file(path: Path) -> Any:
    """Load a YAML file with safe parsing."""

    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)
