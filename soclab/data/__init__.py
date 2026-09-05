"""Runtime data bundled with the package.

The attack and incident scenarios and the Rego policy live here so an
installed wheel is self sufficient: ``uvx soclab demo`` needs nothing from a
repository checkout. This directory is the only copy. Docker mounts and the
``opa test`` target point at it too.

Two environment variables override the locations for containers and
experiments. Both are optional.

* ``SOCLAB_SCENARIO_DIR``: a folder with ``attacks/`` and ``incidents/``.
* ``SOCLAB_POLICY_DIR``: a folder of ``.rego`` files.
"""

from __future__ import annotations

import os
from importlib import resources
from pathlib import Path


def bundled_path(*parts: str) -> Path:
    """Filesystem path of a bundled data file or folder.

    Wheels are installed unpacked, so the traversable is always a real path.
    """
    node = resources.files(__package__)
    for part in parts:
        node = node.joinpath(part)
    return Path(str(node))


def scenario_dir() -> Path:
    """Folder that holds ``attacks/`` and ``incidents/``."""
    override = os.environ.get("SOCLAB_SCENARIO_DIR")
    return Path(override) if override else bundled_path("scenarios")


def policy_dir() -> Path:
    """Folder of Rego files loaded by OPA."""
    override = os.environ.get("SOCLAB_POLICY_DIR")
    return Path(override) if override else bundled_path("policies")
