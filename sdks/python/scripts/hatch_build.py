"""Hatchling build hook. Stamps each wheel with the right platform tag and
bundles the prebuilt zerobox binary as a shared_script. Pattern from deno_pypi."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REPO_ROOT = ROOT.parent.parent
NPM_PACKAGE_JSON = REPO_ROOT / "packages" / "zerobox" / "package.json"

TARGET_TAGS: dict[str, str] = {
    "aarch64-apple-darwin": "py3-none-macosx_11_0_arm64",
    "x86_64-apple-darwin": "py3-none-macosx_10_12_x86_64",
    "aarch64-unknown-linux-gnu": "py3-none-manylinux_2_17_aarch64",
    "x86_64-unknown-linux-gnu": "py3-none-manylinux_2_17_x86_64",
    "aarch64-unknown-linux-musl": "py3-none-musllinux_1_1_aarch64",
    "x86_64-unknown-linux-musl": "py3-none-musllinux_1_1_x86_64",
}


def _read_version() -> str:
    env_override = os.environ.get("ZEROBOX_VERSION")
    if env_override:
        return env_override
    try:
        data = json.loads(NPM_PACKAGE_JSON.read_text())
        return str(data["version"])
    except (OSError, KeyError, json.JSONDecodeError):
        return "0.0.0"


_SEMVER = re.compile(
    r"^(?P<release>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))"
    r"(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SEMVER_VERSION = _read_version()


def _invalid_semver(version: str) -> RuntimeError:
    return RuntimeError(
        f"zerobox version {version!r} does not look like a valid semver. "
        f"Check {NPM_PACKAGE_JSON}."
    )


def semver_to_pep440(version: str) -> str:
    """Represent SemVer prerelease/build identifiers as a PEP 440 local version."""
    match = _SEMVER.fullmatch(version)
    if match is None:
        raise _invalid_semver(version)

    prerelease = match["prerelease"]
    if prerelease is not None and any(
        identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0")
        for identifier in prerelease.split(".")
    ):
        raise _invalid_semver(version)

    local = [part for part in (match["prerelease"], match["build"]) if part]
    normalized_local = ".".join(local).replace("-", ".")
    return match["release"] + (f"+{normalized_local}" if normalized_local else "")

# Hatchling requires PEP 440 metadata. Keep the repository/package identity as
# SemVer while representing prerelease/build labels as a Python local version
# (`0.3.3-fork.1` -> `0.3.3+fork.1`).
VERSION = semver_to_pep440(_SEMVER_VERSION)


class ZeroboxBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        # `version` is hatchling's wheel variant ("standard" or "editable"),
        # not our semver. Skip sdist and editable installs; only standard
        # wheels need the prebuilt binary bundled in.
        if self.target_name != "wheel" or version == "editable":
            return

        target = os.environ.get("ZEROBOX_WHEEL_TARGET")
        if not target:
            raise RuntimeError(
                "ZEROBOX_WHEEL_TARGET is required to build a zerobox wheel. "
                f"Expected one of: {sorted(TARGET_TAGS)}"
            )

        tag = TARGET_TAGS.get(target)
        if tag is None:
            raise RuntimeError(
                f"Unknown ZEROBOX_WHEEL_TARGET={target!r}. "
                f"Expected one of: {sorted(TARGET_TAGS)}"
            )

        artifacts_dir = os.environ.get("ZEROBOX_ARTIFACTS_DIR")
        if not artifacts_dir:
            raise RuntimeError(
                "ZEROBOX_ARTIFACTS_DIR must point at a directory containing "
                "<target>/zerobox for each target being built."
            )

        binary = Path(artifacts_dir) / target / "zerobox"
        if not binary.exists():
            raise RuntimeError(f"prebuilt binary not found: {binary}")

        build_data["tag"] = tag
        build_data["shared_scripts"] = {str(binary): "zerobox"}
        build_data["pure_python"] = False
