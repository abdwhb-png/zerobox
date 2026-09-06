from __future__ import annotations

import sys
import types

import pytest

interface = types.ModuleType("hatchling.builders.hooks.plugin.interface")
interface.BuildHookInterface = object  # type: ignore[attr-defined]
for module_name in [
    "hatchling",
    "hatchling.builders",
    "hatchling.builders.hooks",
    "hatchling.builders.hooks.plugin",
]:
    sys.modules.setdefault(module_name, types.ModuleType(module_name))
sys.modules[interface.__name__] = interface

from scripts.hatch_build import VERSION, semver_to_pep440  # noqa: E402


def test_repository_version_is_generic_fork_release() -> None:
    assert VERSION == "0.3.3+fork.10"


@pytest.mark.parametrize(
    ("semver", "pep440"),
    [
        ("0.3.3", "0.3.3"),
        ("0.3.3-fork.1", "0.3.3+fork.1"),
        ("1.2.3-vendor-build.4+linux-x86-64", "1.2.3+vendor.build.4.linux.x86.64"),
    ],
)
def test_semver_to_pep440_is_label_agnostic(semver: str, pep440: str) -> None:
    assert semver_to_pep440(semver) == pep440


@pytest.mark.parametrize(
    "invalid",
    ["1.2", "1.2.3-", "01.2.3", "1.2.3-01", "1.2.3+bad label"],
)
def test_semver_to_pep440_rejects_invalid_semver(invalid: str) -> None:
    with pytest.raises(RuntimeError, match="valid semver"):
        semver_to_pep440(invalid)
