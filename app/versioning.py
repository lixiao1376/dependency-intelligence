"""Version parsing helpers shared by registry and release clients."""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version


VERSION_IN_TEXT = re.compile(r"(?<!\d)v?(\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?)")


def parse_version(value: str | None) -> Version | None:
    if not value:
        return None
    candidate = value.strip().lstrip("vV")
    try:
        return Version(candidate)
    except InvalidVersion:
        match = VERSION_IN_TEXT.search(candidate)
        if not match:
            return None
        try:
            return Version(match.group(1))
        except InvalidVersion:
            return None


def stable_versions(values: list[str]) -> list[Version]:
    parsed = [version for value in values if (version := parse_version(value))]
    return sorted({version for version in parsed if not version.is_prerelease and not version.is_devrelease})


def in_upgrade_range(version: str, current: str, target: str) -> bool:
    parsed, lower, upper = parse_version(version), parse_version(current), parse_version(target)
    return bool(parsed and lower and upper and lower < parsed <= upper)

