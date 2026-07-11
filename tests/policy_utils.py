"""
Shared helpers for validating the Intune policy JSON exports in this repo.

The IntuneManagement export tool writes policy files as UTF-16LE with a BOM;
files under NativeImport/ are exported as UTF-8 (usually with a BOM); a
handful of hand-authored files (BYOD/AppProtection) are plain UTF-8 with no
BOM at all. None of this is corruption -- it's just how the different export
paths behave -- but it does mean a naive `open(path).read()` or
`json.load()` will misread roughly 80% of the files in this repo. Every
helper in this module sniffs the BOM instead of assuming one encoding.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

# Repo root is the parent of the tests/ directory this file lives in.
REPO_ROOT = Path(__file__).resolve().parent.parent

# Platform directories that hold policy JSON exports. BYOD does not use the
# IntuneManagement/NativeImport split the other platforms use -- its policy
# files live directly under BYOD/AppProtection.
PLATFORM_DIRS = ["WINDOWS", "MACOS", "WINDOWS365", "BYOD"]

# BOM signatures, longest first so UTF-8's 3-byte BOM is checked before any
# accidental 2-byte prefix match.
_UTF8_BOM = b"\xef\xbb\xbf"
_UTF16_LE_BOM = b"\xff\xfe"
_UTF16_BE_BOM = b"\xfe\xff"


def discover_policy_files(root: Path = REPO_ROOT) -> list[Path]:
    """Return every policy JSON file under the known platform directories.

    Deliberately does NOT hardcode `*/IntuneManagement/**/*.json` -- MACOS
    and WINDOWS365 also ship a NativeImport/ subtree, and BYOD ships policy
    JSON directly under AppProtection/ with no IntuneManagement wrapper at
    all. Walking each platform directory for *.json keeps this correct
    regardless of which subfolder shape a given platform uses.
    """
    files: list[Path] = []
    for platform in PLATFORM_DIRS:
        platform_dir = root / platform
        if not platform_dir.is_dir():
            continue
        files.extend(sorted(platform_dir.rglob("*.json")))
    return sorted(files)


def sniff_encoding(data: bytes) -> str:
    """Identify the text encoding of a policy JSON file from its BOM.

    Returns one of: 'utf-16-le-bom', 'utf-16-be-bom', 'utf-8-bom', 'utf-8'.
    Falls back to plain UTF-8 (no BOM) for files like BYOD/AppProtection/*
    that were authored/saved without one.
    """
    if data[:2] == _UTF16_LE_BOM:
        return "utf-16-le-bom"
    if data[:2] == _UTF16_BE_BOM:
        return "utf-16-be-bom"
    if data[:3] == _UTF8_BOM:
        return "utf-8-bom"
    return "utf-8"


_ENCODING_TO_CODEC = {
    "utf-16-le-bom": "utf-16",  # utf-16 codec auto-detects LE/BE from the BOM
    "utf-16-be-bom": "utf-16",
    "utf-8-bom": "utf-8-sig",
    "utf-8": "utf-8",
}


def read_text(path: Path) -> str:
    """Read a policy file's text, decoding it with its actual encoding."""
    data = path.read_bytes()
    encoding = sniff_encoding(data)
    codec = _ENCODING_TO_CODEC[encoding]
    return data.decode(codec)


def load_policy_json(path: Path):
    """Decode (encoding-aware) and JSON-parse a single policy file."""
    return json.loads(read_text(path))


def policy_name(doc: dict) -> str | None:
    """Best-effort extraction of a policy's human-readable name.

    Compliance/App-protection policy exports use `displayName`; Settings
    Catalog / NativeImport exports use `name`. Both are seen in this repo.
    """
    if not isinstance(doc, dict):
        return None
    return doc.get("displayName") or doc.get("name")


def policy_id(doc: dict) -> str | None:
    if not isinstance(doc, dict):
        return None
    return doc.get("id")


# --- Filename naming convention -------------------------------------------
#
# Inspected from the real filenames on disk (2026-07):
#   WINDOWS:    "Win - OIB - <area...> - vX.Y[.Z].json"
#   WINDOWS365: "Win365 - OIB - <area...> - vX.Y[.Z].json"
#   MACOS:      "MacOS - OIB - <area...> - vX.Y[.Z].json"
#   BYOD:       "iOS - Baseline - BYOD - <name>.json" / "Android - Baseline - BYOD - <name>.json"
#
# Note the "<area...>" segment does NOT reliably contain a " - D - " or
# " - U - " (Device/User) token -- e.g.
# "Win - OIB - WUfB - Ring 1 - Pilot - v3.0.json" has none -- so the pattern
# intentionally does not require one. BYOD filenames carry no version suffix
# at all (there is exactly one exported revision of each).
NAMING_PATTERNS: dict[str, re.Pattern] = {
    "WINDOWS": re.compile(r"^Win - OIB - .+ - v\d+(\.\d+){1,2}\.json$"),
    "WINDOWS365": re.compile(r"^Win365 - OIB - .+ - v\d+(\.\d+){1,2}\.json$"),
    "MACOS": re.compile(r"^MacOS - OIB - .+ - v\d+(\.\d+){1,2}\.json$"),
    "BYOD": re.compile(r"^(iOS|Android) - Baseline - BYOD - .+\.json$"),
}


def platform_of(path: Path, root: Path = REPO_ROOT) -> str:
    return path.relative_to(root).parts[0]


def category_of(path: Path) -> Path:
    """The 'category' a policy belongs to, for duplicate-name/id checks.

    This is the file's immediate parent directory, e.g.
    WINDOWS/IntuneManagement/CompliancePolicies or MACOS/NativeImport.
    Scoping duplicate checks to this level (rather than repo-wide, or even
    per-platform) matters: MACOS/WINDOWS365 legitimately export the *same*
    policy twice -- once under IntuneManagement/<Category>/ (full Graph API
    shape) and once under NativeImport/ (trimmed shape for direct import).
    Those pairs share both name and id by design and are not duplicates.
    """
    return path.parent


@dataclass(frozen=True)
class PolicyFile:
    path: Path
    relpath: str


def rel(path: Path, root: Path = REPO_ROOT) -> str:
    return str(path.relative_to(root))
