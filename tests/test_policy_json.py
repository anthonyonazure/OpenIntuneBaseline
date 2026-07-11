"""
Data-validation tests for the Intune policy JSON exports in this repo.

This repo has no application code to unit-test -- what it ships is a tree of
Intune policy JSON exports (WINDOWS/, MACOS/, WINDOWS365/, BYOD/) plus docs
and PowerShell scripts. "Testing" here means validating that tree so drift
or corruption (bad exports, merge damage, accidental hand-edits, encoding
mangling) gets caught in CI instead of silently reaching someone's tenant.

How to run locally
-------------------
    python3 -m venv .venv && source .venv/bin/activate   # optional
    pip install -r tests/requirements.txt
    pytest tests/ -v

No network access or Intune/Graph credentials are needed -- everything here
is static analysis of the checked-in JSON files.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest

from policy_utils import (
    NAMING_PATTERNS,
    category_of,
    discover_policy_files,
    load_policy_json,
    platform_of,
    policy_id,
    policy_name,
    read_text,
    rel,
)

ALL_FILES: list[Path] = discover_policy_files()


def _id(path: Path) -> str:
    return rel(path)


# ---------------------------------------------------------------------------
# Sanity: we actually found policy files to test. If this starts failing,
# the discovery globs in policy_utils.py no longer match the repo layout
# (e.g. a platform directory got renamed) -- every other test in this file
# would otherwise pass vacuously.
# ---------------------------------------------------------------------------


def test_discovered_policy_files_is_nonempty():
    assert len(ALL_FILES) > 0, "No policy JSON files were discovered under WINDOWS/MACOS/WINDOWS365/BYOD"


def test_discovery_covers_all_platform_json(request):
    """Cross-check discovery against a raw filesystem walk.

    Guards against someone tightening discover_policy_files() (e.g. back to
    a *IntuneManagement/**/*.json-only glob) and silently dropping the
    NativeImport/ and BYOD/AppProtection/ files that also carry real
    policies.
    """
    root = Path(__file__).resolve().parent.parent
    expected = set()
    for platform in ("WINDOWS", "MACOS", "WINDOWS365", "BYOD"):
        expected.update((root / platform).rglob("*.json"))
    assert set(ALL_FILES) == expected


# ---------------------------------------------------------------------------
# Check 1: every file parses as valid JSON once correctly decoded.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ALL_FILES, ids=_id)
def test_file_is_valid_json(path: Path):
    doc = load_policy_json(path)
    assert isinstance(doc, dict), f"{rel(path)}: expected a top-level JSON object, got {type(doc).__name__}"


@pytest.mark.parametrize("path", ALL_FILES, ids=_id)
def test_file_has_no_leftover_bom_characters(path: Path):
    """Decoding with the wrong codec (or forgetting utf-8-sig) leaves a
    stray U+FEFF at the start of the text, which happens to still round-trip
    through some lenient JSON parsers as a key/string oddity. Assert it's
    really gone after our encoding-aware read."""
    text = read_text(path)
    assert not text.startswith("﻿"), f"{rel(path)}: BOM character leaked into decoded text"


# ---------------------------------------------------------------------------
# Check 2: filenames follow the platform's naming convention.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ALL_FILES, ids=_id)
def test_filename_matches_platform_naming_convention(path: Path):
    platform = platform_of(path)
    pattern = NAMING_PATTERNS[platform]
    assert pattern.match(path.name), (
        f"{rel(path)}: filename does not match the {platform} naming convention "
        f"({pattern.pattern})"
    )


# ---------------------------------------------------------------------------
# Check 3: no duplicate policy names or ids within a category.
#
# "Category" = a file's immediate parent directory (e.g.
# WINDOWS/IntuneManagement/CompliancePolicies, or MACOS/NativeImport). This
# deliberately does NOT dedupe across IntuneManagement/<Category> vs.
# NativeImport -- MacOS and Windows365 legitimately export identical
# policies (same name, same id) into both trees, once in the full Graph API
# shape and once in the trimmed NativeImport shape. That pairing is expected
# and covered separately below; it is not a same-category collision.
# ---------------------------------------------------------------------------


def _group_by_category():
    names = defaultdict(list)
    ids = defaultdict(list)
    for path in ALL_FILES:
        doc = load_policy_json(path)
        cat = category_of(path)
        name = policy_name(doc)
        pid = policy_id(doc)
        if name is not None:
            names[(cat, name)].append(path)
        if pid is not None:
            ids[(cat, pid)].append(path)
    return names, ids


_NAMES_BY_CATEGORY, _IDS_BY_CATEGORY = _group_by_category()


@pytest.mark.parametrize(
    "key",
    [k for k, v in _NAMES_BY_CATEGORY.items() if len(v) > 1],
    ids=lambda k: f"{k[0]}::{k[1]}",
)
def test_no_duplicate_policy_name_within_category(key):
    files = _NAMES_BY_CATEGORY[key]
    pytest.fail(f"Duplicate policy name {key[1]!r} in {key[0]}: {[rel(f) for f in files]}")


@pytest.mark.parametrize(
    "key",
    [k for k, v in _IDS_BY_CATEGORY.items() if len(v) > 1],
    ids=lambda k: f"{k[0]}::{k[1]}",
)
def test_no_duplicate_policy_id_within_category(key):
    files = _IDS_BY_CATEGORY[key]
    pytest.fail(f"Duplicate policy id {key[1]!r} in {key[0]}: {[rel(f) for f in files]}")


# ---------------------------------------------------------------------------
# Check 4: structural invariants observed across real files.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ALL_FILES, ids=_id)
def test_has_odata_context(path: Path):
    """Every export in this repo (Graph API exports and NativeImport alike)
    carries an @odata.context pointing back at the source Graph endpoint."""
    doc = load_policy_json(path)
    assert doc.get("@odata.context"), f"{rel(path)}: missing/empty @odata.context"


@pytest.mark.parametrize("path", ALL_FILES, ids=_id)
def test_has_nonempty_id(path: Path):
    doc = load_policy_json(path)
    pid = doc.get("id")
    assert isinstance(pid, str) and pid.strip(), f"{rel(path)}: missing/empty id"


@pytest.mark.parametrize("path", ALL_FILES, ids=_id)
def test_has_nonempty_name(path: Path):
    """Every policy has a human-readable name under displayName (compliance
    / app protection policies) or name (Settings Catalog / NativeImport)."""
    doc = load_policy_json(path)
    name = policy_name(doc)
    assert isinstance(name, str) and name.strip(), f"{rel(path)}: missing/empty displayName and name"


@pytest.mark.parametrize("path", ALL_FILES, ids=_id)
def test_body_version_field_when_present_is_sane(path: Path):
    """Only 14/114 files carry a top-level `version` field at all, and it
    means two different things depending on policy type:
      - device compliance policies (WINDOWS/*/CompliancePolicies): a
        non-negative int revision counter bumped by Graph on each edit.
      - BYOD app protection policies: an opaque ETag-like string.
    Neither matches the "vX.Y" in the filename -- that's a curation-time
    label, not a Graph-assigned value -- so we don't compare the two. We
    just assert that when `version` exists, it isn't null/empty garbage.
    """
    doc = load_policy_json(path)
    version = doc.get("version")
    if version is None:
        return
    if isinstance(version, int):
        assert version >= 0, f"{rel(path)}: negative integer version {version!r}"
    elif isinstance(version, str):
        assert version.strip(), f"{rel(path)}: empty string version"
    else:
        pytest.fail(f"{rel(path)}: unexpected `version` type {type(version).__name__} ({version!r})")
