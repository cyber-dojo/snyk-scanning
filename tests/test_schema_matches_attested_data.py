#!/usr/bin/env python3
"""Contract test: single-snyk-vuln.schema.json must match the per-vuln data actually attested."""

import json
import os
import subprocess
import sys

import pytest

MY_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.join(MY_DIR, "..")
SCHEMA_FILE = os.path.join(ROOT_DIR, "single-snyk-vuln.schema.json")
COMBINE = os.path.join(ROOT_DIR, "bin", "combine_snyk.py")
COMBINE_DIR = os.path.join(MY_DIR, "combine-snyk")

# Keys the workflow's "Add time vuln first seen in the repo" step injects into
# each vuln dict after combine_snyk.py and before the data is attested.
WORKFLOW_ADDED_KEYS = {"first_seen_ts", "first_seen"}


def attested_vuln_keys():
    """Return the keys of one per-vuln object as actually attested (combine output plus workflow-added keys)."""
    result = subprocess.run(
        [sys.executable, COMBINE, "1748736000", "1.0.0", "test-repo",
         os.path.join(COMBINE_DIR, "one-medium.sarif.json"),
         os.path.join(COMBINE_DIR, "no-ignore.snyk.yaml"),
         "/dev/null",
         "registry/test-repo:tag@sha256:abc123", "abc123"],
        capture_output=True, text=True, check=True)
    return set(json.loads(result.stdout)[0].keys()) | WORKFLOW_ADDED_KEYS


def load_schema():
    """Load the attestation-type JSON schema."""
    with open(SCHEMA_FILE) as f:
        return json.load(f)


def test_5e1a7c01():
    """The schema's properties are exactly the fields actually attested."""
    assert set(load_schema()["properties"].keys()) == attested_vuln_keys()


def test_5e1a7c02():
    """The schema requires exactly the fields actually attested."""
    assert set(load_schema()["required"]) == attested_vuln_keys()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
