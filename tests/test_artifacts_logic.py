#!/usr/bin/env python3
"""Unit tests for artifacts.py build-flow detection via the type=build annotation."""

import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bin'))
import artifacts  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), 'artifacts')

# kosli get artifact requires a full 64-hex fingerprint (^[a-f0-9]{64}$).
FINGERPRINT = "cafebabe00000000cafebabe00000000cafebabe00000000cafebabe00000000"


def _load(name):
    """Load a snapshot or expected-output JSON fixture by filename."""
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


def _fetch_from(annotations_by_flow):
    """Return a fake fetch_annotations backed by a flow_name -> annotations dict (ignores fingerprint)."""
    def fetch(flow_name, fingerprint):
        """Return the canned annotations dict for flow_name."""
        return annotations_by_flow[flow_name]
    return fetch


def test_b4e1f201():
    """A flow whose attestation carries annotation type=build is included as a build flow."""
    snapshot = _load('github-artifact.snapshot.json')
    fetch = _fetch_from({"runner-ci": {"type": "build"}})
    result = artifacts.artifacts(snapshot, fetch=fetch)
    assert result == _load('expected/github-artifact.json')


def test_b4e1f202():
    """A flow whose attestation has no type=build annotation is excluded from the matrix."""
    snapshot = _load('non-build-flow.snapshot.json')
    fetch = _fetch_from({"runner-ci": {"type": "build"}, "aws-snyk-scan": {}})
    result = artifacts.artifacts(snapshot, fetch=fetch)
    assert result == _load('expected/non-build-flow.json')


def test_b4e1f203():
    """An exited artifact is excluded, and its flows are never queried for annotations."""
    snapshot = _load('exited-artifact.snapshot.json')
    fetch = _fetch_from({"differ-ci": {"type": "build"}})
    result = artifacts.artifacts(snapshot, fetch=fetch)
    assert result == _load('expected/exited-artifact.json')


def test_b4e1f204():
    """A gitlab build flow yields a gitlab raw .snyk policy url."""
    snapshot = _load('gitlab-artifact.snapshot.json')
    fetch = _fetch_from({"creator-ci": {"type": "build"}})
    result = artifacts.artifacts(snapshot, fetch=fetch)
    assert result == _load('expected/gitlab-artifact.json')


def test_b4e1f205(capsys):
    """An unknown CI system in a build flow's commit url exits non-zero with an error on stderr."""
    snapshot = _load('unknown-ci-system.snapshot.json')
    fetch = _fetch_from({"custom-start-points-ci": {"type": "build"}})
    with pytest.raises(SystemExit) as exc:
        artifacts.artifacts(snapshot, fetch=fetch)
    assert exc.value.code == 42
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "ERROR: Unknown CI system "
        "https://gitunknown.com/cyber-dojo/custom-start-points/commit/"
        "deadbeef0000000000000000000000000000cafe\n"
    )


def test_b4e1f208():
    """repo_name is derived from the commit_url, not the flow name: a build flow whose name does not end in -ci still gets the correct repo_name."""
    snapshot = _load('build-flow-non-ci-name.snapshot.json')
    fetch = _fetch_from({"runner": {"type": "build"}})
    result = artifacts.artifacts(snapshot, fetch=fetch)
    assert result == _load('expected/build-flow-non-ci-name.json')


def test_b4e1f20a():
    """artifacts passes each flow's own flow_name and the artifact's fingerprint through to the fetcher."""
    snapshot = _load('non-build-flow.snapshot.json')
    expected_fingerprint = snapshot["artifacts"][0]["fingerprint"]
    seen = []

    def fetch(flow_name, fingerprint):
        """Record the (flow_name, fingerprint) it is asked about; treat none as a build flow."""
        seen.append((flow_name, fingerprint))
        return {}
    artifacts.artifacts(snapshot, fetch=fetch)
    assert seen == [
        ("runner-ci", expected_fingerprint),
        ("aws-snyk-scan", expected_fingerprint),
    ]


def test_b4e1f209(monkeypatch):
    """fetch_annotations runs kosli with a restricted environment containing only PATH, and returns the annotations dict."""
    monkeypatch.setenv("KOSLI_HOST", "https://app.kosli.com")
    monkeypatch.setenv("KOSLI_ORG", "cyber-dojo")
    monkeypatch.setenv("KOSLI_API_TOKEN", "throwaway-readonly")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    calls = {}

    class FakeCompleted:
        """Stand-in for the CompletedProcess returned by subprocess.run."""
        stdout = '{"annotations": {"type": "build"}}'

    def capture(*args, **kwargs):
        """Record the subprocess.run arguments instead of running kosli."""
        calls["args"] = args
        calls["kwargs"] = kwargs
        return FakeCompleted()
    monkeypatch.setattr(artifacts.subprocess, "run", capture)
    result = artifacts.fetch_annotations("runner-ci", FINGERPRINT)
    assert result == {"type": "build"}
    assert calls["kwargs"]["env"] == {"PATH": "/usr/bin:/bin"}
    assert calls["args"][0][0] == "kosli"


def test_b4e1f206(capsys, monkeypatch):
    """fetch_annotations exits non-zero with an error on stderr when the kosli call fails."""
    monkeypatch.setenv("KOSLI_HOST", "https://app.kosli.com")
    monkeypatch.setenv("KOSLI_ORG", "cyber-dojo")
    monkeypatch.setenv("KOSLI_API_TOKEN", "throwaway-readonly")
    def boom(*args, **kwargs):
        """Simulate a failed kosli invocation."""
        raise subprocess.CalledProcessError(1, args[0])
    monkeypatch.setattr(artifacts.subprocess, "run", boom)
    with pytest.raises(SystemExit) as exc:
        artifacts.fetch_annotations("runner-ci", FINGERPRINT)
    assert exc.value.code == 43
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith(f"ERROR: Could not read annotations for runner-ci@{FINGERPRINT}")


def test_b4e1f207(capsys, monkeypatch):
    """fetch_annotations exits non-zero with a clear message when a required KOSLI_ env var is unset."""
    monkeypatch.delenv("KOSLI_HOST", raising=False)
    monkeypatch.setenv("KOSLI_ORG", "cyber-dojo")
    monkeypatch.setenv("KOSLI_API_TOKEN", "throwaway-readonly")
    with pytest.raises(SystemExit) as exc:
        artifacts.fetch_annotations("runner-ci", FINGERPRINT)
    assert exc.value.code == 44
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "ERROR: KOSLI_HOST must be set\n"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
