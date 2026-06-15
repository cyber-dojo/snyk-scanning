#!/usr/bin/env python3

import json
import os
import subprocess
import sys


def print_help():
    print("""
        Reads (from stdin) the result of a 'kosli get snapshot $ENV --org=cyber-dojo ... --output=json'.
        Writes (to stdout) a JSON array with one dict for each Artifact running in $ENV.
        This JSON can be used as the source for a Github Action strategy:matrix:include to run a parallel job for each Artifact.

        Example:

          $ ./bin/kosli_get_snapshot_json.sh | ./bin/artifacts.py
          [
            {
              "artifact_name": "244531986313.dkr.ecr.eu-central-1.amazonaws.com/languages-start-points:8836628@sha256:1d7fc67092bee8492e5019ca0175edf5189e4fc71a4b3a21976c64070def810a",
              "artifact_fingerprint": "1d7fc67092bee8492e5019ca0175edf5189e4fc71a4b3a21976c64070def810a",
              "flow_name": "languages-start-points-ci",
              "git_commit": "88366281011d1aa83c5db4280aa8a6daa0be8541",
              "repo_name": "languages-start-points",
              "snapshot_index": 3600,
              "snapshot_artifact_url": "https://app.kosli.com/cyber-dojo/environments/aws-prod/snapshots/3600?fingerprint=1d7fc67092bee8492e5019ca0175edf5189e4fc71a4b3a21976c64070def810a",
              "raw_snyk_policy_url": "https://raw.githubusercontent.com/cyber-dojo/languages-start-points/commit/88366281011d1aa83c5db4280aa8a6daa0be8541/.snyk"
            },          
            ...
          ]
    """)


def artifacts(raw, fetch=None):
    """
    Transform a parsed snapshot dict into the scanning matrix list, one entry per
    (artifact, build-flow) pair. 'fetch' is the annotation fetcher injected for
    testing; it defaults to the real 'fetch_annotations' that calls kosli.
    """
    if fetch is None:
        fetch = fetch_annotations
    result = []
    snapshot_index = raw["index"]
    html_url = raw["html_url"]
    for artifact in raw["artifacts"]:
        annotation_type = artifact["annotation"]["type"]
        if annotation_type != "exited":
            artifact_name = artifact["name"]
            fingerprint = artifact["fingerprint"]
            for flow in artifact["flows"]:
                flow_name = flow["flow_name"]
                if is_build_flow(flow_name, fingerprint, fetch):
                    git_commit = flow["git_commit"]
                    commit_url = flow["commit_url"]
                    repo_name, raw_url = parse_commit_url(commit_url)
                    result.append({
                        "artifact_name": artifact_name,
                        "artifact_fingerprint": fingerprint,
                        "flow_name": flow_name,
                        "git_commit": git_commit,
                        "repo_name": repo_name,
                        "snapshot_index": snapshot_index,
                        "snapshot_artifact_url": f"{html_url}?fingerprint={fingerprint}",
                        "raw_snyk_policy_url": raw_url
                    })

    return result


def parse_commit_url(commit_url):
    """
    Parse an artifact's commit_url into (repo_name, raw_snyk_policy_url).
    repo_name is the repository's short name (the last path segment of the repo),
    taken from the commit_url itself so it does not depend on the flow naming
    convention. Exits non-zero for an unrecognised CI system.
    """
    commit_sha = commit_url[-40:]
    if commit_url.startswith("https://github.com"):
        # https://github.com/cyber-dojo/languages-start-points/commit/<commit_sha>
        repo_path = commit_url[len("https://github.com/"):-len(f"/commit/{commit_sha}")]
        # eg repo_path = cyber-dojo/languages-start-points
        repo_name = repo_path.split("/")[-1]
        raw_url = f"https://raw.githubusercontent.com/{repo_path}/{commit_sha}/.snyk"
        return repo_name, raw_url
    elif commit_url.startswith("https://gitlab.com"):
        # https://gitlab.com/cyber-dojo/creator/-/commit/<commit_sha>
        repo_url = commit_url[:-len(f"/-/commit/{commit_sha}")]
        # eg repo_url = https://gitlab.com/cyber-dojo/creator
        repo_name = repo_url.split("/")[-1]
        raw_url = f"{repo_url}/-/raw/{commit_sha}/.snyk"
        return repo_name, raw_url
    else:
        stderr(f"Unknown CI system {commit_url}")
        sys.exit(42)


def is_build_flow(flow_name, fingerprint, fetch):
    """
    A flow is a build flow when the artifact's attestation in that flow carries
    the annotation type=build, set by the CI pipeline's
    'kosli attest artifact --annotate type=build' call.
    'fetch' reads the annotations dict for this (flow_name, fingerprint).
    """
    return fetch(flow_name, fingerprint).get("type") == "build"


def fetch_annotations(flow_name, fingerprint):
    """
    Return the annotations dict for an artifact-in-flow by calling
    'kosli get artifact <flow_name>@<fingerprint> --output=json'.
    The snapshot JSON does not carry per-flow annotations, so each
    (flow_name, fingerprint) pair needs its own call.
    Exits non-zero on any failure rather than risk dropping a build flow.
    Requires KOSLI_HOST, KOSLI_ORG and KOSLI_API_TOKEN to be set; exits with a
    clear message rather than passing an unset (None) value to the kosli call.
    """
    host = os.environ.get("KOSLI_HOST")
    org = os.environ.get("KOSLI_ORG")
    api_token = os.environ.get("KOSLI_API_TOKEN")
    for name, value in (("KOSLI_HOST", host), ("KOSLI_ORG", org), ("KOSLI_API_TOKEN", api_token)):
        if not value:
            stderr(f"{name} must be set")
            sys.exit(44)
    try:
        output = subprocess.run(
            ["kosli", "get", "artifact", f"{flow_name}@{fingerprint}",
             "--host", host,
             "--org", org,
             "--api-token", api_token,
             "--debug=false",
             "--output=json"],
            check=True,
            capture_output=True,
            text=True,
            # Restrict the child to only PATH (so kosli can be located) and pass
            # all config explicitly as flags, so nothing else in the ambient
            # environment can influence the call.
            env={"PATH": os.environ.get("PATH", "")},
        ).stdout
        return json.loads(output).get("annotations", {})
    except (subprocess.CalledProcessError, json.JSONDecodeError) as error:
        stderr(f"Could not read annotations for {flow_name}@{fingerprint}: {error}")
        sys.exit(43)


def stderr(message):
    print(f"ERROR: {message}", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ["-h", "--help"]:
        print_help()
    else:
        # Note: This is expecting input on stdin
        raw = json.loads(sys.stdin.read())
        print(json.dumps(artifacts(raw), indent=2))

