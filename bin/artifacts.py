#!/usr/bin/env python3

import json
import os
import subprocess
import sys


KOSLI_HOST = os.environ.get("KOSLI_HOST")
KOSLI_ORG = os.environ.get("KOSLI_ORG")
KOSLI_API_TOKEN = os.environ.get("KOSLI_API_TOKEN")


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
              "commit_url": "https://github.com/cyber-dojo/languages-start-points/commit/88366281011d1aa83c5db4280aa8a6daa0be8541",
              "repo_name": "languages-start-points",
              "snapshot_index": 3600,
              "snapshot_artifact_url": "https://app.kosli.com/cyber-dojo/environments/aws-prod/snapshots/3600?fingerprint=1d7fc67092bee8492e5019ca0175edf5189e4fc71a4b3a21976c64070def810a"
            },          
            ...
          ]
    """)


def artifacts():
    raw = json.loads(sys.stdin.read())
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
                if build_flow(flow_name):
                    git_commit = flow["git_commit"]
                    commit_url = flow["commit_url"]
                    repo_name = flow_name[:-3]
                    result.append({
                        "artifact_name": artifact_name,
                        "artifact_fingerprint": fingerprint,
                        "flow_name": flow_name,
                        "git_commit": git_commit,
                        "commit_url": commit_url,
                        "repo_name": repo_name,
                        "snapshot_index": snapshot_index,
                        "snapshot_artifact_url": f"{html_url}?fingerprint={fingerprint}"
                    })

    return result


def build_flow(flow_name):
    # The incoming snapshot is from an Environment on a SINGLE-SERVER eg app.kosli.com
    # and the Flows it finds for its artifacts will be from that server.
    # But in the CI worflow, the following kosli-get-flow will be a multi-host call. 
    # And this breaks because although the original Flow exists on all the servers,
    # when a Flow is renamed, its new name includes a timestamp of when it was renamed. Eg
    #   aws-beta-new-snyk-vulns-TEST-archived-at-1773914589
    # This timestamp will be different on different servers.
    # This could happen at any time, since artifacts can be rolled back.
    if "archived-at" in flow_name:
        return False

    command = [
        'kosli', 'get', 'flow',
        f"{flow_name}",
        f"--host={KOSLI_HOST}",
        f"--org={KOSLI_ORG}",
        f"--api-token={KOSLI_API_TOKEN}",
        '--debug=false',
        '--output=json'
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr)
        sys.exit(result.returncode)

    flow_json = json.loads(result.stdout)
    tags = flow_json.get("tags", {})
    return tags.get("kind", "") == "build"


def stderr(message):
    print(f"ERROR: {message}", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ["-h", "--help"]:
        print_help()
    else:
        # Note: This is expecting input on stdin
        print(json.dumps(artifacts(), indent=2))

