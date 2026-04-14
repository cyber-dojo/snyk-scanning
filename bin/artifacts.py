import json
import sys


def print_help():
    print("""
        Reads (from stdin) the result of a 'kosli get snapshot $ENV --org=cyber-dojo ... --output=json'.
        Writes (to stdout) a JSON array with one dict for each Artifact running in $ENV.
        This JSON can be used as the source for a Github Action strategy:matrix:include to run a parallel job for each Artifact.

        Example:

          $ ./bin/get_snapshot_json.sh | python3 ./bin/artifacts.py    
          [
            {
              "artifact_name": "244531986313.dkr.ecr.eu-central-1.amazonaws.com/languages-start-points:8836628@sha256:1d7fc67092bee8492e5019ca0175edf5189e4fc71a4b3a21976c64070def810a",
              "artifact_fingerprint": "1d7fc67092bee8492e5019ca0175edf5189e4fc71a4b3a21976c64070def810a",
              "flow_name": "languages-start-points-ci",
              "git_commit": "88366281011d1aa83c5db4280aa8a6daa0be8541",
              "commit_url": "https://github.com/cyber-dojo/languages-start-points/commit/88366281011d1aa83c5db4280aa8a6daa0be8541",
              "repo_name": "languages-start-points",
              "snapshot_index": 3600,
              "snapshot_artifact_url": "https://app.kosli.com/cyber-dojo/environments/aws-prod/snapshots/3600?fingerprint=1d7fc67092bee8492e5019ca0175edf5189e4fc71a4b3a21976c64070def810a",
              "environment_name": "aws-prod",
              "raw_snyk_policy_url": "https://raw.githubusercontent.com/cyber-dojo/languages-start-points/commit/88366281011d1aa83c5db4280aa8a6daa0be8541/.snyk"
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
                if not excluded_flow(flow_name):
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
                        "snapshot_artifact_url": f"{html_url}?fingerprint={fingerprint}",
                        "environment_name": "aws-prod",
                        "raw_snyk_policy_url": raw_snyk_policy_url(commit_url)
                    })

    return result


def raw_snyk_policy_url(commit_url):
    commit_sha = commit_url[-40:]
    if commit_url.startswith("https://github.com"):
        # https://github.com/cyber-dojo/languages-start-points/commit/88366281011d1aa83c5db4280aa8a6daa0be8541
        cut_suffix = "/commit/88366281011d1aa83c5db4280aa8a6daa0be8541"
        prefix_url = commit_url[len("https://github.com/"):-len(cut_suffix)]
        # eg prefix_url = cyber-dojo/languages-start-points/commit
        return f"https://raw.githubusercontent.com/{prefix_url}/{commit_sha}/.snyk"
    elif commit_url.startswith("https://gitlab.com"):
        # https://gitlab.com/cyber-dojo/creator/-/commit/dca5d2f7571f9b63d651088c2b38946091853083
        cut_suffix = "/-/commit/dca5d2f7571f9b63d651088c2b38946091853083"
        prefix_url = commit_url[:-len(cut_suffix)]
        # eg prefix_url = https://gitlab.com/cyber-dojo/creator
        return f"{prefix_url}/-/raw/{commit_sha}/.snyk"
    else:
        stderr(f"Unknown CI system {commit_url}")
        sys.exit(42)


def excluded_flow(flow_name):
    if flow_name == "production-promotion":
        return True
    elif flow_name == "aws-beta":
        return True
    elif flow_name == "aws-prod":
        return True
    else:
        return False


def stderr(message):
    print(f"ERROR: {message}", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ["-h", "--help"]:
        print_help()
    else:
        # Note: This is expecting input on stdin
        print(json.dumps(artifacts(), indent=2))

