
demo:
	@cat ${PWD}/tests/get-snapshot/aws-prod.json | ${PWD}/bin/artifacts.py

run_tests:
	@${PWD}/tests/run_tests.sh

artifacts:
	@${PWD}/bin/kosli_get_snapshot_json.sh | ${PWD}/bin/artifacts.py

trail_json:
	@${PWD}/bin/kosli_get_trail_json.sh	

get_vulns:
	@${PWD}/bin/kosli_get_trail_json.sh	> /tmp/trail.json
	@${PWD}/bin/get_all_vulns_attestations.py /tmp/trail.json
