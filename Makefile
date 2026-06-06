
run_tests:
	@${PWD}/tests/run_tests.sh

artifacts:
	@${PWD}/bin/kosli_get_snapshot_json.sh | ${PWD}/bin/artifacts.py
