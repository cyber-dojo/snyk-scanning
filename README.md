A repo holding CI workflows to run snyk container tests on the Docker images running in cyber-dojo's 
[aws-beta](https://app.kosli.com/cyber-dojo/environments/aws-beta/events/) and
[aws-prod](https://app.kosli.com/cyber-dojo/environments/aws-prod/events/) runtime environments.  

Reports newly found snyk vulnerabilities to a dedicated [Kosli Flow](https://app.kosli.com/cyber-dojo/flows/snyk-vulns/trails/).

Uses the `.snyk` policy file from the repo's git commit whose CI workflow
built the deployed image. This means `ignore` entries in the `.snyk` file 
_will_ be used.

Run's daily at 09:00.
