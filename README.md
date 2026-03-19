A CI workflow to run live snyk container tests on the Docker images running in cyber-dojo's 
[aws-beta](https://app.kosli.com/cyber-dojo/environments/aws-beta/events/) and
[aws-prod](https://app.kosli.com/cyber-dojo/environments/aws-prod/events/) runtime environments.  

# All snyk vulnerabilities

Reports _all_ snyk vulnerabilities to dedicated Kosli Flows:
- [All aws-beta](https://app.kosli.com/cyber-dojo/flows/aws-beta-all-snyk-vulns/trails/)
- [All aws-prod](https://app.kosli.com/cyber-dojo/flows/aws-prod-all-snyk-vulns/trails/)

The snyk tests use an _empty_ Snyk policy file, which means no vulnerabilities are "hidden".

# New snyk vulnerabilities

Reports _new_ snyk vulnerabilities to dedicated Kosli Flows:
- [New aws-beta](https://app.kosli.com/cyber-dojo/flows/aws-beta-new-snyk-vulns/trails/)
- [New aws-prod](https://app.kosli.com/cyber-dojo/flows/aws-prod-new-snyk-vulns/trails/)

When an artifact is first deployed it may have snyk vulnerabilities, but whether those
vulnerabilities constitute non-compliance is assumed to be handled by other processes.
In other words, _new_ means vulnerabilities which have newly arisen _since_ the artifact was first deployed.

Workflow runs daily at 06:00 AM.
