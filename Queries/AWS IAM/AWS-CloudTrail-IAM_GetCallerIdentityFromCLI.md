# AWS - IAM: STS Get-Caller-Identity from the AWS CLI

### Description
This query detects when `aws sts get-caller-identity` is executed from the AWS CLI.

This activity can be suspicious if your users typically do not use the CLI, but may be legitimate when performed by authorized administrators or automation processes. Ensure the request comes from a trusted entity.

### Query
```kql
AWSCloudTrail
| where EventName == "GetCallerIdentity"
| where UserAgent contains "cli"
| project TimeGenerated, EventName, UserIdentityArn, UserIdentityAccessKeyId, SourceIpAddress, UserAgent
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | Credential Access |
| [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | Credential Access |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
False Positives
- Legitimate CLI usage by authorized administrators
- Automation scripts and CI/CD pipelines
- Cloud management tools using AWS CLI

Enrichment
- Correlate SourceIpAddress with known locations/networks
- Check if UserIdentityArn matches approved admin accounts
- Verify if AccessKeyId is assigned to authorized service accounts

Response Actions
- Investigate unusual source IPs or unauthorized users
- Rotate compromised access keys immediately
- Review CloudTrail for additional suspicious activity from same source
- Check for lateral movement using the identified credentials

Tracking specific AccessKeyIds allows for precise identification of compromised credentials. Consider creating a baseline of expected CLI usage patterns.