# AWS CloudTrail: New Access Key Created for Root User

### Description
This query looks for new access keys created for an AWS root user. Root user accounts should rarely be used, and should never have an access key associated with them, instead IAM user accounts should be created with the lowest permissions possible.


### Query
```kql
AWSCloudTrail
| where EventName == "CreateAccessKey"
| where UserIdentityType == "Root"
| extend AccessKeyCreated = parse_json(ResponseElements).accessKey.accessKeyId
| project TimeGenerated, UserIdentityArn, SourceIpAddress, UserAgent, UserIdentityAccessKeyId, SessionMfaAuthenticated, SessionCreationDate, AccessKeyCreated
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1556](https://attack.mitre.org/techniques/T1556/) | Modify Authentication Process | Credential Access, Defense Evasion, Persistence |
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Account Manipulation: Additional Cloud Credentials | Persistence, Privilege Escalation |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
Monitor for access keys created for your root account and immediatly remove them when detected, access keys should never be created for the root account.