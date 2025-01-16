# AWS CloudTrail: Failed Login from Root User

### Description
This query looks for failed console logins from the Root user account.

### Query
```kql
AWSCloudTrail
| where UserIdentityType == "Root"
| where EventName == "ConsoleLogin"
| extend Status = parse_json(ResponseElements).ConsoleLogin
| where Status == "Failure"
| project TimeGenerated, RecipientAccountId, UserIdentityArn, SourceIpAddress, UserAgent
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|  |  |  |

### Analytic Rule
- Yaml: 
- ARM: 

### Notes
