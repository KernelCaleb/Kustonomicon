# AWS CloudTrail: Console Login Without MFA

### Description
This query detects when an IAM user logins to the AWS console without MFA.

### Query
```kql
AWSCloudTrail
| where EventName == "ConsoleLogin"
| where SessionIssuerUserName !contains "AWSReservedSSO"
| extend MFAUsed = parse_json(AdditionalEventData).MFAUsed
| where MFAUsed == "No"
| extend Trail = parse_json(RequestParameters).name
| project TimeGenerated, UserIdentityArn, UserIdentityAccessKeyId, SessionMfaAuthenticated, SessionIssuerAccountId, SourceIpAddress, UserAgent, Trail
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: 
- ARM: 

### Notes
