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
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

### Analytic Rule
- Yaml: 
- ARM: 

### Notes
