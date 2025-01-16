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
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access |

### Analytic Rule
- Yaml: 
- ARM: 

### Notes
