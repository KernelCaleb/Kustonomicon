# Azure AD: Successful Sign-In from BG Account

### Description
This query detects when there is successful sign-in from a BG account.

### Query
```kql
let BreakGlassAccounts = dynamic(["...id1...", "...id2..."]);
SigninLogs
| where UserId in (BreakGlassAccounts)
| where ResultType == "0"
| project TimeGenerated, CorrelationId, UserId, UserPrincipalName, IPAddress, AppDisplayName
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
