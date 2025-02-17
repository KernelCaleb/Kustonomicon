# Azure AD: Risky Sign-In to Azure Portal

### Description
This query detects when there is a risky sign-in to the Azure portal.

### Query
```kql
SigninLogs
| where AppId == "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
| where RiskLevelDuringSignIn != "none"
| project TimeGenerated, CorrelationId, UserPrincipalName, IPAddress, AppDisplayName, RiskLevelDuringSignIn, RiskDetail, RiskLevelAggregated, IsRisky
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
