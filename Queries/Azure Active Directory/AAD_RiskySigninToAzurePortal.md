```kql
SigninLogs
| where AppId == "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
| where RiskLevelDuringSignIn != "none"
| project TimeGenerated, CorrelationId, UserPrincipalName, IPAddress, AppDisplayName, RiskLevelDuringSignIn, RiskDetail, RiskLevelAggregated, IsRisky
```