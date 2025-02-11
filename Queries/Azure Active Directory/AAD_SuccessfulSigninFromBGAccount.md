```kql
let BreakGlassAccounts = dynamic(["...id1...", "...id2..."]);
SigninLogs
| where UserId in (BreakGlassAccounts)
| project TimeGenerated, CorrelationId, UserId, UserPrincipalName, IPAddress, AppDisplayName
```