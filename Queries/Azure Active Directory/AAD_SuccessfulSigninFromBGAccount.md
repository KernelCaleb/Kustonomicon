```kql
let BreakGlassAccounts = dynamic(["...id1...", "...id2..."]);
SigninLogs
| where UserId in (BreakGlassAccounts)
| where ResultType == "0"
| project TimeGenerated, CorrelationId, UserId, UserPrincipalName, IPAddress, AppDisplayName
```