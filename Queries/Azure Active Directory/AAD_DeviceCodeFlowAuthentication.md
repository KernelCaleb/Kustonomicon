```kql
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| project TimeGenerated, CorrelationId, AuthenticationProtocol, UserPrincipalName, IPAddress, UserAgent, AppDisplayName, AppId
```
