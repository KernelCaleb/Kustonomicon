```kql
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| summarize by AppDisplayName, UserId
```
