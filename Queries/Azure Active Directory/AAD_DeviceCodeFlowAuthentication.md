```kql
SigninLogs
| where TimeGenerated > ago(90d)
| where AuthenticationProtocol == "deviceCode"
| summarize by AppDisplayName, UserId
```