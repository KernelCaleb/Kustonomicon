```kusto
let Total = toscalar(SigninLogs | count);
SigninLogs
| summarize count() by UserAgent
| sort by count_ asc
| extend percentage = (count_ * 100.0) / Total
| where percentage <= 10.0
```