```kusto
let Lookback = 30d;
let Total = toscalar(AzureActivity
    | where TimeGenerated > ago(Lookback)
    | where isnotempty(CallerIpAddress)
    | count
);
AzureActivity
| where TimeGenerated > ago(Lookback)
| summarize count() by CallerIpAddress
| sort by count_ asc
| extend percentage = (count_ * 100.0) / Total
| where percentage <= 5.0
```