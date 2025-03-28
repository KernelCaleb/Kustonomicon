```kusto
let ExcludedCallers = dynamic(["Microsoft.Advisor", "Microsoft.ResourceHealth", "Microsoft.Security"]);
let PreviouslyObservedIPs = (
    AzureActivity
    | where Caller !in (ExcludedCallers)
    | where TimeGenerated between (ago(90d) .. ago(1d))
    | where isnotempty(CallerIpAddress)
    | distinct CallerIpAddress
);
AzureActivity
| where TimeGenerated > ago(1d)
| where Caller !in (ExcludedCallers)
| where isnotempty(CallerIpAddress)
| where CallerIpAddress !in (PreviouslyObservedIPs)
| project TimeGenerated, Caller, CallerIpAddress, OperationName
```