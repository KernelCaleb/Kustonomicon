```kusto
let Exclude_UserIdentityArn = dynamic([
"..."
]);
let PreviousUserAgents = (
    AWSCloudTrail
    | where UserIdentityArn !in (Exclude_UserIdentityArn)
    | where TimeGenerated between (ago(90d) .. ago(1d))
    | distinct UserAgent
);
AWSCloudTrail
| where UserIdentityArn !in (Exclude_UserIdentityArn)
| where TimeGenerated < ago(1d)
| where UserAgent !in (PreviousUserAgents)
| extend Severity = case(
    EventName has_any("ConsoleLogin", "AssumeRole"), "High",
    EventName has_any("CreateUser", "CreateAccessKey"), "Medium", 
    "Low"
)
```