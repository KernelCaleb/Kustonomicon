```kusto
let Exclude_UserIdentityArn = dynamic([
"arn:aws:sts::897722704681:assumed-role/OIDC_MicrosoftSentinelRole/MicrosoftSentinel_156ef4a8-4a25-48da-93b3-c821e35a090b"
]);
let PreviousIPs = (
    AWSCloudTrail
    | where SourceIpAddress matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    | where UserIdentityArn !in (Exclude_UserIdentityArn)
    | where TimeGenerated between (ago(90d) .. ago(1d))
    | distinct SourceIpAddress
);
AWSCloudTrail
| where SourceIpAddress matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
| where UserIdentityArn !in (Exclude_UserIdentityArn)
| where TimeGenerated < ago(1d)
| where SourceIpAddress !in (PreviousIPs)
| extend Severity = case(
    EventName has_any("ConsoleLogin", "AssumeRole"), "High",
    EventName has_any("CreateUser", "CreateAccessKey"), "Medium", 
    "Low"
)
```