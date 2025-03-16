```kql
let Lookback = 1h;
let Threshold = 5;
AuditLogs
| where OperationName == "Delete group"
| extend parse_AdditionalDetails = parse_json(AdditionalDetails)
| extend UserAgent = parse_AdditionalDetails[0].value
| extend parse_InitiatedBy = parse_json(InitiatedBy)
| extend Caller = tostring(parse_InitiatedBy.userPrincipalName)
| extend CallerIPAddress = parse_InitiatedBy.ipAddress
| extend parse_TargetResources = parse_json(TargetResources)
| extend GroupName = parse_TargetResources[0].displayName
| extend GroupId = tostring(parse_TargetResources[0].groupType)
| summarize
    DistinctGroupCount = dcount(GroupId),
    GroupNameSet = make_set(GroupName),
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    IPAddressSet = make_set(CallerIPAddress),
    UserAgentSet = make_set(UserAgent)
    by Caller, bin(TimeGenerated, Lookback)
| where DistinctGroupCount > Threshold
| extend TimeDifference = format_timespan(EndTime - StartTime, 'hh:mm:ss')
```