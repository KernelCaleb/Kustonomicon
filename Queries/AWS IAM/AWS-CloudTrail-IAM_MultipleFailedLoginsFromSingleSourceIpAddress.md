```kql
let interval = 1h;
AWSCloudTrail
| extend TimeWindow = bin(TimeGenerated, interval)
| where EventName == "CredentialVerification"
| extend CredentialVerification = parse_json(ServiceEventDetails).CredentialVerification
| where CredentialVerification == "Failure"
| summarize
    FailureCount = count(),
    DistinctUsers = dcount(UserIdentityUserName),
    Users = make_set(UserIdentityUserName),
    FirstFailureTime = min(TimeGenerated),
    LastFailureTime = max(TimeGenerated)
    by SourceIpAddress, TimeWindow
| where DistinctUsers > 2 and FailureCount > 2
| extend FailureDuration = LastFailureTime - FirstFailureTime
| project SourceIpAddress, FailureDuration, FailureCount, FirstFailureTime, LastFailureTime, DistinctUsers, Users
```