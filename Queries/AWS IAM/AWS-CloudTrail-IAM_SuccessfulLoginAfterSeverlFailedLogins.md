```kql
let FailedLogins = AWSCloudTrail
| where EventName == "CredentialVerification"
| extend CredentialVerification = parse_json(ServiceEventDetails).CredentialVerification
| where CredentialVerification == "Failure"
| summarize
    FailureCount = count(),
    IPs = make_set(SourceIpAddress),
    UserAgents = make_set(UserAgent),
    FirstFailureTime = min(TimeGenerated),
    LastFailureTime = max(TimeGenerated)
    by UserIdentityUserName, bin(TimeGenerated, 1h)
| where FailureCount> 3;
AWSCloudTrail
| where EventName == "CredentialVerification"
| extend CredentialVerification = parse_json(ServiceEventDetails).CredentialVerification
| where CredentialVerification == "Success"
| extend SuccessfulLoginTime = TimeGenerated
| join kind=inner (FailedLogins) on UserIdentityUserName
| where LastFailureTime < SuccessfulLoginTime
| where SuccessfulLoginTime - LastFailureTime <= 1h
| project UserIdentityUserName, FailureCount, IPs, UserAgents, LastFailureTime, SuccessfulLoginTime
```