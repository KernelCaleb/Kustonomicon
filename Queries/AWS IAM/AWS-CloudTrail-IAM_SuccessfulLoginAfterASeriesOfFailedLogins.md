```kql
let FailedLogins = AWSCloudTrail
| where EventName == "CredentialVerification"
| extend CredentialVerificationStatus = parse_json(ServiceEventDetails).CredentialVerification
| where CredentialVerificationStatus == "Failure"
| summarize
    FailedLoginCount = count(),
    IPs = make_set(SourceIpAddress),
    UserAgents = make_set(UserAgent),
    FirstFailedLoginTime = min(TimeGenerated),
    LastFailedLoginTime = max(TimeGenerated)
    by UserIdentityUserName, bin(TimeGenerated, 1h)
    | where FailedLoginCount >= 5;
AWSCloudTrail
| where EventName == "CredentialVerification"
| extend CredentialVerificationStatus = parse_json(ServiceEventDetails).CredentialVerification
| where CredentialVerificationStatus == "Success"
| extend SuccessfulLoginTime = TimeGenerated
| join kind=inner (FailedLogins) on UserIdentityUserName
| where LastFailedLoginTime < SuccessfulLoginTime
| where SuccessfulLoginTime - LastFailedLoginTime <= 1h
| project UserIdentityUserName, FailedLoginCount, IPs, UserAgents, LastFailedLoginTime, SuccessfulLoginTime
```