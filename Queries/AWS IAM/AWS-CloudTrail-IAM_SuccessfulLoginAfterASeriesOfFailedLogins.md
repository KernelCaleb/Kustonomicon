```kql
AWSCloudTrail
| where EventName == "CredentialVerification"
| extend CredentialVerificationStatus = parse_json(ServiceEventDetails).CredentialVerification



AWSCloudTrail
| where EventName == "CredentialVerification"
| extend CredentialVerificationStatus = parse_json(ServiceEventDetails).CredentialVerification
| extend UserIdentityArn = tostring(UserIdentity.Arn)
| where isnotempty(UserIdentityArn)
| order by UserIdentityArn, TimeGenerated asc
| extend PrevStatus = prev(CredentialVerificationStatus, 1) over (partition by UserIdentityArn)
| extend PrevTime = prev(TimeGenerated, 1) over (partition by UserIdentityArn)
| extend FailureCount = row_window_count(
    CredentialVerificationStatus == "Failure",
    1h,
    3,
    UserIdentityArn
)
| where CredentialVerificationStatus == "Success" 
    and FailureCount >= 3
    and datetime_diff('minute', TimeGenerated, PrevTime) <= 60
| project
    TimeGenerated,
    UserIdentityArn,
    CredentialVerificationStatus,
    FailureCount,
    PrevStatus,
    PrevTime
```