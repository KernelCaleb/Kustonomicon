```kql
let Lookback = 1h;
let Threshold = 2;
AWSCloudTrail
| where EventName == "DeleteSecret"
| extend SecretId = tostring(parse_json(RequestParameters).secretId)
| summarize 
    DistinctSecretCount = dcount(SecretId),
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    IPAddressSet = make_set(SourceIpAddress),
    UserAgentSet = make_set(UserAgent),
    SecretsAccessed = make_set(SecretId)
    by UserIdentityArn, bin(TimeGenerated, Lookback)
| where DistinctSecretCount > Threshold
| extend TimeDifference = format_timespan(EndTime - StartTime, 'hh:mm:ss')
| project UserIdentityArn, IPAddressSet, UserAgentSet, DistinctSecretCount, SecretsAccessed, StartTime, EndTime, TimeDifference
```