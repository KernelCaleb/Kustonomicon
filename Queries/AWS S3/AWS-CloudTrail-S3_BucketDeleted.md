```kql
AWSCloudTrail
| where EventName == "DeleteBucket"
| extend Bucket = parse_json(RequestParameters).bucketName
| project TimeGenerated, SourceIpAddress, UserAgent, EventSource, EventName, UserIdentityArn, UserIdentityAccountId, UserIdentityAccessKeyId, SessionMfaAuthenticated, SessionIssuerArn, SessionIssuerAccountId, Bucket
```