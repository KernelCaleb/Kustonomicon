```kql
AWSCloudTrail
| where EventName == "GetFederationToken"
| extend parse_RequestParameters = parse_json(RequestParameters)
| extend parse_ResponseElements = parse_json(ResponseElements)
| extend
    FederatedUserName = parse_RequestParameters.name,
    AccessKeyId = parse_ResponseElements.credentials.accessKeyId,
    SessionToken = parse_ResponseElements.credentials.expiration,
    FederatedUserArn = parse_ResponseElements.federatedUser.arn,
    FederatedUserId = parse_ResponseElements.federatedUser.federatedUserId
| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, UserAgent, FederatedUserArn, FederatedUserId, FederatedUserName, AccessKeyId, SessionToken
```