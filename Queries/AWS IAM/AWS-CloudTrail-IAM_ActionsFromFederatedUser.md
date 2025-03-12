```kql
let federationEvents = AWSCloudTrail
| where EventName == "GetFederationToken"
| extend parse_RequestParameters = parse_json(RequestParameters)
| extend parse_ResponseElements = parse_json(ResponseElements)
| extend
    FederatedUserName = parse_RequestParameters.name,
    AccessKeyId = parse_ResponseElements.credentials.accessKeyId,
    SessionToken = parse_ResponseElements.credentials.expiration,
    FederatedUserArn = tostring(parse_ResponseElements.federatedUser.arn),
    FederatedUserId = parse_ResponseElements.federatedUser.federatedUserId;
federationEvents
| join (
    AWSCloudTrail
    | where isnotempty(UserIdentityArn)
    | extend UserIdentityArn = tostring(UserIdentityArn)
) on $left.FederatedUserArn == $right.UserIdentityArn
| project 
    TimeGenerated,
    EventName,
    FederatedUserName,
    FederatedUserArn,
    UserIdentityArn,
    SourceIpAddress,
    UserAgent
```