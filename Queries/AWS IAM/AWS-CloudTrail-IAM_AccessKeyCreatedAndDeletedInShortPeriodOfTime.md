```kql
// Find created access keys
let createdKeys = AWSCloudTrail
| where EventName == "CreateAccessKey"
| extend parse_ResponseElements = parse_json(ResponseElements)
| extend AccessKeyId = tostring(parse_ResponseElements.accessKey.accessKeyId)
| extend AccessKeyUserName = tostring(parse_ResponseElements.accessKey.userName)
| extend TimeCreated = TimeGenerated
| project AccessKeyId, AccessKeyUserName, TimeCreated, UserIdentityPrincipalid;
// Find deleted access keys
let deletedKeys = AWSCloudTrail
| where EventName == "DeleteAccessKey"
| extend parse_RequestParameters = parse_json(RequestParameters)
| extend AccessKeyId = tostring(parse_RequestParameters.accessKeyId)
| extend AccessKeyUserName = tostring(parse_RequestParameters.userName)
| extend TimeDeleted = TimeGenerated
| project AccessKeyId, AccessKeyUserName, TimeDeleted, UserIdentityPrincipalid;
// Join and filter for keys deleted within 24 hours of creation
createdKeys
| join kind=inner deletedKeys on AccessKeyId
| where TimeDeleted between (TimeCreated .. (TimeCreated + 24h))
| project
    AccessKeyId,
    AccessKeyUserName=coalesce(AccessKeyUserName, AccessKeyUserName1),
    TimeCreated,
    TimeDeleted,
    TimeDifference=datetime_diff('minute', TimeDeleted, TimeCreated),
    CreatorId=UserIdentityPrincipalid,
    DeleterId=UserIdentityPrincipalid1
```