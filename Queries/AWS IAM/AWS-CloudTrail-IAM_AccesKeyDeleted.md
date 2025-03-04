```kql
AWSCloudTrail
| where EventName == "DeleteAccessKey"
| extend parse_RequestParameters = parse_json(RequestParameters)
| extend AccessKeyId = tostring(parse_RequestParameters.accessKeyId)
| extend AccessKeyUserName = tostring(parse_RequestParameters.userName)
| project TimeGenerated, UserIdentityArn, AccessKeyUserName, AccessKeyId
```