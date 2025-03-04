```kql
AWSCloudTrail
| where EventName == "CreateAccessKey"
| extend parse_ResponseElements = parse_json(ResponseElements)
| extend AccessKeyId = tostring(parse_ResponseElements.accessKey.accessKeyId)
| extend AccessKeyUserName = tostring(parse_ResponseElements.accessKey.userName)
| project TimeGenerated, UserIdentityArn, AccessKeyUserName, AccessKeyId
```