```kql
AWSCloudTrail
| where EventName == "CreateAccessKey"
| extend parse_ResponseElements = parse_json(ResponseElements)
| extend AccessKeyId = tostring(parse_ResponseElements.accessKey.accessKeyId)
| extend AccessKeyUserName = tostring(parse_ResponseElements.accessKey.userName)
| summarize KeyCount = count() by bin(TimeGenerated, 1h), AccessKeyUserName
| where KeyCount >= 5
| project TimeWindow = TimeGenerated, AccessKeyUserName, NumberOfKeysCreated = KeyCount
| order by TimeWindow asc, NumberOfKeysCreated desc
```