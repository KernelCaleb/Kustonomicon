```kql
let lookback = 24h;
AWSCloudTrail
| where EventName == "CreateAccessKey" 
| extend parse_ResponseElements = parse_json(ResponseElements)
| extend AccessKeyId = tostring(parse_ResponseElements.accessKey.accessKeyId)
| extend AccessKeyUserName = tostring(parse_ResponseElements.accessKey.userName)
| summarize 
    KeyCount = count(),
    FirstKeyTime = min(TimeGenerated),
    LastKeyTime = max(TimeGenerated),
    AccessKeyIds = make_set(AccessKeyId),
    UniqueUsers = make_set(AccessKeyUserName)
    by AccessKeyUserName, bin(TimeGenerated, lookback)
| where KeyCount >= 2
| extend TimeBetweenFirstAndLastKey = LastKeyTime - FirstKeyTime
| project 
    TimeWindow = TimeGenerated,
    NumberOfKeysCreated = KeyCount,
    FirstKeyCreated = FirstKeyTime,
    LastKeyCreated = LastKeyTime,
    TimeSpan = TimeBetweenFirstAndLastKey,
    AllAccessKeyIds = AccessKeyIds,
    AllAccessKeyUsers = UniqueUsers
| order by TimeWindow asc, NumberOfKeysCreated desc
```