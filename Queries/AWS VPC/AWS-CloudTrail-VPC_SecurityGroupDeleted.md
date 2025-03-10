```kql
AWSCloudTrail
| where EventName == "DeleteSecurityGroup"
| extend parse_RequestParameters = parse_json(RequestParameters)
| extend SecurityGroup = parse_RequestParameters.groupId
| project TimeGenerated, EventName, SecurityGroup, UserIdentityArn, SourceIpAddress, UserAgent
```