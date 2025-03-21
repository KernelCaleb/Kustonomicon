```kql
AWSCloudTrail
| where EventName == "StartAutomationExecution"
| extend InstanceIds = parse_json(RequestParameters).parameters.InstanceId
| where array_length(InstanceIds) >= 2
| project TimeGenerated, UserIdentityArn, InstanceIds, RequestParameters
```