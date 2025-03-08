```kql
let SanctionedEC2Sizes = dynamic(["t2.micro"]);
AWSCloudTrail
| where EventName == "RunInstances"
| extend RequestParameters = parse_json(RequestParameters)
| extend ImageId = RequestParameters.instancesSet.items[0].imageId
| extend MinCount = RequestParameters.instancesSet.items[0].minCount
| extend MaxCount = RequestParameters.instancesSet.items[0].maxCount
| extend InstanceType = RequestParameters.instanceType
| where InstanceType !in (SanctionedEC2Sizes)
| project TimeGenerated, ImageId, MinCount, MaxCount, InstanceType
```