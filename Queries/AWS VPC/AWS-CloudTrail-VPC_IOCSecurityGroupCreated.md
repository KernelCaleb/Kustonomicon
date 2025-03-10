```kql
let SuspiciousGroups = dynamic(["Java_Ghost", "We Are There But Not Visible."]);
AWSCloudTrail
| where EventName == "CreateSecurityGroup"
| extend parse_RequestParameters = parse_json(RequestParameters)
| extend parse_ResponseElements = parse_json(ResponseElements)
| extend
    SecurityGroupName = parse_RequestParameters.groupName,
    SecurityGroupDescription = parse_RequestParameters.groupDescription,
    GroupId = parse_ResponseElements.groupId,
    GroupARN = parse_RequestParameters.groupArn
| where SecurityGroupName in (SuspiciousGroups) or SecurityGroupDescription in (SuspiciousGroups)
| project TimeGenerated, EventName, UserIdentityArn, SecurityGroupName, SecurityGroupDescription, GroupId, GroupARN
```