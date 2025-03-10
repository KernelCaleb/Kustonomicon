# AWS - VPC: Suspicious Security Group Created

### Description
This query detects when a suspicious security group is created.

Some threat actors create security groups with specific names and descriptions as a type of calling card after compromising an environment.

### Query
```kql
let SuspiciousGroups = dynamic(["Java_Ghost", "We Are There But Not Visible.", "sec-hhs", "example"]);
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

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
- https://threats.wiz.io/all-incidents/javaghost-ses-abuse
- https://unit42.paloaltonetworks.com/javaghost-cloud-phishing/
- https://www.crowdstrike.com/en-us/blog/how-adversaries-persist-with-aws-user-federation/