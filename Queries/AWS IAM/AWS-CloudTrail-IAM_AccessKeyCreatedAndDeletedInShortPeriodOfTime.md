# AWS - IAM: AccessKey Created and Deleted in Short Period of Time

### Description
This query detects when an AWS IAM `AccessKey` was created and deleted in a short periof of time (in `Threshold`).

### Query
```kql
let Threshold = 24h;
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
| where TimeDeleted between (TimeCreated .. (TimeCreated + Threshold))
| project
    AccessKeyId,
    AccessKeyUserName=coalesce(AccessKeyUserName, AccessKeyUserName1),
    TimeCreated,
    TimeDeleted,
    TimeDifference=datetime_diff('minute', TimeDeleted, TimeCreated),
    CreatorId=UserIdentityPrincipalid,
    DeleterId=UserIdentityPrincipalid1
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Account Manipulation: Additional Cloud Credentials |  Persistence, Privilege Escalation |
| [T1550](https://attack.mitre.org/techniques/T1550/) | Use Alternate Authentication Material |  Defense Evasion, Lateral Movement |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
This pattern is useful for hunting because:
Legitimate access keys are typically long-lived for service accounts or have established lifecycle patterns
Attackers often create temporary credentials to avoid detection
Short-lived keys suggest potential data exfiltration or temporary backdoor access
It can identify both malicious insiders and external threat actors with AWS console access

False positives include:
Cloud automation that creates temporary credentials
CI/CD pipelines with ephemeral access
Security tools that create and rotate credentials
Developers testing functionality

The detection's effectiveness can be enhanced by:
Correlating with unusual source IPs or user agents
Tracking what actions were performed using the short-lived key
Creating baselines for normal credential lifecycle patterns
Adding volume metrics (number of keys created/deleted per user)