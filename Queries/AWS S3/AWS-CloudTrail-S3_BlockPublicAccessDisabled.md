# AWS CloudTrail: AWS S3 - Changes to Block Public Access Settings

### Description
This query detects when an AWS S3 bucket's Block Public Access settings are modified.

### Query
```kql
AWSCloudTrail
| where EventName == "PutBucketPublicAccessBlock"
| extend RequestParametersJson = parse_json(RequestParameters)
| extend PublicAccessBlock = tostring(RequestParametersJson.publicAccessBlock)
| extend BucketName = tostring(RequestParametersJson.bucketName)
| extend RestrictPublicBuckets = tostring(RequestParametersJson.PublicAccessBlockConfiguration.RestrictPublicBuckets)
| extend BlockPublicPolicy = tostring(RequestParametersJson.PublicAccessBlockConfiguration.BlockPublicPolicy)
| extend BlockPublicAcls = tostring(RequestParametersJson.PublicAccessBlockConfiguration.BlockPublicAcls)
| extend IgnorePublicAcls = tostring(RequestParametersJson.PublicAccessBlockConfiguration.IgnorePublicAcls)
| extend Host = tostring(RequestParametersJson.Host)
| where RestrictPublicBuckets == "false" or BlockPublicPolicy == "false" or BlockPublicAcls  == "false" or IgnorePublicAcls == "false"
| extend Resources = parse_json(Resources)
| extend ResourcesJson = parse_json(Resources)
| mv-expand ResourcesJson
| extend AccountId = tostring(ResourcesJson.accountId)
| extend BucketArn = tostring(ResourcesJson.ARN)
| project TimeGenerated, UserIdentityArn, SourceIpAddress, UserAgent, AccountId, BucketName, RestrictPublicBuckets, BlockPublicPolicy, BlockPublicAcls, IgnorePublicAcls, BucketArn
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | Impair Defenses: Disable or Modify Cloud Firewall | Defense Evasion |


### Analytic Rule
- Yaml: 
- ARM: 

### Notes
Monitor S3 bucket policies closely.