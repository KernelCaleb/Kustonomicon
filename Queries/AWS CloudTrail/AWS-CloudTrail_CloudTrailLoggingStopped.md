# AWS CloudTrail: New Access Key Created for Root User

### Description
This query detects when an AWS CloudTrail is stopped. An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection, in AWS an adversary may disable CloudWatch/CloudTrail integrations prior to conducting further malicious activity.


### Query
```kql
AWSCloudTrail
| where EventName == "StopLogging"
| extend Trail = parse_json(RequestParameters).name
| project TimeGenerated, UserIdentityArn, UserIdentityAccessKeyId, SessionMfaAuthenticated, SourceIpAddress, UserAgent, Trail
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | Impair Defenses: Disable or Modify Cloud Logs | Defense Evasion |

### Analytic Rule
- Yaml: [AWS_CloudTrailLoggingStopped.yaml](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/AWS%20CloudTrail/AWS_CloudTrailLoggingStopped.yaml)
- ARM: [AWS_CloudTrailLoggingStopped.json](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/AWS%20CloudTrail/AWS_CloudTrailLoggingStopped.json)

### Notes
Monitor for events where logging is stopped, erased, or interfered with, as this can be a sign of malicious activity.