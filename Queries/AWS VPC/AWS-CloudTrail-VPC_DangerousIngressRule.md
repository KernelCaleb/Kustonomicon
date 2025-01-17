# AWS CloudTrail: AWS VPC - Changes to Inbound Rules Allowing Management Ports

### Description
This query detects when an AWS VPC inbound rule is modified that allows access to management ports.

### Query
```kql
let MgmtPorts = dynamic(["22", "3389", "-1"]);
AWSCloudTrail
| where EventName == "AuthorizeSecurityGroupIngress"
| extend groupId = parse_json(RequestParameters).groupId
| extend responseData = parse_json(ResponseElements)
| mv-expand items = responseData.securityGroupRuleSet.items
| extend fromPort = tostring(items.fromPort)
| extend toPort = tostring(items.toPort)
| where toPort in (MgmtPorts)
| project TimeGenerated, UserIdentityArn, SourceIpAddress, UserAgent, RecipientAccountId, groupId, fromPort, toPort, CidrIp
```

```kql
let MgmtPorts = dynamic(["22", "3389", "-1"]);
AWSCloudTrail
| where EventName == "ModifySecurityGroupRules"
| extend requestParams = parse_json(RequestParameters)
| extend securityGroupRule = requestParams.ModifySecurityGroupRulesRequest.SecurityGroupRule.SecurityGroupRule
| extend FromPort = tostring(securityGroupRule.FromPort)
| extend ToPort = tostring(securityGroupRule.ToPort)
| extend CidrIp = tostring(securityGroupRule.CidrIpv4)
| extend securityGroupRule = requestParams.ModifySecurityGroupRulesRequest.SecurityGroupRule
| extend SecurityGroupRuleId = tostring(securityGroupRule.SecurityGroupRuleId)
| where ToPort in (MgmtPorts)
| project TimeGenerated, UserIdentityArn, SourceIpAddress, UserAgent, RecipientAccountId, SecurityGroupRuleId, FromPort, ToPort, CidrIp
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | Impair Defenses: Disable or Modify Cloud Firewall | Defense Evasion |


### Analytic Rule
- Yaml: 
- ARM: 

### Notes
Monitor your VPC rules for suspicious changes, and restrict management ports to only essential sources.