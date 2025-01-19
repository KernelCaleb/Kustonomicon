# AzureActivity - NSG: Changes to Inbound Rules Allowing Management Ports

### Description
This query detects when an Azure NSG inbound rule is modified that allows access to management ports.

### Query
```kql
let MgmtPorts = dynamic(["22", "3389", "*"]);
AzureActivity
| where OperationNameValue == "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
| where ActivityStatusValue == "Accept" and ActivitySubstatusValue == "Created"
| extend responseBody = parse_json(extractjson("$.responseBody", Properties)) 
| extend properties = parse_json(responseBody)
| extend
    name = tostring(properties.name),
    protocol = tostring(properties.properties.protocol),
    sourcePortRange = tostring(properties.properties.sourcePortRange),
    sourceAddressPrefix = tostring(properties.properties.sourceAddressPrefix),
    destinationAddressPrefix = tostring(properties.properties.destinationAddressPrefix),
    destinationPortRange = tostring(properties.properties.destinationPortRange),
    access = tostring(properties.properties.access),
    priority = toint(properties.properties.priority),
    direction = tostring(properties.properties.direction),
    entity = tostring(extractjson("$.entity", Properties)),
    caller = tostring(extractjson("$.caller", Properties))
| where destinationPortRange in (MgmtPorts)and access == "Allow"
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, name, sourceAddressPrefix, sourcePortRange, destinationAddressPrefix, destinationPortRange, protocol, access, _ResourceId
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | Impair Defenses: Disable or Modify Cloud Firewall | Defense Evasion |


### Analytic Rule
- Yaml: 
- ARM: 

### Notes
Monitor your NSG rules for suspicious changes, and restrict management ports to only essential sources.