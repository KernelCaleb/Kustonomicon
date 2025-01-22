# AzureActivity - VM: Password Reset through EnableAccess VM Extension

### Description
This query detects when the VM administrator account is reset through EnableAccess VM extension.

### Query
```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE"
| where Properties contains "enablevmaccess"
| where ActivityStatusValue == "Success"
| extend entity = parse_json(Properties).entity
| extend VMName = tostring(split(entity, "/")[8])
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, SubscriptionId, ResourceGroup, VMName, _ResourceId
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1651](https://attack.mitre.org/techniques/T1651/) | Cloud Administration Command | Execution |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes