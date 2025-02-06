# Name

### Description
This query detects when a SAS URL to download a VM disk is generated. Adversarys may create a SAS URL to download disks. Ensure this action was legitimate and executed by an authorized administrator.

### Query
```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION"
| where ActivityStatusValue == "Success"
| extend props = parse_json(Properties)
| extend entity = props.entity
| extend Disk = props.resource
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, SubscriptionId, ResourceGroup, Disk, entity
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes