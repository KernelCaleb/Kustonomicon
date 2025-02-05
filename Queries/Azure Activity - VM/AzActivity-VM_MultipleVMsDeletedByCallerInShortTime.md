# Azure Activity - VM: Multiple VMs Deleted in a Short Period of Time

### Description
This query detects when a single caller deletes a large number of VMs in a short period of time.

### Query
```kql
let Threshold = 5;
AzureActivity
| where OperationNameValue == "MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE"
| where ActivityStatusValue == "Success"
| extend PropertiesParsed = parse_json(Properties)
| extend 
    Resource = tostring(PropertiesParsed.resource),
    ResourceGroup = tostring(PropertiesParsed.resourceGroup),
    SubscriptionId = tostring(PropertiesParsed.subscriptionId)
| summarize
    VMDeleteCount = dcount(Resource),
    VMs = make_set(Resource),
    RGs = make_set(ResourceGroup),
    Subscriptions = make_set(SubscriptionId),
    CallerIps = make_set(CallerIpAddress)  
    by bin(TimeGenerated, 1h), Caller
| where VMDeleteCount > Threshold
| project TimeGenerated, VMDeleteCount, VMs, RGs, Subscriptions, Caller, CallerIps
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T578.003](https://attack.mitre.org/techniques/T1578/003/) | Modify Cloud Compute Infrastructure: Delete Cloud Instance | Defense Evasion |
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Impact |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes