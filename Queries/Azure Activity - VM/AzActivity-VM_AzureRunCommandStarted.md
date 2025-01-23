# AzureActivity - VM: Azure Run Command Started on VM

### Description
This query detects when the run command is started on an Azure VM.

### Query
```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION"
| where ActivityStatusValue == "Accept"
| extend 
    EventDataID = tostring(parse_json(Properties).eventDataId),
    Caller = tostring(parse_json(Properties).caller),
    SubscriptionID = tostring(parse_json(Properties).subscriptionId),
    Resource = tostring(parse_json(Properties).resource),
    ResourceGroup = tostring(parse_json(Properties).resourceGroup),
    Action = tostring(parse_json(Properties).message),
    ActivityStatus = tostring(parse_json(Properties).activityStatusValue),
    Substatus = tostring(parse_json(Properties).activitySubstatusValue),
    StatusCode = tostring(parse_json(Properties).statusCode),
    EventTimestamp = todatetime(parse_json(Properties).eventSubmissionTimestamp)
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, Action, SubscriptionId, ResourceGroup, Resource, _ResourceId
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1651](https://attack.mitre.org/techniques/T1651/) | Cloud Administration Command | Execution |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes