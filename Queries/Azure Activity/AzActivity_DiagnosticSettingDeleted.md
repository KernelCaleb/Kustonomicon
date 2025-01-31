# Azure Activity: Diagnostic Setting Deleted

### Description
This query detects when an Azure resource's diagnostic setting has been deleted.

Azure Diagnostic Settings are critical for logging security events, monitoring performance, and maintaining compliance. If an attacker or unauthorized user deletes these settings, it can prevent security teams from detecting malicious activity, making it a defense evasion technique.

### Query
```kql
AzureActivity
| where OperationNameValue contains "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS"
| where ActivityStatusValue == "Start"
| extend props = parse_json(Properties)
| extend message = props.message
| extend entity = props.entity
| extend resource = props.resource
| where message contains "delete"
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, SubscriptionId, ResourceGroup, resource, entity
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | Impair Defenses: Disable or Modify Cloud Logs | Defense Evasion |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes