# Azure: Storage Account - Public Access Enabled

### Description
This query uses the AzureActivity table to detect when a request is made to enable public access to a storage account. While this should not be a problem in 2025, and you should have Azure Policy in place to prevent this. It is still possible for an exception to be made and the policy bypassed. This query can help catch a misconfiguration before it becomes an incident.

### Query
```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"
| extend parse_Properties = parse_json(Properties)
| extend parse_requestBody = parse_json(tostring(parse_Properties.requestbody))
| where parse_requestBody contains "allowBlobPublicAccess"
| extend PublicAccess = tostring(parse_requestBody.properties.allowBlobPublicAccess)
| where PublicAccess == "true"
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, SubscriptionId, ResourceGroup, _ResourceId
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | mpair Defenses: Disable or Modify Cloud Firewall | Defense Evasion |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage  | Collection |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes