# Azure Activity: Public Access Enabled on Storage Account

### Description
This query uses the AzureActivity table to detect when a request is made to enable public access to a storage account. While this should not be a problem in 2025, and you should have Azure Policy in place to prevent this. It is still possible for an exception to be made and the policy bypassed.

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
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | Impair Defenses: Disable or Modify Cloud Firewall | Defense Evasion |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage  | Collection |

### Analytic Rule
- Yaml: [AzActivity-ST_PublicAccessEnabledOnStorageAccount.yaml](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Activity/AzActivity-ST_PublicAccessEnabledOnStorageAccount.yaml)
- ARM: [AzActivity-ST_PublicAccessEnabledOnStorageAccount.json](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Activity/AzActivity-ST_PublicAccessEnabledOnStorageAccount.json)

### Notes
This analytic rule detects when a request is made to enable public access on a storage account. While Azure Policy should be in place to control this setting, an administrator with appropriate permissions or an exclusion on a resource group or subscription could lead to an unwanted misconfiguration. This rule can help catch a misconfiguration before it becomes an incident.
You can also used the Azure Resource Graph to detect this event, as well as all storage accounts that currently have allowBlobPublicAccess Enabled, you can find this query [here](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Resource%20Graph/ARG_StorageAccountPublicAccessEnabled.md).
