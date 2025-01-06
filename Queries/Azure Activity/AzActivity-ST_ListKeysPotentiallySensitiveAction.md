# Azure Activity: ListKeys Potentially Sensitive Action

### Description
This query uses the AzureActivity table to detect when an actor performs the `LISTKEYS` action on an Azure Storage Account. While this operation can be legitimate for administrative purposes, it poses a significant security risk if executed maliciously. The `LISTKEYS` action indicates the potential retrieval of storage account access keys or generation of a new Shared Access Signature (SAS), which can be exploited to access and exfiltrate data.

### Query
```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION"
| extend parsed_Properties = parse_json(Properties)
| extend StorageAccount = parsed_Properties.resource
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, SubscriptionId, ResourceGroup, StorageAccount, _ResourceId
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage  | Collection |

### Analytic Rule
- Yaml:
- ARM:

### Notes
This query can be beneficial in hunting potentially risky activity. While SAS tokens can be used for legitimate administrative purposes, a misconfigured SAS token can grant too much access and expose data.