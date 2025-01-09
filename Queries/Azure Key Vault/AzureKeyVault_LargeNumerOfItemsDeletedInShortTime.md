# Azure Key Vault: Large Number of Items Deleted in Short Period of Time

### Description
This query detects a large number of Keys, Secrets, or Certificates are deleted from Azure Key Vault in a short period of time. Use the `Threshold` value to define an alert value.

### Query
```kql
let Threshold = 5;
let DeleteOperations = dynamic(["SecretDelete", "KeyDelete", "CertificateDelete"]);
AzureDiagnostics
| where ResourceType == "VAULTS" and OperationName in (DeleteOperations)
| where ResultType == "Success"
| extend Caller = coalesce(identity_claim_unique_name_s, "UnknownCaller")
| summarize EventCount = count(), StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), IPAddressSet = make_set(CallerIPAddress) 
    by Caller, bin(TimeGenerated, 1h)
| where EventCount > Threshold
| project StartTime, EndTime, Caller, EventCount, IPAddressSet
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1555.006](https://attack.mitre.org/techniques/T1555/006/) | Credentials from Password Stores: Cloud Secrets Managemetn Stores | Credential Access |
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | Impact |

### Analytic Rule
- Yaml: [Azure-KV_LargeNumberOfItemsDeleted.yaml](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Key%20Vault/Azure-KV_LargeNumberOfItemsDeleted.yaml)
- ARM: [Azure-KV_LargeNumberOfItemsDeleted.json](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Key%20Vault/Azure-KV_LargeNumberOfItemsDeleted.json)

### Notes
This query can be beneficial in hunting unusual or potentially malicious activity, such as mass deletions of secrets, keys, or certificates, which could indicate insider threats, compromised accounts, or automation errors impacting critical services.  