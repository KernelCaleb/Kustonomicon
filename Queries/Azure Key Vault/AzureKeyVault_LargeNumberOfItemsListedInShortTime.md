# Azure Key Vault: Large Number of Items Accessed in Short Period of Time

### Description
This query detects when a large number of Vaults, Keys, Secrets, or Certificates are accessed listed by a single caller in a short period of time. Use the `VaultThreshold` value to define a distinct number of vaults that are accessed, as well as the `ItemThreshold` to define the distint number of Key Vault items that are accessed. Use the `exclude_caller` list to filter out unwanted noise from services that are frequently accessing Key Vault items (such as function apps). This activity can indicate a programatic attempt to enummerate key vaults and secrets before an exploitation attempt.

### Query
```kql
let exclude_caller = dynamic("9aa2267e-3135-40f9-be0d-c902b62d51af");
let VaultThreshold = 0;
let ItemThreshold = 5;
let GetOperations = dynamic(["VaultList", "SecretList", "KeyList", "CertificateList"]);
AzureDiagnostics
| where ResourceType == "VAULTS" and OperationName in (GetOperations)
| where clientInfo_s != "PolicyScan-GF"
| where ResultType == "Success"
| extend Caller = coalesce(identity_claim_unique_name_s, identity_claim_oid_g, "UnknownCaller")
| where Caller !in (exclude_caller)
| extend item = tostring(split(id_s, "/")[4])
| summarize 
    DistinctVaultCount = dcount(Resource),
    DistinctItemCount = dcount(item),
    StartTime = min(TimeGenerated), 
    EndTime = max(TimeGenerated), 
    IPAddressSet = make_set(CallerIPAddress),  
    VaultsAccessed = make_set(Resource),
    ItemsAccessed = make_set(item)
    by Caller, bin(TimeGenerated, 1h)
| where DistinctVaultCount > VaultThreshold
| where DistinctItemCount > ItemThreshold
| project StartTime, EndTime, Caller, DistinctVaultCount, DistinctItemCount, IPAddressSet, VaultsAccessed, ItemsAccessed
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1555.006](https://attack.mitre.org/techniques/T1555/006/) | Credentials from Password Stores: Cloud Secrets Managemetn Stores | Credential Access |

### Analytic Rule
- Yaml: [Azure-KV_LargeNumberOfItemsAccessed.yaml](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Key%20Vault/Azure-KV_LargeNumberOfItemsAccessed.yaml)
- ARM: [Azure-KV_LargeNumberOfItemsAccessed.json](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Key%20Vault/Azure-KV_LargeNumberOfItemsAccessed.json)

### Notes
This query can be beneficial in hunting unusual and potentially malicious activity, such as mass retreival of secrets, keys, or certificates, which could indicate an adversary attempting to escalate privilege or maintain persistence.