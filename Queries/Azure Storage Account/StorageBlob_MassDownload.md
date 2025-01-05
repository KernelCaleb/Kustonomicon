# Azure Storage Account: Mass Blob Download

### Description
This query will detect when a mass download of unique blob files occurs, use the `blob_threshold` value to define when to generate an alert or return results. Adversaries access and exfiltrate blob data after through bypassing storage account controls or a misconfiguration of the storage account access controls. This query can help to identify suspicious behavior, alert on exfiltration of sensitive data from a given storage account, or uncover unknown access.

### Query
```kql
let blob_threshold = 50;
StorageBlobLogs
| where OperationName == "GetBlob"
| summarize TotalUniqueDownloads = dcount(ObjectKey) by bin(TimeGenerated, 1h), AccountName, CallerIpAddress
| where TotalUniqueDownloads > blob_threshold
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage  | Collection |

### Analytic Rule
- Yaml: [StorageBlob_MassDownload.yaml](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Storage%20Account/StorageBlob_MassDownload.json)
- ARM: [StorageBlob_MassDownload.json](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Storage%20Account/StorageBlob_MassDownload.json)

### Notes
As an analytic rule, you can tune results based on the `CallerIpAddress` value and remove known safe IPs or filter out any storage accounts, `AccountName`, that are intended to be accessed and contents downloaded.