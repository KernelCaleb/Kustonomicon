# Azure Storage Account: Mass Blob Download

### Description
This query will detect when a mass download of unique blob files occures, use the `blob_threshold` value to define when to generate an alert or return results. Adversaries access and exfiltrate blob data after through bypassing storage account controls or a misconfiguration of the storage account access controls. This query can help to identify suspicious behavior, alert on exfiltration of sensitive data from a given storage account, or uncover unknown access.

### Query
```kql
let blob_threshold = 4;
StorageBlobLogs
| where OperationName == "GetBlob"
| summarize TotalUniqueDownloads = dcount(ObjectKey) by AccountName, CallerIpAddress
| where TotalUniqueDownloads > blob_threshold
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage  | Collection |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
As an analytic rule, you can tune results based on the `CallerIpAddress` value and remove known safe IPs or filter out any storage accounts, `AccountName`, that are intended to be accessed and contents downloaded.