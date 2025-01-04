# Azure Activity: New IP Address Added to Storage Account Firewall

### Description
This query uses the AzureActivity table to detect when a new IP address is added to the storage account firewall. You can define a list of known IP address with the `let` operator, or you can use a watchlist or import an external data source.  An adversary with appropriate permissions may introduce new firewall rule to bypass controls and allow access to the victim storage account.

### Query
```kql
let knownIPs = dynamic(["10.10.10.10", "10.10.10.20", "10.10.10.30"]); // Define your set of known IPs, or use a watchlist, or import an external data source
AzureActivity
| where OperationNameValue == "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"
| extend parse_Properties = parse_json(Properties)
| extend parse_requestBody = parse_json(tostring(parse_Properties.requestbody))
| where parse_requestBody contains "networkAcls"
| extend NetworkAcls = tostring(parse_requestBody.properties.networkAcls)
| extend parse_NetworkAcls = parse_json(NetworkAcls)
| extend ipRules = parse_json(tostring(parse_NetworkAcls.ipRules))
| mv-apply ip = ipRules on (
    extend NewIPAddress = tostring(ip.value)
    | where not(NewIPAddress in (knownIPs))
)
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, NewIPAddress, SubscriptionId, ResourceGroup, _ResourceId
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | Impair Defenses: Disable or Modify Cloud Firewall | Defense Evasion |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage  | Collection |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
This query can be beneficial in hunting unauthorized changes to storage account firewall rules. As a detection this may generate noise, however, you can leverage the `Caller`, `_ResourceId`, and even the `NewIPAddress` values to filter out noise.
