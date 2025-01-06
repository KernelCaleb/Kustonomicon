# Azure Key Vault: New IP Address Added to Key Vautl Firewall

### Description
This query detects when a new or unknown IP address is added to an Azure Key Vault firewall.  You can define a list of known IP address with the `let` operator, use a watchlist, or import an external data source. An adversary with appropriate permissions may introduce new firewall rules to bypass controls and allow access to the Key Vault.

### Query
```kql
let knownIPs = dynamic(["10.10.10.10/32", "10.10.10.20/32", "10.10.10.30/32"]); // Define your set of known IPs, or use a watchlist, or import an external data source
AzureDiagnostics
| where OperationName == "VaultPatch"
| extend Caller = identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s
| extend NewIPAddress = addedIpRule_Value_s
| where NewIPAddress != ""
| where NewIPAddress !in (knownIPs)
| project TimeGenerated, CorrelationId, Caller, CallerIPAddress, NewIPAddress, SubscriptionId, ResourceGroup, Resource, ResourceId
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | Impair Defenses: Disable or Modify Cloud Firewall | Defense Evasion |
| [T1555.006](https://attack.mitre.org/techniques/T1555/006/) | Credentials from Password Stores: Cloud Secrets Managemetn Stores | Credential Access |

### Analytic Rule
- Yaml: 
- ARM: 

### Notes
This query can be beneficial in hunting unauthorized changes to Key Vault firewall rules. As a detection this may generate noise if there are frequent changes to Key Vault firewall rules, however, you can leverage the `KnowIPs`, `Caller`, `_ResourceId`, and the `NewIPAddress` values to filter out unwanted noise.

