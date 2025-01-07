# Azure Key Vault: New IP Address Added to Key Vautl Firewall

### Description
This query detects when a Key Vault Access Configuration policy is changed from `Azure role-based access` to `vault access policy`. `Azure role-based access` policy is the recommended configuration of Key Vault access and allows for enhanced security, the `vault access policy` can be modified by any actor who has `Contributor` or `Key Vault Contributor` access to the Key Vault, allowing for potential privilege escalation.

### Query
```kql
AzureDiagnostics
| where OperationName contains "VaultPatch"
| where properties_enableRbacAuthorization_b == "false"
| extend Caller = identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s
| project TimeGenerated, CorrelationId, Caller, CallerIPAddress, SubscriptionId, ResourceGroup, Resource, ResourceId
```

```kql
arg('').resourcechanges
| extend parse_properties = parse_json(properties)
| extend TimeStamp = parse_properties.changeAttributes.timestamp
| extend CorrelationId = parse_properties.changeAttributes.correlationId
| extend InitiatingUPN = parse_properties.changeAttributes.changedBy
| extend ResourceType = parse_properties.targetResourceType
| extend ResourceId = parse_properties.targetResourceId
| extend ResourceString = split(ResourceId, "/")
| extend ResourceName = tostring(ResourceString[array_length(ResourceString) - 1])
| extend Subscription = tostring(split(ResourceId, "/")[2])
| extend ResourceGroup = tostring(split(ResourceId, "/")[4])
| extend changeType = parse_properties.changeType
| where changeType == "Update"
| extend parse_changes = parse_properties.changes
| where parse_changes contains "properties.enableRbacAuthorization"
| extend ParsedChanges = parse_json(parse_changes)
| extend PreviousValue = tostring(ParsedChanges["properties.enableRbacAuthorization"].previousValue)
| extend NewValue = tostring(ParsedChanges["properties.enableRbacAuthorization"].newValue)
| where PreviousValue == "True"
| where NewValue == "False"
| project TimeStamp, CorrelationId, InitiatingUPN, Subscription, ResourceGroup, ResourceName, ResourceId
```

```kql
arg('').resources
| where type == "microsoft.keyvault/vaults"
| extend parse_properties = parse_json(properties)
| extend enableRbacAuthorization = parse_properties.enableRbacAuthorization
| where enableRbacAuthorization == "false"
| project subscriptionId, resourceGroup, name, id, enableRbacAuthorization, location, kind, sku, tags
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1555.006](https://attack.mitre.org/techniques/T1555/006/) | Credentials from Password Stores: Cloud Secrets Managemetn Stores | Credential Access |
| [T1556](https://attack.mitre.org/techniques/T1556/) | Modify Authentication Process | Credential Access, Defense Evasion, Persistence |

### Analytic Rule
- Yaml: 
- ARM: 

### Notes
