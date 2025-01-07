# Azure Resource Graph: Storage Account - Public Access Enabled

### Description
This query detects when a Key Vault Access Configuration policy is changed from `Azure role-based access` to `vault access policy`. Using the `resourcechanges` table you can detect when the `enableRbacAuthorization` is changed from true to false. Using the `resources` table, you can determine which Key Vaults currently have `enableRbacAuthorization` set to false.

### Query
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