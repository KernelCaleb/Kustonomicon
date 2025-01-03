# Azure Resource Graph: Storage Account - Public Access Enabled

### Description
This query detects when public access is enabled for a storage account where it was previously disabled. Using the `resourcechanges` table you can detect when allow blob public access is enabled when it was previously disabled. Using the `resources` table, you can determine which storage accounts currently have allow blob public access enabled.

### Query
```kql
arg('').resourcechanges
| extend ParsedProperties = parse_json(properties)
| extend TimeStamp = ParsedProperties.changeAttributes.timestamp
| extend CorrelationId = ParsedProperties.changeAttributes.correlationId
| extend InitiatingUPN = ParsedProperties.changeAttributes.changedBy
| extend ResourceType = ParsedProperties.targetResourceType
| extend ResourceId = ParsedProperties.targetResourceId
| extend ResourceString = split(ResourceId, "/")
| extend StorageAccount = tostring(ResourceString[array_length(ResourceString) - 1])
| extend Subscription = tostring(split(ResourceId, "/")[2])
| extend ResourceGroup = tostring(split(ResourceId, "/")[4])
| extend Changes = ParsedProperties.changes
| extend ParsedChanges = parse_json(Changes)
| extend PreviousValue = tostring(ParsedChanges["properties.allowBlobPublicAccess"].previousValue)
| extend NewValue = tostring(ParsedChanges["properties.allowBlobPublicAccess"].newValue)
| where ResourceType == "microsoft.storage/storageaccounts"
| where Changes contains "properties.allowBlobPublicAccess"
| where PreviousValue == "False"
| where NewValue == "True"
| project TimeStamp, CorrelationId, InitiatingUPN, Subscription, ResourceGroup, StorageAccount, ResourceId
```

```kql
arg('').resources
| where type == "microsoft.storage/storageaccounts"
| extend PublicAccess = parse_json(properties).allowBlobPublicAccess
| where PublicAccess == "true"
| project subscriptionId, resourceGroup, name, id, location, kind, sku, tags
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | Impair Defenses: Disable or Modify Cloud Firewall | Defense Evasion |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
This query leverages the Azure Resource Graph to detect when public blob access is enabled on a storage account. While this should not be a problem in 2025, and you should have Azure Policy in place to prevent this. It is still possible for an exception to be made and the policy bypassed. This query can help catch a misconfiguration before it becomes an incident.
