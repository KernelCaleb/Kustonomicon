# Azure Key Vault: Vault Access Configuration Modified

### Description
This query detects when a Key Vault Access Configuration policy is changed from `Azure role-based access` to `vault access policy`. `Azure role-based access` policy is the recommended configuration of Key Vault access and allows for enhanced security.

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
- Yaml: [Azure-KV_KeyVaultAccessConfigurationModified.yaml](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Key%20Vault/Azure-KV_KeyVaultAccessConfigurationModified.yaml)
- ARM: [Azure-KV_KeyVaultAccessConfigurationModified.json](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Key%20Vault/Azure-KV_KeyVaultAccessConfigurationModified.json)

### Notes
The `vault access policy` allows for granular access, however, a privilege escalation path exists where an actor who has the `Contributor` or `Key Vault Contributor` role can grant themselves access to the vault. Monitor for a change from `Azure role-based access` to `vault access policy` may identify suspicious unwanted behavior, additionally, using the the Azure Resource Graph you can not only monitor for this change, but identify all Key Vaults that are not using RBAC.

Reference: [Escalating privilges to read secrets with Azure Key Vault access policies, Katie Knowles](https://securitylabs.datadoghq.com/articles/escalating-privileges-to-read-secrets-with-azure-key-vault-access-policies/)
