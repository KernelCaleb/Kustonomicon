# Azure Key Vault: Potential Privilege Escalation

### Description
This query detects when a caller creates a vault access policy for themselves, shortly after the vault configuration access policy is changed from RBAC enabled to vault access policy. This series of activity is highly suspicious and should be investigated.

### Query
```kql
AzureDiagnostics
| where OperationName contains "VaultPatch"
| where properties_enableRbacAuthorization_b == "false"
| extend Caller_VaultConfiguration = identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s
| extend TimeGenerated_VaultConfiguration = TimeGenerated
| project TimeGenerated_VaultConfiguration, CorrelationId, Caller_VaultConfiguration, CallerIPAddress, SubscriptionId, ResourceGroup, Resource, ResourceId
| join (AzureDiagnostics
    | where ResourceType == "VAULTS"
    | where OperationName == "VaultPatch"
    | where ResultType == "Success"
    | extend Caller_AccessAssigned = identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_name_s
    | extend Caller_Id = identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g
    | extend NewSPN = addedAccessPolicy_ObjectId_g
    | where Caller_Id == NewSPN
    | extend NewAccessPolicy_Key = addedAccessPolicy_Permissions_keys_s
    | extend NewAccessPolicy_Secret = addedAccessPolicy_Permissions_secrets_s
    | extend NewAccessPolicy_Certificate = addedAccessPolicy_Permissions_certificates_s
    | extend TimeGenerated_AccessAssigned = TimeGenerated
    )
    on Resource
| where TimeGenerated_AccessAssigned between (TimeGenerated_VaultConfiguration .. TimeGenerated_VaultConfiguration+1h)
| project 
    TimeGenerated_VaultConfiguration,
    TimeGenerated_AccessAssigned,
    Caller_VaultConfiguration,
    Caller_AccessAssigned, 
    Caller_Id, 
    SubscriptionId, 
    ResourceGroup, 
    Resource, 
    ResourceId, 
    NewAccessPolicy_Key, 
    NewAccessPolicy_Secret, 
    NewAccessPolicy_Certificate
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
- Yaml: [Azure-KV_PotentialPrivilegeEscalation.yaml](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Key%20Vault/Azure-KV_PotentialPrivilegeEscalationActivity.yaml)
- ARM: [Azure-KV_PotentialPrivilegeEscalation.json](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Key%20Vault/Azure-KV_PotentialPrivilegeEscalationActivity.json)

### Notes
The `vault access policy` allows for granular access, however, a privilege escalation path exists where an actor who has the `Contributor` or `Key Vault Contributor` role can grant themselves access to the vault. Monitor for a change from `Azure role-based access` to `vault access policy` may identify suspicious unwanted behavior, additionally, using the the Azure Resource Graph you can not only monitor for this change, but also identify all Key Vaults that are not using RBAC. This series of events is highly suspicious and indicates a clear attempt to gain access to key vault items.

Reference: [Escalating privilges to read secrets with Azure Key Vault access policies, Katie Knowles](https://securitylabs.datadoghq.com/articles/escalating-privileges-to-read-secrets-with-azure-key-vault-access-policies/)
