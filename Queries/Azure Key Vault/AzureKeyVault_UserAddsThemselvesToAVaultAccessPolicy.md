# Azure Key Vault - User Adds Themselves to a Vault Access Policy

### Description
This query detects when a user adds themselves to a vault access policy. This activity can be an indication of privilege escalation through a known attack path.

### Query
```kql
AzureDiagnostics
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
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1555.006](https://attack.mitre.org/techniques/T1555/006/) | Credentials from Password Stores: Cloud Secrets Managemetn Stores | Credential Access |
| [T1556](https://attack.mitre.org/techniques/T1556/) | Modify Authentication Process | Credential Access, Defense Evasion, Persistence |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
This query comes from a known attack path in vault access policies. It is unusual for a user to add themselves to a vault access policy and should be investigated. Additionally, all Key Vaults should use Azure RBAC rather than the legacy vault access policies.