# AAD - App: New Credential Added to Azure AD Application

### Description
This query detects when an Azure AD App Registration has a new credential added. Adversaries may add adversary-controlled credentials to a cloud account, like an Azure AD app registration, in order to maintain persistent access to victim accounts and instances within the environment.

### KQL
```kql
AuditLogs
| where OperationName == "Update application – Certificates and secrets management "
| extend InitiatingUPN = InitiatedBy.user.userPrincipalName
| extend IPAddress = InitiatedBy.user.ipAddress
| extend UserAgent = AdditionalDetails.[0].value
| extend AppObjectId = TargetResources.[0].id
| extend AppDisplayName = TargetResources.[0].displayName
| extend CredentialAdded = TargetResources.[0].modifiedProperties.[0].newValue
| project TimeGenerated, CorrelationId, InitiatingUPN, IPAddress, UserAgent, AppObjectId, AppDisplayName, CredentialAdded
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Account Manipulation: Additional Cloud Credentials | Persistence, Privilege Escalation |

### Analytic Rule
- Yaml: [AAD-App_NewCredAddedToSPN.yaml](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Active%20Directory/AAD-App_NewCredAddedToSPN.yaml)
- ARM: [AAD-App_NewCredAddedToSPN.json](https://github.com/KernelCaleb/Kustonomicon/blob/main/Analytic%20Rules/Azure%20Active%20Directory/AAD-App_NewCredAddedToSPN.json)

### Notes
This analytic rule detects when a secret or client certificate has been added to an app registration, this activity can be an indication that an adversary has accessed the environment and is seeking to maintain persistence or escalate privilege. This analytic rule can generate noise, you can filter out events based on the `InitiatingUPN` and `AppObjectId` values.
