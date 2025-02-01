# Azure Activity: Privileged Role Assigned to Resource

### Description
This query detects when a principal is assigned a privileged built-in role to an Azure resource.

Defining overly permissive policies is considered bad practice, as it increases attack surface. Be sure to follow the principle of least privilege by granting each identity only the minimum required permissions and scoping the resources which can be accessed by it.

### Query
```kql
let PrivilegedRoles = dynamic (["b24988ac-6180-42a0-ab88-20f7382dd24c", "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "a8889054-8d42-49c9-bc1c-52486c10e7cd", "f58310d9-a9f6-439a-9e8d-f62e7b41a168", "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"]);
AzureActivity
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue == "Start"
| extend props = parse_json(Properties)
| extend parsed_requestBody = parse_json(tostring(props.requestbody))
| extend RoleDefinitionId = tostring(parsed_requestBody.Properties.RoleDefinitionId)
| extend RoleGuid = extract(@"roleDefinitions/([a-f0-9\-]+)", 1, RoleDefinitionId)
| where RoleGuid in (PrivilegedRoles)
| extend Scope = tostring(parsed_requestBody.Properties.Scope)
| extend PrincipalId = tostring(parsed_requestBody.Properties.PrincipalId)
| extend PrincipalType = tostring(parsed_requestBody.Properties.PrincipalType)
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, RoleDefinitionId, RoleGuid, Scope, PrincipalId, PrincipalType
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | Account Manipulation: Additional Cloud Roles | Persistence, Privilege Escalation |
| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#privileged