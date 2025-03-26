```kql
AuditLogs
| where TimeGenerated > ago (1d)
| where OperationName in ("Add eligible member to role in PIM completed (permanent)", "Add eligible member to role in PIM completed (timebound)", "Add member to role in PIM completed (permanent)", "Add member to role in PIM completed (timebound)")
| extend ['Azure AD Role Name'] = tostring(TargetResources[0].displayName)
| extend Target = tostring(TargetResources[2].userPrincipalName)
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| where Target contains "#ext#"
```