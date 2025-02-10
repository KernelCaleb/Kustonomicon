```kql
let PrivEscRole = dynamic(["9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "c4e39bd9-1100-46d3-8c65-fb160da0071f", "8329153b-31d0-4727-b945-745eb3bc5f31", "9f06204d-73c1-4d4c-880a-6edb90606fd8", "158c047a-c907-4556-b7ef-446551a6b5f7", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "d29b2b05-8046-44ba-8758-1e26182fcf32", "9360feb5-f418-4baa-8175-e2a00bac4301", "29232cdf-9323-42fd-ade2-1d097af3e4de", "be2f45a1-457d-42af-a067-6ec1fa63bc45", "729827e3-9c14-49f7-bb1b-9608f156bbb8", "3a2c62db-5318-420d-8d74-23affee5d9d5", "966707d0-3269-4727-9be2-8c3a10f19b9d", "4ba39ca4-527c-499a-b93d-d9b492c50246", "194ae4cb-b126-40b2-bd5b-6091b380977d", "fe930be7-5e62-47db-91af-98c3a49a38b1"]);
AuditLogs
| where OperationName contains "Add member to role in PIM completed" or OperationName contains "Add eligible member to role in PIM completed"
| extend details = parse_json(AdditionalDetails)
| extend RoleDefOriginType = tostring(details[1].value)
| where RoleDefOriginType == "BuiltInRole"
| extend RoleTemplateId = details[2].value
| where RoleTemplateId in (PrivEscRole)
| extend parse_TargetResource = parse_json(TargetResources)
| extend TargetId = parse_TargetResource[2].id
| extend TargetType = parse_TargetResource[2].type
| extend TargetUserPrincipalName = parse_TargetResource[2].userPrincipalName
| extend RoleDisplayName = parse_TargetResource[0].displayName
| project TimeGenerated, CorrelationId, Identity, OperationName, RoleTemplateId, RoleDisplayName, TargetType, TargetId, TargetUserPrincipalName
```