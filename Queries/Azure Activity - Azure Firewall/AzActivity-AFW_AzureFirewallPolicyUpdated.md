# Azure Activity - Firewall: Firewall Policy Updated

### Description
This query detects when an Azure Firewall Policy Is Modified

### Query
```kql
AzureActivity
| where OperationNameValue contains "MICROSOFT.NETWORK/AZUREFIREWALLS/WRITE"
| where ActivityStatusValue == "Start"
| extend propertiesJson = todynamic(Properties)
| extend requestBodyString = tostring(propertiesJson.requestbody)
| extend requestBodyJson = todynamic(requestBodyString)
| extend AzureFirewallPolicyId = tostring(requestBodyJson.properties.firewallPolicy.id)
| project TimeGenerated, CorrelationId, Caller, CallerIpAddress, AzureFirewallPolicyId
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
|    |           |        |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
