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