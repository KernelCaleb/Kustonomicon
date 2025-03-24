```kusto
AWSCloudTrail
| where EventName == "StartAutomationExecution"
| extend RequestParameters_d = parse_json(RequestParameters)
| extend SSMDocumentName = tostring(RequestParameters_d.documentName)
```