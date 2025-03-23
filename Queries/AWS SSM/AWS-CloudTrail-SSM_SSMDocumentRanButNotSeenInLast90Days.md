```kql
AWSCloudTrail
| where EventName == "StartAutomationExecution"
| extend RequestParameters_d = parse_json(RequestParameters)
| extend SSMDocumentName = tostring(RequestParameters_d.documentName)
| where TimeGenerated > ago(1d)
| join kind=leftanti (
    AWSCloudTrail
    | where EventName == "StartAutomationExecution" 
    | where TimeGenerated > ago(90d) and TimeGenerated <= ago(1d)
    | extend RequestParameters_d = parse_json(RequestParameters)
    | extend SSMDocumentName = tostring(RequestParameters_d.documentName)
    | distinct SSMDocumentName
) on SSMDocumentName
| project TimeGenerated, SSMDocumentName, RequestParameters
```