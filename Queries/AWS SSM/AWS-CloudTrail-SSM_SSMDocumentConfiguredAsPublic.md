```kql
AWSCloudTrail
| where EventName == "ModifyDocumentPermission"
| extend parse_RequestParameters = parse_json(RequestParameters)
| extend
    SSMDocument = parse_RequestParameters.name,
    AccountsToAdd = parse_RequestParameters.accountIdsToAdd
| where AccountsToAdd == '["all"]'
| project TimeGenerated, UserIdentityArn, UserIdentityAccountId, UserIdentityAccessKeyId, SessionIssuerAccountId, SourceIpAddress, UserAgent, SSMDocument, AccountsToAdd, RecipientAccountId
```S