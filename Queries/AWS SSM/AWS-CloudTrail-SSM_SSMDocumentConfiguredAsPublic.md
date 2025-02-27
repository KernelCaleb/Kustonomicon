# AWS - SSM: SSM Document Configured as Public

### Description
This query detects when a SSM document has configured as public, allowing any AWS account to access it.

### Query
```kql
AWSCloudTrail
| where EventName == "ModifyDocumentPermission"
| extend parse_RequestParameters = parse_json(RequestParameters)
| extend
    SSMDocument = parse_RequestParameters.name,
    AccountsToAdd = parse_RequestParameters.accountIdsToAdd
| where AccountsToAdd == '["all"]'
| project TimeGenerated, UserIdentityArn, UserIdentityAccountId, UserIdentityAccessKeyId, SessionIssuerAccountId, SourceIpAddress, UserAgent, SSMDocument, AccountsToAdd, RecipientAccountId
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
SSM Documents should never be configured as public, this can lead to potential compromise of your AWS account (depending on the SSM document). If a document must be public, ensure it does not disclose sensitive information or authorize privileged actions.

To block public sharing of SSM documents see: (Block public sharing for SSM documents
)[https://docs.aws.amazon.com/systems-manager/latest/userguide/documents-ssm-sharing.html#block-public-access]