# Azure AD - App/OAuth: Admin Consented to Risky API Permissions on Behalf of the Organization

### Description
This query detects when an admin consents to a risky third-party application to access resources on behalf entire tenant.

Consent is the process of granting an application authorization to access protected resources on users' behalf. In Microsoft Entra ID, a high-privileged user can grant admin consent to third-party applications with delegated or application permissions (e.g., Mail, Files, ApplicationReadWrite, DirectoryReadWrite).

Tenant-wide admin consent allows all users to access the application by default, and application permissions enable access without a signed-in user. These broad permissions create significant security risks, as attackers can exploit consent grants through methods like phishing, password spray, or malicious application registration to gain persistent access to sensitive organizational data.

### Query
```kql
let RiskyScopes = dynamic(["Mail.Read", "Mail.ReadWrite", "MailboxItem.Read", "etc.RiskyScope"]);
AuditLogs
| where OperationName == "Consent to application"
| extend InitiatedByJson = parse_json(InitiatedBy)
| extend userPrincipalName = tostring(InitiatedByJson.user.userPrincipalName)
| extend ipAddress = tostring(InitiatedByJson.user.ipAddress)
| extend AdditionalDetailsJson = parse_json(AdditionalDetails)
| extend UserAgent = AdditionalDetailsJson[0].value
| extend ClientId = AdditionalDetailsJson[1].value
| extend TargetResourcesJson = parse_json(TargetResources)
| extend modifiedPropertiesJson = parse_json(TargetResourcesJson[0].modifiedProperties)
| extend NewValue = tostring(parse_json(modifiedPropertiesJson[4]).newValue)
| extend StartIndex = indexof(NewValue, "] => [[") + 6
| extend ExtractedValues = substring(NewValue, StartIndex)
| extend Scope = extract(@"Scope:\s*([^,]+)", 1, ExtractedValues)
| where Scope has_any (RiskyScopes)
| project TimeGenerated, CorrelationId, userPrincipalName, ipAddress, UserAgent, ClientId, Scope
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1199](https://attack.mitre.org/techniques/T1199/) | Trusted Relationship | Initial Access |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes
- https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants