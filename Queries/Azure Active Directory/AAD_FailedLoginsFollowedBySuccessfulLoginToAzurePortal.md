# Azure AD - SigninLogs: Large Number of Failed Logins Followed by a Successful Login to the Azure Portal

### Description
This query detects when a user logins to the Azure Portal after previously having a large number of failed logins. This could be malicious activity where an adversary has successfully been able to brute-force your user's password and was able to login after several attempts.

### Query
```kql
let FailedLogins = SigninLogs
| where ResultType != "0"
| summarize 
    FailedLoginCount = count(),
    FailedLoginIPs = make_set(IPAddress),
    FailedLoginCodes = make_set(ResultType),
    FailedLoginApps = make_set(AppDisplayName),
    FirstFailedLoginTime = min(TimeGenerated),
    LastFailedLoginTime = max(TimeGenerated)
    by UserPrincipalName, bin(TimeGenerated, 1h)
    | where FailedLoginCount >= 5;
SigninLogs
| where ResultType == "0"
| where AppDisplayName == "Azure Portal"
| extend SuccessfulLoginTime = TimeGenerated
| join kind=inner (FailedLogins) on UserPrincipalName
| where LastFailedLoginTime < SuccessfulLoginTime
| where SuccessfulLoginTime - LastFailedLoginTime <= 1h
| project UserPrincipalName, FailedLoginCount, FailedLoginIPs, FailedLoginCodes, FailedLoginApps, LastFailedLoginTime, SuccessfulLoginTime
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1110](https://attack.mitre.org/techniques/T1110/)| Brute Force | Credential Access |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | Credential Access |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Brute Force: Password Spraying | Credential Access |
| [T1110.004](https://attack.mitre.org/techniques/T1110/004/) | Brute Force: Password Stuffing | Credential Access |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes