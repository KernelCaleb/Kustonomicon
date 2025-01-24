# AAD - SigninLogs: Multiple valid Microsoft Entra ID (AAD) users failing to authenticate from same source IP

### Description
This detects failed logins to multiple valid AAD accounts from the same source IP over a short interval. This activity may indicate password spraying or brute forcing.

### Query
```kql
let interval = 1h;
SigninLogs
| extend TimeWindow = bin(TimeGenerated, interval)
| summarize 
    FailureCount = count(),
    DistinctUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName),
    Apps = make_set(AppDisplayName),
    FirstFailureTime = min(TimeGenerated),
    LastFailureTime = max(TimeGenerated)
    by IPAddress, TimeWindow
| where DistinctUsers > 3
    and FailureCount > 3
| project 
    IPAddress, 
    TimeWindow,
    DistinctUsers, 
    FailureCount, 
    Users,
    Apps,
    FirstFailureTime,
    LastFailureTime,
    FailureDuration = LastFailureTime - FirstFailureTime
| order by FailureCount desc
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [https://attack.mitre.org/techniques/T1110/](T1110) | Brute Force | Credential Access |
| [https://attack.mitre.org/techniques/T1110/001/](T1110.001) | Brute Force: Password Guessing | Credential Access |
| [https://attack.mitre.org/techniques/T1110/003/](T1110.003) | Brute Force: Password Spraying | Credential Access |
| [https://attack.mitre.org/techniques/T1110/004/](T1110.004) | Brute Force: Password Stuffing | Credential Access |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes