# MDE: MDE Exclusion Added or Modified

### Description
This query will detect changes to MDE exclusion registry paths.

### Query
```kql
DeviceRegistryEvents 
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" or RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" or RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"
| join kind=inner (
    DeviceProcessEvents
    | project 
        ProcessId,
        InitiatingProcessId,
        ProcessCommandLine,
        ProcessVersionInfoCompanyName,
        ProcessVersionInfoFileDescription
) on $left.InitiatingProcessId == $right.ProcessId
| project 
    TimeGenerated,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    RegistryKey,
    RegistryValueData,
    ProcessVersionInfoCompanyName,
    ProcessVersionInfoFileDescription
```

### MITRE ATT&CK
| ID | Technique | Tactic |
|----|-----------|--------|
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools  | Defense Evasion |

### Analytic Rule
- Yaml: []()
- ARM: []()

### Notes