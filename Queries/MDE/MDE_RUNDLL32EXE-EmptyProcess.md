```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine == '"rundll32.exe"' or isempty(ProcessCommandLine)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, ProcessId, ProcessIntegrityLevel, ProcessCreationTime, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath
```