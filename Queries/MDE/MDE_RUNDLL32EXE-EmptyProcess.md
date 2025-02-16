```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where isempty(ProcessCommandLine)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```