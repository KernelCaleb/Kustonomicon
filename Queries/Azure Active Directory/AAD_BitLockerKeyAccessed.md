```kql
AuditLogs
| where OperationName == "Read BitLocker key"
```