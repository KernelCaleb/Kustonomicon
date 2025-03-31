```kusto
AuditLogs
| where LoggedByService == "Self-service Password Management"
```