```kql
let Lookback = 1h;
let Threshold = 2;
AzureActivity
| where OperationNameValue == "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION"
| where ActivityStatusValue == "Success"
| extend parse_Properties = parse_json(Properties)
| extend
    StorageAccount = tostring(parse_Properties.resource),
    Entity = parse_Properties.entity
| summarize
    DistinctStorageAccountCount = dcount(StorageAccount),
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    IPAddressSet = make_set(CallerIpAddress),
    StorageAccountsAccessed = make_set(StorageAccount)
    by Caller, bin(TimeGenerated, Lookback)
| where DistinctStorageAccountCount > Threshold
| extend TimeDifference = format_timespan(EndTime - StartTime, 'hh:mm:ss')
| project Caller, IPAddressSet, DistinctStorageAccountCount, StorageAccountsAccessed, StartTime, EndTime, TimeDifference
```