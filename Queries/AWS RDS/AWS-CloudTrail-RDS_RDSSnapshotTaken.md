```kql
AWSCloudTrail
| where EventName == "CreateDBSnapshot"
| where isempty(ErrorCode) and isempty(ErrorMessage)
| extend parse_RequestParameters = parse_json(RequestParameters)
| extend
    DBInstanceIdentifier = parse_RequestParameters.dBInstanceIdentifier,
    DBSnapshotIdentifier = parse_RequestParameters.dBSnapshotIdentifier
| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, UserAgent, DBInstanceIdentifier, DBSnapshotIdentifier
```