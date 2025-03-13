```kql
AWSCloudTrail
| where EventName == "StartExportTask"
| where isempty(ErrorCode) and isempty(ErrorMessage)
| extend parse_RequestParamaters = parse_json(RequestParameters)
| extend
    ExportTaskId = parse_RequestParamaters.exportTaskIdentifier,
    IAMRoleARN = parse_RequestParamaters.iamRoleArn,
    KMSKeyId = parse_RequestParamaters.kmsKeyId,
    SourceDBARN = parse_RequestParamaters.sourceArn,
    DestinationS3Bucket = parse_RequestParamaters.s3BucketName
| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, UserAgent, ExportTaskId, SourceDBARN, DestinationS3Bucket, IAMRoleARN, KMSKeyId
```