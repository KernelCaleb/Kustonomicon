```kql
AWSCloudTrail
| where EventName == "CreateInstanceExportTask"
| where isempty(ErrorCode)
| extend parse_ResponseElements = parse_json(ResponseElements)
| extend
    ExportTaskId = parse_ResponseElements.exportTask.exportTaskId,
    InstanceId = parse_ResponseElements.exportTask.instanceExport.instanceId,
    S3Bucket =  parse_ResponseElements.exportTask.exportToS3.s3Bucket,
    S3Key = parse_ResponseElements.exportTask.exportToS3.s3Key
| project TimeGenerated, UserIdentityArn, SourceIpAddress, UserAgent, ExportTaskId, InstanceId, S3Bucket, S3Key
```