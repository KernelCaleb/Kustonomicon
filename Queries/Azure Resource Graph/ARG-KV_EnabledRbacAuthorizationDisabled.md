```kql
arg('').resourcechanges
| extend parse_properties = parse_json(properties)
| extend TimeStamp = parse_properties.changeAttributes.timestamp
| extend CorrelationId = parse_properties.changeAttributes.correlationId
| extend InitiatingUPN = parse_properties.changeAttributes.changedBy
| extend ResourceType = parse_properties.targetResourceType
| extend ResourceId = parse_properties.targetResourceId
| extend ResourceString = split(ResourceId, "/")
| extend ResourceName = tostring(ResourceString[array_length(ResourceString) - 1])
| extend Subscription = tostring(split(ResourceId, "/")[2])
| extend ResourceGroup = tostring(split(ResourceId, "/")[4])
| extend changeType = parse_properties.changeType
| where changeType == "Update"
| extend parse_changes = parse_properties.changes
| where parse_changes contains "properties.enableRbacAuthorization"
| extend ParsedChanges = parse_json(parse_changes)
| extend PreviousValue = tostring(ParsedChanges["properties.enableRbacAuthorization"].previousValue)
| extend NewValue = tostring(ParsedChanges["properties.enableRbacAuthorization"].newValue)
| where PreviousValue == "True"
| where NewValue == "False"
| project TimeStamp, CorrelationId, InitiatingUPN, Subscription, ResourceGroup, ResourceName, ResourceId
```