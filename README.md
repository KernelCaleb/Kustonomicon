# kustonomicon

```
  _              _                              _                 
 | |            | |                            (_)                
 | | ___   _ ___| |_ ___  _ __   ___  _ __ ___  _  ___ ___  _ __  
 | |/ / | | / __| __/ _ \| '_ \ / _ \| '_ ` _ \| |/ __/ _ \| '_ \ 
 |   <| |_| \__ \ || (_) | | | | (_) | | | | | | | (_| (_) | | | |
 |_|\_\\__,_|___/\__\___/|_| |_|\___/|_| |_| |_|_|\___\___/|_| |_|
                                                      
```
## About

This repo contains various KQL based queries and Sentinel Analytic rules in both ARM templates and Yaml, featured in the Detection of the Day from [Misconfigued.io](https://misconfigured.io/)

Please note, this repo is a work in progress and will be updated over the course of the year. Check back later for additional content and thanks for stopping by!

Inspired by the fantastic KQL community, be sure to check out all the great work here: https://kqlquery.com/posts/kql-sources-2025/


## Detection of the Day

| Date | Title | Description | Log Source |
|------|-------|-------------|------------|
| 2025-01-01 | [AAD - CAP: Conditional Access Policy Modified](https://github.com/KernelCaleb/kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-CAP_CAPModified.md) | Detect changes to CAPs | AAD - AuditLogs |
| 2025-01-02 | [AAD - App: New Credential Added to SPN](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-App_NewCredAddedToSPN.md) | Detect when a Secret/Certificate is added to AAD App Registration | AAD - AuditLogs |
| 2025-01-03 | [Azure Activity: Public Access Enabled on Storage Account](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity/AzActivity-ST_PublicAccessEnabledOnStorageAccount.md) | Detect when a request is made to enable public access on a storage account | Azure - AzureActivity |
| 2025-01-04 | [Azure Activity: New IP Address Added to Storage Account Firewall](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity/AzActivity-ST_NewIPAddedToStorageAccountFirewall.md) | Detect when a new or unknown IP address has been added to a storage account network acl | Azure - AzureActivity |