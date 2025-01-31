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

| Date | Title | Description | Log Source | Table Name |
|------|-------|-------------|------------|------------|
| 2025-01-01 | [AAD - CAP: Conditional Access Policy Modified](https://github.com/KernelCaleb/kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-CAP_CAPModified.md) | Detect changes to CAPs | Azure Active Directory | AuditLogs |
| 2025-01-02 | [AAD - App: New Credential Added to SPN](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-App_NewCredAddedToSPN.md) | Detect when a Secret/Certificate is added to AAD App Registration | Azure Active Directory | AuditLogs |
| 2025-01-03 | [Azure Activity: Public Access Enabled on Storage Account](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity/AzActivity-ST_PublicAccessEnabledOnStorageAccount.md) | Detect when a request is made to enable public access on a storage account | Azure Storage Account | AzureActivity |
| 2025-01-04 | [Azure Activity: New IP Address Added to Storage Account Firewall](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity/AzActivity-ST_NewIPAddedToStorageAccountFirewall.md) | Detect when a new or unknown IP address has been added to a storage account network acl | Azure Storage Account | AzureActivity |
| 2025-01-05 | [Azure Storage Account: Mass Download](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Storage%20Account/StorageBlob_MassDownload.md) | Detect when a large number of unique blobs have been downloaded in a short period of time | Azure Storage Account | StorageBlobLogs |
| 2025-01-06 | [Azure Key Vault: New IP Address Added to Firewall](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Key%20Vault/AzureKeyVault_NewIPAddressAddedToFirewall.md) | Detect when a new or unknown IP address has been added to a Key Vault network acl | Azure Key Vault | AzureDiagnostics |
| 2025-01-07 | [Azure Key Vault: Access Configuration Modified](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Key%20Vault/AzureKeyVault_AccessConfigurationModified.md) | Detect when a Key Vault access configuration is changed from RBAC to Vault Access Policy | Azure Key Vault | AzureDiagnostics |
| 2025-01-08 | [Azure Key Vault: Large Number of Items Deleted in Short Period of Time](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Key%20Vault/AzureKeyVault_LargeNumerOfItemsDeletedInShortTime.md) | Detect when a large number of Key Vault items are deleted in a short time | Azure Key Vault | AzureDiagnostics |
| 2025-01-09 | [Azure Key Vault: Large Number of Items Accessed in Short Period of Time](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Key%20Vault/AzureKeyVault_LargeNumberOfItemsAccessedInShortTime.md) | Detect when a large number of Key Vault items are accessed by a single caller in a short time | Azure Key Vault | AzureDiagnostics |
| 2025-01-10 | [Azure Key Vault: Potential Privilege Escalation](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Key%20Vault/AzureKeyVault_PotentialPrivilegeEscalationActivity.md) | Detect when a key vault access configuration is modified and a caller then grants themselves access to the vault | Azure Key Vault | AzureDiagnostics |
| 2025-01-11 | [AWS CloudTrail: CVE-2024-50603 Potential Exploitation Activity](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20CloudTrail/AWS-CloudTrail_CVE-2024-50603.md) | Detection potential exploitation activity related to CVE-2024-50603 | AWS CloudTrail | AWSCloudTrail |
| 2025-01-12 | [AWS CloudTrail: New Access Key Created for Root User](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20CloudTrail/AWS-CloudTrail_NewAccessKeyCreatedForRoot.md) | Detect when a new access key has been created for root | AWS CloudTrail | AWSCloudTrail |
| 2025-01-13 | [AWS CloudTrail: CloudTrail Logging Stopped](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20CloudTrail/AWS-CloudTrail_CloudTrailLoggingStopped.md) | Detect when a CloudTrail log has been stopped | AWS CloudTrail | AWSCloudTrail |
| 2025-01-14 | [AWS CloudTrail: Console Login Without MFA](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20CloudTrail/AWS-CloudTrail_ConsoleLoginWithoutMFA.md) | Detect console login events without MFA | AWS CloudTrail | AWSCloudTrail |
| 2025-01-15 | [AWS CloudTrail: Failed Login from Root User](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20CloudTrail/AWS-CloudTrail_FailedLoginFromRoot.md) | Detect failed logins from the Root account | AWS CloudTrail | AWSCloudTrail |
| 2025-01-16 | [AWS CloudTrail: AWS VPC - Changes to Inbound Rules Allowing Management Ports](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20VPC/AWS-CloudTrail-VPC_DangerousIngressRule.md) | Detect when an AWS security group rule is added or modified to allow access to ports 22, 3389, or -1 | AWS VPC | AWSCloudTrail |
| 2025-01-17 | [AWS CloudTrail: AWS S3 - Changes to Block Public Access Settings](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20S3/AWS-CloudTrail-S3_BlockPublicAccessDisabled.md) | Detect changes to S3 public access protection settins | AWS S3 | AWSCloudTrail |
| 2025-01-18 | [AzureActivity - NSG: Changes to Inbound Rules Allowing Management Ports](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity%20-%20NSG/AzActivity-NSG_InboundRuleChangeMgmtPorts.md) | Detect when an Azure NSG rule has an inbound rule added/modified that allows access to ports 22, 3389, or * | Azure NSG | AzureActivity |
| 2025-01-19 | [Azure Key Vault - User Adds Themselves to a Vault Access Policy](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Key%20Vault/AzureKeyVault_UserAddsThemselvesToAVaultAccessPolicy.md) | Detect when a user adds themselves to a vault access policy, a known privesc attack path | Azure Key Vault | AzureDiagnostics |
| 2025-01-20 | [MDE: MDE Exclusion Added or Modified](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/MDE/MDE_MdeExclusionAdded.md) | Detect when an MDE exclusion is added or modified | Microsoft Defender for Endpoint | DeviceRegistryEvents, DeviceProcessEvents |
| 2025-01-21 | [AzureActivity - VM: Password Reset through EnableAccess VM Extension](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity%20-%20VM/AzActivity-VM_EnableAccessExtensionRan.md) | Detect when a VMs admin account is reset through the EnableAccess extension | Azure VM | AzureActivity |
| 2025-01-22 | [AzureActivity - VM: Azure Run Command Started on VM](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity%20-%20VM/AzActivity-VM_AzureRunCommandStarted.md) | Detect when the Run Command is started on a VM | Azure VM | AzureActivity |
| 2025-01-23 | [AAD - SigninLogs: Multiple valid Microsoft Entra ID (AAD) users failing to authenticate from same source IP](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-SignIn_MultipleVailidAADUsesFailingAuthFromSameSourceIP.md) | Multiple AAD accounts with failed logins from same source IP in short time | Azure Active Directory | SigninLogs |
| 2025-01-24 | [AAD - CAP: Conditional Access Policy Deleted](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-CAP_CAPDeleted.md) | Detect when a CAP is deleted | Azure AD - CAP | AuditLogs |
| 2025-01-25 | [Azure AD - App/OAuth: Admin Consented to Risky API Permissions](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-App_AdminConsented) | Detect when an admin grants consent to risky api permissions on behalf of an organization | Azure AD - App/Oauth | AuditLogs |
| 2025-01-26 | [Azure AD - SigninLogs: Large Number of Failed Logins Followed by a Successful Login to the Azure Portal](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD_FailedLoginsFollowedBySuccessfulLoginToAzurePortal.md) | Successful login to Azure Portal after a series of failed logins | Azure AD | SigninLogs |
| 2025-01-27 | [Azure AD - CAP: New Trusted Location Created](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-CAP_NewTrustedLocation.md) | This query detects when a new Trusted Location has been created | Azure AD - CAP | AuditLogs |
| 2025-01-28 | [Azure AD - CAP: Named Location Modified](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-CAP_NamedLocatonModified.md) | This query detects a named location has been modified | Azure AD - CAP | AuditLogs |
| 2025-01-29 | [Azure AD - CAP: Trusted Location Modified](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-CAP_TrustedLocationModified.md) | This query detects when a trusted location has been modified or a standard named location has been set as trusted | Azure AD - CAP | AuditLogs |
| 2025-01-30 | []() | ... | ... | ... |
| 2025-01-31 | ... | ... | ... | ... |
| 2025-02-01 | ... | ... | ... | ... |
| 2025-02-02 | ... | ... | ... | ... |
| 2025-02-03 | ... | ... | ... | ... |
| 2025-02-04 | ... | ... | ... | ... |
| 2025-02-05 | ... | ... | ... | ... |
| 2025-02-06 | ... | ... | ... | ... |
| 2025-02-07 | ... | ... | ... | ... |
| 2025-02-08 | ... | ... | ... | ... |
| 2025-02-09 | ... | ... | ... | ... |
| 2025-02-10 | ... | ... | ... | ... |
| 2025-02-11 | ... | ... | ... | ... |
| 2025-02-12 | ... | ... | ... | ... |
| 2025-02-13 | ... | ... | ... | ... |
| 2025-02-14 | ... | ... | ... | ... |
| 2025-02-15 | ... | ... | ... | ... |
| 2025-02-16 | ... | ... | ... | ... |
| 2025-02-17 | ... | ... | ... | ... |
| 2025-02-18 | ... | ... | ... | ... |
| 2025-02-19 | ... | ... | ... | ... |
| 2025-02-20 | ... | ... | ... | ... |
| 2025-02-21 | ... | ... | ... | ... |
| 2025-02-22 | ... | ... | ... | ... |
| 2025-02-23 | ... | ... | ... | ... |
| 2025-02-24 | ... | ... | ... | ... |
| 2025-02-25 | ... | ... | ... | ... |
| 2025-02-26 | ... | ... | ... | ... |
| 2025-02-27 | ... | ... | ... | ... |
| 2025-02-28 | ... | ... | ... | ... |
| 2025-03-01 | ... | ... | ... | ... |
| 2025-03-02 | ... | ... | ... | ... |
| 2025-03-03 | ... | ... | ... | ... |
| 2025-03-04 | ... | ... | ... | ... |
| 2025-03-05 | ... | ... | ... | ... |
| 2025-03-06 | ... | ... | ... | ... |
| 2025-03-07 | ... | ... | ... | ... |
| 2025-03-08 | ... | ... | ... | ... |
| 2025-03-09 | ... | ... | ... | ... |
| 2025-03-10 | ... | ... | ... | ... |
| 2025-03-11 | ... | ... | ... | ... |
| 2025-03-12 | ... | ... | ... | ... |
| 2025-03-13 | ... | ... | ... | ... |
| 2025-03-14 | ... | ... | ... | ... |
| 2025-03-15 | ... | ... | ... | ... |
| 2025-03-16 | ... | ... | ... | ... |
| 2025-03-17 | ... | ... | ... | ... |
| 2025-03-18 | ... | ... | ... | ... |
| 2025-03-19 | ... | ... | ... | ... |
| 2025-03-20 | ... | ... | ... | ... |
| 2025-03-21 | ... | ... | ... | ... |
| 2025-03-22 | ... | ... | ... | ... |
| 2025-03-23 | ... | ... | ... | ... |
| 2025-03-24 | ... | ... | ... | ... |
| 2025-03-25 | ... | ... | ... | ... |
| 2025-03-26 | ... | ... | ... | ... |
| 2025-03-27 | ... | ... | ... | ... |
| 2025-03-28 | ... | ... | ... | ... |
| 2025-03-29 | ... | ... | ... | ... |
| 2025-03-30 | ... | ... | ... | ... |
| 2025-03-31 | ... | ... | ... | ... |
| 2025-04-01 | ... | ... | ... | ... |
| 2025-04-02 | ... | ... | ... | ... |
| 2025-04-03 | ... | ... | ... | ... |
| 2025-04-04 | ... | ... | ... | ... |
| 2025-04-05 | ... | ... | ... | ... |
| 2025-04-06 | ... | ... | ... | ... |
| 2025-04-07 | ... | ... | ... | ... |
| 2025-04-08 | ... | ... | ... | ... |
| 2025-04-09 | ... | ... | ... | ... |
| 2025-04-10 | ... | ... | ... | ... |
| 2025-04-11 | ... | ... | ... | ... |
| 2025-04-12 | ... | ... | ... | ... |
| 2025-04-13 | ... | ... | ... | ... |
| 2025-04-14 | ... | ... | ... | ... |
| 2025-04-15 | ... | ... | ... | ... |
| 2025-04-16 | ... | ... | ... | ... |
| 2025-04-17 | ... | ... | ... | ... |
| 2025-04-18 | ... | ... | ... | ... |
| 2025-04-19 | ... | ... | ... | ... |
| 2025-04-20 | ... | ... | ... | ... |
| 2025-04-21 | ... | ... | ... | ... |
| 2025-04-22 | ... | ... | ... | ... |
| 2025-04-23 | ... | ... | ... | ... |
| 2025-04-24 | ... | ... | ... | ... |
| 2025-04-25 | ... | ... | ... | ... |
| 2025-04-26 | ... | ... | ... | ... |
| 2025-04-27 | ... | ... | ... | ... |
| 2025-04-28 | ... | ... | ... | ... |
| 2025-04-29 | ... | ... | ... | ... |
| 2025-04-30 | ... | ... | ... | ... |
| 2025-05-01 | ... | ... | ... | ... |
| 2025-05-02 | ... | ... | ... | ... |
| 2025-05-03 | ... | ... | ... | ... |
| 2025-05-04 | ... | ... | ... | ... |
| 2025-05-05 | ... | ... | ... | ... |
| 2025-05-06 | ... | ... | ... | ... |
| 2025-05-07 | ... | ... | ... | ... |
| 2025-05-08 | ... | ... | ... | ... |
| 2025-05-09 | ... | ... | ... | ... |
| 2025-05-10 | ... | ... | ... | ... |
| 2025-05-11 | ... | ... | ... | ... |
| 2025-05-12 | ... | ... | ... | ... |
| 2025-05-13 | ... | ... | ... | ... |
| 2025-05-14 | ... | ... | ... | ... |
| 2025-05-15 | ... | ... | ... | ... |
| 2025-05-16 | ... | ... | ... | ... |
| 2025-05-17 | ... | ... | ... | ... |
| 2025-05-18 | ... | ... | ... | ... |
| 2025-05-19 | ... | ... | ... | ... |
| 2025-05-20 | ... | ... | ... | ... |
| 2025-05-21 | ... | ... | ... | ... |
| 2025-05-22 | ... | ... | ... | ... |
| 2025-05-23 | ... | ... | ... | ... |
| 2025-05-24 | ... | ... | ... | ... |
| 2025-05-25 | ... | ... | ... | ... |
| 2025-05-26 | ... | ... | ... | ... |
| 2025-05-27 | ... | ... | ... | ... |
| 2025-05-28 | ... | ... | ... | ... |
| 2025-05-29 | ... | ... | ... | ... |
| 2025-05-30 | ... | ... | ... | ... |
| 2025-05-31 | ... | ... | ... | ... |
| 2025-06-01 | ... | ... | ... | ... |
| 2025-06-02 | ... | ... | ... | ... |
| 2025-06-03 | ... | ... | ... | ... |
| 2025-06-04 | ... | ... | ... | ... |
| 2025-06-05 | ... | ... | ... | ... |
| 2025-06-06 | ... | ... | ... | ... |
| 2025-06-07 | ... | ... | ... | ... |
| 2025-06-08 | ... | ... | ... | ... |
| 2025-06-09 | ... | ... | ... | ... |
| 2025-06-10 | ... | ... | ... | ... |
| 2025-06-11 | ... | ... | ... | ... |
| 2025-06-12 | ... | ... | ... | ... |
| 2025-06-13 | ... | ... | ... | ... |
| 2025-06-14 | ... | ... | ... | ... |
| 2025-06-15 | ... | ... | ... | ... |
| 2025-06-16 | ... | ... | ... | ... |
| 2025-06-17 | ... | ... | ... | ... |
| 2025-06-18 | ... | ... | ... | ... |
| 2025-06-19 | ... | ... | ... | ... |
| 2025-06-20 | ... | ... | ... | ... |
| 2025-06-21 | ... | ... | ... | ... |
| 2025-06-22 | ... | ... | ... | ... |
| 2025-06-23 | ... | ... | ... | ... |
| 2025-06-24 | ... | ... | ... | ... |
| 2025-06-25 | ... | ... | ... | ... |
| 2025-06-26 | ... | ... | ... | ... |
| 2025-06-27 | ... | ... | ... | ... |
| 2025-06-28 | ... | ... | ... | ... |
| 2025-06-29 | ... | ... | ... | ... |
| 2025-06-30 | ... | ... | ... | ... |
| 2025-07-01 | ... | ... | ... | ... |
| 2025-07-02 | ... | ... | ... | ... |
| 2025-07-03 | ... | ... | ... | ... |
| 2025-07-04 | ... | ... | ... | ... |
| 2025-07-05 | ... | ... | ... | ... |
| 2025-07-06 | ... | ... | ... | ... |
| 2025-07-07 | ... | ... | ... | ... |
| 2025-07-08 | ... | ... | ... | ... |
| 2025-07-09 | ... | ... | ... | ... |
| 2025-07-10 | ... | ... | ... | ... |
| 2025-07-11 | ... | ... | ... | ... |
| 2025-07-12 | ... | ... | ... | ... |
| 2025-07-13 | ... | ... | ... | ... |
| 2025-07-14 | ... | ... | ... | ... |
| 2025-07-15 | ... | ... | ... | ... |
| 2025-07-16 | ... | ... | ... | ... |
| 2025-07-17 | ... | ... | ... | ... |
| 2025-07-18 | ... | ... | ... | ... |
| 2025-07-19 | ... | ... | ... | ... |
| 2025-07-20 | ... | ... | ... | ... |
| 2025-07-21 | ... | ... | ... | ... |
| 2025-07-22 | ... | ... | ... | ... |
| 2025-07-23 | ... | ... | ... | ... |
| 2025-07-24 | ... | ... | ... | ... |
| 2025-07-25 | ... | ... | ... | ... |
| 2025-07-26 | ... | ... | ... | ... |
| 2025-07-27 | ... | ... | ... | ... |
| 2025-07-28 | ... | ... | ... | ... |
| 2025-07-29 | ... | ... | ... | ... |
| 2025-07-30 | ... | ... | ... | ... |
| 2025-07-31 | ... | ... | ... | ... |
| 2025-08-01 | ... | ... | ... | ... |
| 2025-08-02 | ... | ... | ... | ... |
| 2025-08-03 | ... | ... | ... | ... |
| 2025-08-04 | ... | ... | ... | ... |
| 2025-08-05 | ... | ... | ... | ... |
| 2025-08-06 | ... | ... | ... | ... |
| 2025-08-07 | ... | ... | ... | ... |
| 2025-08-08 | ... | ... | ... | ... |
| 2025-08-09 | ... | ... | ... | ... |
| 2025-08-10 | ... | ... | ... | ... |
| 2025-08-11 | ... | ... | ... | ... |
| 2025-08-12 | ... | ... | ... | ... |
| 2025-08-13 | ... | ... | ... | ... |
| 2025-08-14 | ... | ... | ... | ... |
| 2025-08-15 | ... | ... | ... | ... |
| 2025-08-16 | ... | ... | ... | ... |
| 2025-08-17 | ... | ... | ... | ... |
| 2025-08-18 | ... | ... | ... | ... |
| 2025-08-19 | ... | ... | ... | ... |
| 2025-08-20 | ... | ... | ... | ... |
| 2025-08-21 | ... | ... | ... | ... |
| 2025-08-22 | ... | ... | ... | ... |
| 2025-08-23 | ... | ... | ... | ... |
| 2025-08-24 | ... | ... | ... | ... |
| 2025-08-25 | ... | ... | ... | ... |
| 2025-08-26 | ... | ... | ... | ... |
| 2025-08-27 | ... | ... | ... | ... |
| 2025-08-28 | ... | ... | ... | ... |
| 2025-08-29 | ... | ... | ... | ... |
| 2025-08-30 | ... | ... | ... | ... |
| 2025-08-31 | ... | ... | ... | ... |
| 2025-09-01 | ... | ... | ... | ... |
| 2025-09-02 | ... | ... | ... | ... |
| 2025-09-03 | ... | ... | ... | ... |
| 2025-09-04 | ... | ... | ... | ... |
| 2025-09-05 | ... | ... | ... | ... |
| 2025-09-06 | ... | ... | ... | ... |
| 2025-09-07 | ... | ... | ... | ... |
| 2025-09-08 | ... | ... | ... | ... |
| 2025-09-09 | ... | ... | ... | ... |
| 2025-09-10 | ... | ... | ... | ... |
| 2025-09-11 | ... | ... | ... | ... |
| 2025-09-12 | ... | ... | ... | ... |
| 2025-09-13 | ... | ... | ... | ... |
| 2025-09-14 | ... | ... | ... | ... |
| 2025-09-15 | ... | ... | ... | ... |
| 2025-09-16 | ... | ... | ... | ... |
| 2025-09-17 | ... | ... | ... | ... |
| 2025-09-18 | ... | ... | ... | ... |
| 2025-09-19 | ... | ... | ... | ... |
| 2025-09-20 | ... | ... | ... | ... |
| 2025-09-21 | ... | ... | ... | ... |
| 2025-09-22 | ... | ... | ... | ... |
| 2025-09-23 | ... | ... | ... | ... |
| 2025-09-24 | ... | ... | ... | ... |
| 2025-09-25 | ... | ... | ... | ... |
| 2025-09-26 | ... | ... | ... | ... |
| 2025-09-27 | ... | ... | ... | ... |
| 2025-09-28 | ... | ... | ... | ... |
| 2025-09-29 | ... | ... | ... | ... |
| 2025-09-30 | ... | ... | ... | ... |
| 2025-10-01 | ... | ... | ... | ... |
| 2025-10-02 | ... | ... | ... | ... |
| 2025-10-03 | ... | ... | ... | ... |
| 2025-10-04 | ... | ... | ... | ... |
| 2025-10-05 | ... | ... | ... | ... |
| 2025-10-06 | ... | ... | ... | ... |
| 2025-10-07 | ... | ... | ... | ... |
| 2025-10-08 | ... | ... | ... | ... |
| 2025-10-09 | ... | ... | ... | ... |
| 2025-10-10 | ... | ... | ... | ... |
| 2025-10-11 | ... | ... | ... | ... |
| 2025-10-12 | ... | ... | ... | ... |
| 2025-10-13 | ... | ... | ... | ... |
| 2025-10-14 | ... | ... | ... | ... |
| 2025-10-15 | ... | ... | ... | ... |
| 2025-10-16 | ... | ... | ... | ... |
| 2025-10-17 | ... | ... | ... | ... |
| 2025-10-18 | ... | ... | ... | ... |
| 2025-10-19 | ... | ... | ... | ... |
| 2025-10-20 | ... | ... | ... | ... |
| 2025-10-21 | ... | ... | ... | ... |
| 2025-10-22 | ... | ... | ... | ... |
| 2025-10-23 | ... | ... | ... | ... |
| 2025-10-24 | ... | ... | ... | ... |
| 2025-10-25 | ... | ... | ... | ... |
| 2025-10-26 | ... | ... | ... | ... |
| 2025-10-27 | ... | ... | ... | ... |
| 2025-10-28 | ... | ... | ... | ... |
| 2025-10-29 | ... | ... | ... | ... |
| 2025-10-30 | ... | ... | ... | ... |
| 2025-10-31 | ... | ... | ... | ... |
| 2025-11-01 | ... | ... | ... | ... |
| 2025-11-02 | ... | ... | ... | ... |
| 2025-11-03 | ... | ... | ... | ... |
| 2025-11-04 | ... | ... | ... | ... |
| 2025-11-05 | ... | ... | ... | ... |
| 2025-11-06 | ... | ... | ... | ... |
| 2025-11-07 | ... | ... | ... | ... |
| 2025-11-08 | ... | ... | ... | ... |
| 2025-11-09 | ... | ... | ... | ... |
| 2025-11-10 | ... | ... | ... | ... |
| 2025-11-11 | ... | ... | ... | ... |
| 2025-11-12 | ... | ... | ... | ... |
| 2025-11-13 | ... | ... | ... | ... |
| 2025-11-14 | ... | ... | ... | ... |
| 2025-11-15 | ... | ... | ... | ... |
| 2025-11-16 | ... | ... | ... | ... |
| 2025-11-17 | ... | ... | ... | ... |
| 2025-11-18 | ... | ... | ... | ... |
| 2025-11-19 | ... | ... | ... | ... |
| 2025-11-20 | ... | ... | ... | ... |
| 2025-11-21 | ... | ... | ... | ... |
| 2025-11-22 | ... | ... | ... | ... |
| 2025-11-23 | ... | ... | ... | ... |
| 2025-11-24 | ... | ... | ... | ... |
| 2025-11-25 | ... | ... | ... | ... |
| 2025-11-26 | ... | ... | ... | ... |
| 2025-11-27 | ... | ... | ... | ... |
| 2025-11-28 | ... | ... | ... | ... |
| 2025-11-29 | ... | ... | ... | ... |
| 2025-11-30 | ... | ... | ... | ... |
| 2025-12-01 | ... | ... | ... | ... |
| 2025-12-02 | ... | ... | ... | ... |
| 2025-12-03 | ... | ... | ... | ... |
| 2025-12-04 | ... | ... | ... | ... |
| 2025-12-05 | ... | ... | ... | ... |
| 2025-12-06 | ... | ... | ... | ... |
| 2025-12-07 | ... | ... | ... | ... |
| 2025-12-08 | ... | ... | ... | ... |
| 2025-12-09 | ... | ... | ... | ... |
| 2025-12-10 | ... | ... | ... | ... |
| 2025-12-11 | ... | ... | ... | ... |
| 2025-12-12 | ... | ... | ... | ... |
| 2025-12-13 | ... | ... | ... | ... |
| 2025-12-14 | ... | ... | ... | ... |
| 2025-12-15 | ... | ... | ... | ... |
| 2025-12-16 | ... | ... | ... | ... |
| 2025-12-17 | ... | ... | ... | ... |
| 2025-12-18 | ... | ... | ... | ... |
| 2025-12-19 | ... | ... | ... | ... |
| 2025-12-20 | ... | ... | ... | ... |
| 2025-12-21 | ... | ... | ... | ... |
| 2025-12-22 | ... | ... | ... | ... |
| 2025-12-23 | ... | ... | ... | ... |
| 2025-12-24 | ... | ... | ... | ... |
| 2025-12-25 | ... | ... | ... | ... |
| 2025-12-26 | ... | ... | ... | ... |
| 2025-12-27 | ... | ... | ... | ... |
| 2025-12-28 | ... | ... | ... | ... |
| 2025-12-29 | ... | ... | ... | ... |
| 2025-12-30 | ... | ... | ... | ... |
| 2025-12-31 | ... | ... | ... | ... |

