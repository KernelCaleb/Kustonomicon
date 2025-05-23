# Kustonomicon

```
  _              _                              _                 
 | |            | |                            (_)                
 | | ___   _ ___| |_ ___  _ __   ___  _ __ ___  _  ___ ___  _ __  
 | |/ / | | / __| __/ _ \| '_ \ / _ \| '_ ` _ \| |/ __/ _ \| '_ \ 
 |   <| |_| \__ \ || (_) | | | | (_) | | | | | | | (_| (_) | | | |
 |_|\_\\__,_|___/\__\___/|_| |_|\___/|_| |_| |_|_|\___\___/|_| |_|
                                                      
```
## About

Welcome to the Kustonomicon, a repo containing various KQL queries, techniques, and notes, with a focus on cloud detection and response.

This repo is a work in progress and will be updated over the course of the year, check back later for additional content and thanks for stopping by!

## 100 Days of KQL

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
| 2025-01-30 | [Azure Activity: Diagnostic Setting Deleted)](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity/AzActivity_DiagnosticSettingDeleted.md) | This query detects when an Azure resource's diagnostic settings have been deleted | Azure Activity - Insights | AzureActivity |
| 2025-01-31 | [Azure Activity: Diagnostic Setting Modified](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity/AzActivity_DiagnosticSettingModified.md) | This query detects when an Azure resource's diagnostic settings have been modified | Azure Activity - Insights | AzureActivity |
| 2025-02-01 | [Azure Activity: Privileged Role Assigned to Resource](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity/AzActivity-RBAC_PrivilegedRoleAssigned.md) | This query detects when a built-in privileged Azure RBAC role has been assigned | Azure Activity - RBAC | AzureActivity |
| 2025-02-02 | [Azure Activity: Privileged Role Assigned to Subscription](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity/AzActivity-RBAC_PrivilegedRoleAssignedToSubscription.md) | This query detects when a principal is assigned a privileged built-in role to an Azure subscription | Azure AD - Roles | AzureActivity |
| 2025-02-03 | [Azure Activity - Firewall: Firewall Policy Updated](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity%20-%20Azure%20Firewall/AzActivity-AFW_AzureFirewallPolicyUpdated.md) | This query detects when an Azure Firewall policy is modified | Azure Firewall | AzureActivity |
| 2025-02-04 | [Azure AD: Risky Sign-In to Azure Portal](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD_RiskySigninToAzurePortal.md) | This query detects when there is a risky sign-in to the Azure Portal | AAD Identity Protection | SigninLogs |
| 2025-02-05 | [Azure Activity - VM: Multiple VMs Deleted in a Short Period of Time by Single Caller](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity%20-%20VM/AzActivity-VM_MultipleVMsDeletedByCallerInShortTime.md) | This query detects when a single caller deletes a large number of VMs in a short period of time, 1 hour | Azure VMs | AzureActivity |
| 2025-02-06 | [Azure Activity - VM: Disk Exported Through SAS URL](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity%20-%20VM/AzActivity-VM_DiskExportSASURLGenerated.md) | This query detects when a SAS URL to download a VM disk is generated | Azure VMs | AzureActivity |
| 2025-02-07 | [Azure Activity - NSG: NSG Deleted](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity%20-%20NSG/AzActivity-NSG_NSGDeleted.md) | This query detects when a NSG is deleted | Azure Network - NSG | AzureActivity |
| 2025-02-08 | [Azure Activity - NIC: NIC Modified](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity%20-%20NIC/AzActivity-NIC_NICModified.md) | This query detects when a NIC is modified | Network Interfaces | AzureActivity |
| 2025-02-09 | [Azure Activity - ST: Storage Account Container Deleted](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity%20-%20Storage/AzActivity-ST_ContainerDeleted.md) | This query detects when a Storage Account Container is deleted | Storage Account | AzureActivity |
| 2025-02-10 | [**UPDATE ME** AAD - PIM: Privileged AD Role Assigned to Principal](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-PIM_PrivilegedRoleAssignedToPrincipal.md) | This query will detect when a privileged Azure AD role has been assigned to a principal | AAD PIM | AuditLogs |
| 2025-02-11 | [**UPDATE ME** Azure AD: Successful Sign-In from BG Account](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD_SuccessfulSigninFromBGAccount.md) | This query detects when there is successful sign-in from a BG account | Azure AD | SigninLogs |
| 2025-02-12 | [Azure AD: Administrator Password Reset by Another Administrator](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD_AdminResetPasswordForAnotherAdmin.md) | This query detects when an administrator changes the password of another administrator | Azure AD | AuditLogs |
| 2025-02-13 | [Azure AD - PIM: Role Assigned to Group](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD_RoleAssignedToGroup.md) | This query detects when an Azure AD role has been assigned to a gorup | Azure AD - PIM | AuditLogs |
| 2025-02-14 | [Azure Activity - Security Insights: Alert Rule Modified](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity%20-%20Security%20Insights/AzActivity-Security_AnalyticRuleModified.md) | This query detects when an Alert Rule or Analytic Rule has been modified | Azure Acitivity - Security Insights | AzureActivity |
| 2025-02-15 | [Azure Activity - Security Insights: Alert Rule Deleted](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity%20-%20Security%20Insights/AzActivity-Security_AnalyticRuleDeleted.md) | This query detects when an Alert Rule or Analytic Rule has been deleted | Azure Acitivity - Security Insights | AzureActivity |
| 2025-02-16 | [MDE: RUNDLL32.EXE With Empty Process Command Line](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/MDE/MDE_RUNDLL32EXE-EmptyProcess.md) | This query detects when rundll32.exe is ran with an empty process command line | MDE | DeviceProcessEvents |
| 2025-02-17 | [Azure AD: New Tenant Added to Cross Tenant Access](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD_NewTenantAddedToCrossTenantAccessSettings.md) | This query detects when a new tenant has been added to the cross tenant access settings | Azure AD | AuditLogs |
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
| 2025-03-01 | [AWS - IAM: STS Get-Caller-Identity from the AWS CLI](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20IAM/AWS-CloudTrail-IAM_GetCallerIdentityFromCLI.md) | This query detects when aws sts get-caller-identity is executed from the AWS CLI | AWS IAM | AWSCloudTrail |
| 2025-03-02 | [AWS IAM: Access Key Created and Deleted in Short Period of Time](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20IAM/AWS-CloudTrail-IAM_AccessKeyCreatedAndDeletedInShortPeriodOfTime.md) | ... | AWS IAM | AWSCloudTrail |
| 2025-03-03 | [AWS IAM: Access Key Created](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20IAM/AWS-CloudTrail-IAM_AccessKeyCreated.md) | ... | AWS IAM | AWSCloudTrail |
| 2025-03-04 | [AWS IAM: Access Key Deleted](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20IAM/AWS-CloudTrail-IAM_AccesKeyDeleted.md) | ... | AWS IAM | Access Key Deleted |
| 2025-03-05 | [AWS IAM: Large Volume of Access Keys Created in Short Time](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20IAM/AWS-CloudTrail-IAM_LargeVolumeOfAccessKeysCreatedInShortWindowOfTime.md) | ... | AWS IAM | AWSCloudTrail |
| 2025-03-06 | [AWS EC2: EC2 Instanced Exported to S3](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20EC2/AWS-CloudTrail-EC2_EC2InstanceExportedToS3.md) | ... | AWS EC2 | AWSCloudTrail |
| 2025-03-07 | [AWS EC2: Unsanctioned EC2 Type Created](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20EC2/AWS-CloudTrail-EC2_UnsanctionedEC2TypeCreated.md) | ... | AWS EC2 | AWSCloudTrail |
| 2025-03-08 | [AWS VPC: Security Group Deleted](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20VPC/AWS-CloudTrail-VPC_SecurityGroupDeleted.md) | ... | AWS VPC | AWSCloudTrail |
| 2025-03-09 | [AWS VPC: VPC With Suspicious Name Created (IOC)](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20VPC/AWS-CloudTrail-VPC_IOCSecurityGroupCreated.md) | ... | AWS VPC | AWSCloudTrail |
| 2025-03-10 | [AWS IAM: Federated User Created](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20IAM/AWS-CloudTrail-IAM_FederatedUserCreated.md) | ... | AWS IAM | AWSCloudTrail |
| 2025-03-11 | [AWS IAM: Actions From Federated User](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20IAM/AWS-CloudTrail-IAM_ActionsFromFederatedUser.md) | ... | AWS IAM | AWSCloudTrail |
| 2025-03-12 | [AWS RDS: Snapshot Taken](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20RDS/AWS-CloudTrail-RDS_RDSSnapshotTaken.md) | ... | AWS RDS | AWSCloudTrail |
| 2025-03-13 | [AWS RDS: Snaptshot Exported to S3](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20RDS/AWS-CloudTrail-RDS_RDSSnapshotExportedToS3.md) | ... | AWS RDS | AWSCloudTrail |
| 2025-03-14 | [AWS Secrets Manager: Large Number of Secrets Accessed in Short Time](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20Secrets%20Manager/AWS-CloudTrail-SecretsManager_LargeNumberOfSecretsAccessedInShortTime.md) | ... | AWS Secrets Manager | AWSCloudTrail |
| 2025-03-15 | [AWS Secrets Manager: Large Number of Secrets Deleted in Short Time](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20Secrets%20Manager/AWS-CloudTrail-SecretsManager_LargeNumberOfSecretsDeletedInShortTime.md) | ... | AWS Secrets Manager | AWSCloudTrail |
| 2025-03-16 | ... | ... | ... | ... |
| 2025-03-17 | [Azure AD: BitLocker Key Accessed](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD_BitLockerKeyAccessed.md) | BitLocker Key Accessed | Azure AD | AuditLogs |
| 2025-03-18 | [Azure Storage: Storage Account Key Accessed](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity%20-%20Storage/AzActivity-ST_StorageAccountKeysAccessed.md) | Azure Storage Account Key accessed | Azure Storage | AzureActivity |
| 2025-03-19 | [Azure Storage: Multiple Storage Account Keys Accessed in Short Time](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity%20-%20Storage/AzActivity-ST_MultipleStorageAccountKeysAccessedInShortTime.md) | Multiple Azure Storage Account Keys accessed in short time | Azure Storage | AzureActivity |
| 2025-03-20 | [SSM Document Ran on Multiple EC2 Instances](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20SSM/AWS-CloudTrail-SSM_SSMDocumentRanOnMultipleInstances.md) | An SSM Document was ran on multiple EC2 instances | AWS SSM | AWSCloudTrail |
| 2025-03-21 | ... | ... | ... | ... |
| 2025-03-22 | [SSM Document Ran but Not Ran in Previous 90 Days](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20SSM/AWS-CloudTrail-SSM_SSMDocumentRanButNotSeenInLast90Days.md) | An SSM Document was ran within the past 1 day, but has not been run within the previous 90 days | AWS SSM | AWSCloudTrail |
| 2025-03-23 | [AWS SSM: SSM Document Ran](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20SSM/AWS-CloudTrail-SSM_SSMDocumentRan.md) | ... | AWS SSM | AWSCloudTrail |
| 2025-03-24 | ... | ... | ... | ... |
| 2025-03-25 | [AAD: Role Assigned to Guest](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD_RoleAssignedToGuest.md) | ... | Azure AD | AuditLogs |
| 2025-03-26 | [AAD: Find Uncommon User-Agent in Sign-In Logs](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD_FindUncommonUserAgent.md) | ... | Azure AD | SignInLogs |
| 2025-03-27 | [Azure Activity: API Call from IP Not Seen in Previous 90 Days](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity/AzActivity_EventsFromIPNotSeenInPrevious90Days.md) | ... | Azure API | AzureActivity |
| 2025-03-28 | ... | ... | ... | ... |
| 2025-03-29 | [AWS CloudTrail: API Call from IP Not Seen in Previous 90 Days](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20CloudTrail/AWS-CloudTrail_NewIPNotSeenInPrevious90Days.md) | ... | AWS CloudTrail | AWSCloudTrail |
| 2025-03-30 | [AWS CloudTrail: API Call from User-Agent Not Seen in Previous 90 days](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/AWS%20CloudTrail/AWS-CloudTrail_NewUserAgentNotSeenInPrevious90Days.md) | ... | AWS CloudTrail | AWSCloudTrail |
| 2025-03-31 | ... | ... | ... | ... |
| 2025-04-01 | [Azure AD: Failed SSPR](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD_SSPR.md) | ... | Azure AD | AuditLogs |
| 2025-04-02 | ... | ... | ... | ... |
| 2025-04-03 | [Azure AD - AuditLogs: Owner Added to App](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-AudtLogs_OwnerAddedToApp.md) | ... | Azure AD | AuditLogs |
| 2025-04-04 | [Azure AD - AuditLogs: Guest Account Added as App Owner](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-AuditLogs_GuestAccountAddedToAppOwner.md) | ... | Azure AD | AuditLogs |
| 2025-04-05 | [Azure AD - AuditLogs: Privileged Role Assigned to External Guest Account](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Active%20Directory/AAD-AuditLogs_PrivilegedRoleAssignedToExternalGuest.md) | ... | Azure AD | AuditLogs |
| 2025-04-06 | ... | ... | ... | ... |
| 2025-04-07 | [Azure Activity: Find Uncommon CallerIpAddresses](https://github.com/KernelCaleb/Kustonomicon/blob/main/Queries/Azure%20Activity/AzActivty_FindUncommonCallerIPAddresses.md) | ... | Azure | AzureActivity |
| 2025-04-08 | ... | ... | ... | ... |
| 2025-04-09 | ... | ... | ... | ... |
| 2025-04-10 | ... | ... | ... | ... |
| 2025-04-11 | ... | ... | ... | ... |

