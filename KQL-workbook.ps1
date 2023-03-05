# Connect to Azure for Log Analytics
Connect-AzAccount
$sub = Get-azsubscription
Set-AzContext -Subscription $sub
$workspaceName = "sc200"
$workspaceRG = "sc-200"
$WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $workspaceName -ResourceGroupName $workspaceRG).CustomerID

# Query user's last PIM role activation for 'Global Reader' (role definition id: f2ef992c-3afb-46b9-b7cf-a126ee74c451)
$query = "AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName == 'Add member to role completed (PIM activation)'
| where Result == 'success'
| where InitiatedBy.user.id == '8b51737b-f961-41b0-ade7-6e59c77d6e62'
| where TargetResources[0].id == 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'
| sort by TimeGenerated desc
| limit 1"

$kqlQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query
$kqlQuery.Results.TimeGenerated

# Last 50 sign ins

$query2 = "SigninLogs
| order by TimeGenerated desc
| take 50"

$kqlQuery2 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query2
$kqlQuery2.Results

$query3 = Get-Content '.\Azure Activity\Azure-ServicePrincipalAddedtoAzure.kql'
$kqlQuery3 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query3
$kqlQuery3.Results

# network logins for Local accounts in M365 Defender 
$mdeQuery1 = 'DeviceLogonEvents
| where Timestamp > ago(30d)
| where AccountDomain == DeviceName and isnotempty( RemoteIP) and RemoteIP !in ('::1','-', '0.0.0.0') and RemoteIP !startswith "127."
| summarize LogonAttempts = count(), DistinctMachines = dcount(DeviceId), Successes = countif(ActionType == 'Success'), RemoteDeviceName = any(RemoteDeviceName)  by RemoteIP, Protocol, LogonType, AccountName
| order by Successes desc, LogonAttempts desc'
$mdeQuery1 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery1
$mdeQuery1.Results

# Admin 500 account login
$mdeQuery2 = "DeviceLogonEvents
| where AccountSid endswith '-500' and parse_json(AdditionalFields).IsLocalLogon != true
| join kind=leftanti IdentityLogonEvents on AccountSid // Remove the domain's built-in admin acccount"
$mdeQuery2 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery2
$mdeQuery2.Results

# Look for public IP addresses that failed to logon to a computer multiple times, using multiple accounts, and eventually succeeded.
$mdeQuery3 = 'DeviceLogonEvents
| where isnotempty(RemoteIP) 
    and AccountName !endswith "$"
    and RemoteIPType == "Public"
| extend Account=strcat(AccountDomain, "\\", AccountName)
| summarize 
    Successful=countif(ActionType == "LogonSuccess"),
    Failed = countif(ActionType == "LogonFailed"),
    FailedAccountsCount = dcountif(Account, ActionType == "LogonFailed"),
    SuccessfulAccountsCount = dcountif(Account, ActionType == "LogonSuccess"),
    FailedAccounts = makeset(iff(ActionType == "LogonFailed", Account, ""), 5),
    SuccessfulAccounts = makeset(iff(ActionType == "LogonSuccess", Account, ""), 5)
    by DeviceName, RemoteIP, RemoteIPType
| where Failed > 10 and Successful > 0 and FailedAccountsCount > 2 and SuccessfulAccountsCount == 1

// Query #2: Look for machines failing to log-on to multiple machines or using multiple accounts
// Note - RemoteDeviceName is not available in all remote logon attempts
DeviceLogonEvents
| where isnotempty(RemoteDeviceName)
| extend Account=strcat(AccountDomain, "\\", AccountName)
| summarize 
    Successful=countif(ActionType == "LogonSuccess"),
    Failed = countif(ActionType == "LogonFailed"),
    FailedAccountsCount = dcountif(Account, ActionType == "LogonFailed"),
    SuccessfulAccountsCount = dcountif(Account, ActionType == "LogonSuccess"),
    FailedComputerCount = dcountif(DeviceName, ActionType == "LogonFailed"),
    SuccessfulComputerCount = dcountif(DeviceName, ActionType == "LogonSuccess")
    by RemoteDeviceName
| where
    Successful > 0 and
    ((FailedComputerCount > 100 and FailedComputerCount > SuccessfulComputerCount) or
        (FailedAccountsCount > 100 and FailedAccountsCount > SuccessfulAccountsCount))'
$mdeQuery3 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery3
$mdeQuery3.Results

# Weird process from webserver
# Detect suspicious commands initiated by web server processes


$mdeQuery4 = 'DeviceProcessEvents 
| where Timestamp > ago(7d)
// Pivoting on parents or grand parents
and (((InitiatingProcessParentFileName in("w3wp.exe", "beasvc.exe",
"httpd.exe") or InitiatingProcessParentFileName startswith "tomcat")
or InitiatingProcessFileName in("w3wp.exe", "beasvc.exe", "httpd.exe") or
InitiatingProcessFileName startswith "tomcat"))
    and FileName in~("cmd.exe","powershell.exe")
| where ProcessCommandLine contains "%temp%"
    or ProcessCommandLine has "wget"
    or ProcessCommandLine has "whoami"
    or ProcessCommandLine has "certutil"
    or ProcessCommandLine has "systeminfo"
    or ProcessCommandLine has "ping"
    or ProcessCommandLine has "ipconfig"
    or ProcessCommandLine has "timeout"
| summarize any(Timestamp), any(Timestamp), any(FileName),
makeset(ProcessCommandLine), any(InitiatingProcessFileName),
any(InitiatingProcessParentFileName) by DeviceId'

$mdeQuery4 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery4
$mdeQuery4.Results


# kERBEROASTING ldap 
$mdeQuery5 = 'let ASREP_ROASTING = "userAccountControl:1.2.840.113556.1.4.803:=4194304";
let ASREP_ROASTING1 = "userAccountControl|4194304";
let ASREP_ROASTING2 = "userAccountControl&4194304";
let KERBEROASTING = "serviceprincipalname=*";
let LDAP_PORT = 389;
let ExcludeNtAuthorityProcess = true;
let AzureAtpLdap = (
IdentityQueryEvents
| where ActionType == "LDAP query"
| parse Query with * "Search Scope: " SearchScope ", Base Object:" BaseObject ", Search Filter: " SearchFilter
| where SearchFilter contains ASREP_ROASTING or
SearchFilter contains ASREP_ROASTING1 or
SearchFilter contains ASREP_ROASTING2 or
SearchFilter contains KERBEROASTING
| extend Time = bin(Timestamp, 1s)
| extend DeviceNameWithoutDomain = tolower(tostring(split(DeviceName, '.')[0])));
let MDAtpNetworkToProcess = (
DeviceNetworkEvents
| extend DeviceNameWithoutDomain = tolower(tostring(split(DeviceName, '.')[0]))
| where RemotePort == LDAP_PORT
| extend Time = bin(Timestamp, 1s)
| extend isExclude = iff( ExcludeNtAuthorityProcess and InitiatingProcessAccountDomain == "nt authority" , true, false));
AzureAtpLdap
| join kind=leftouter (
MDAtpNetworkToProcess ) on DeviceNameWithoutDomain, Time 
| where isExclude == false or isnull(isExclude)'

$mdeQuery5 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery5
$mdeQuery5.Results

# // Query for processes that accessed more than 10 IP addresses over port 445
$mdeQuery6 = '
DeviceNetworkEvents
| where RemotePort == 445 and Timestamp > ago(7d) 
    // Exclude Kernel processes, as they are too noisy in this query
    and InitiatingProcessId !in (0, 4)
| summarize RemoteIPCount=dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime
| where RemoteIPCount > 10'
$mdeQuery6 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery6
$mdeQuery6.Results

# cConnections to URL can use contains or has
$mdeQuery7 = "
let partialRemoteUrlToDetect = 'milkybeefers.com'; 
DeviceNetworkEvents  
| where Timestamp > ago(30d)
and RemoteUrl contains partialRemoteUrlToDetect 
| project Timestamp, DeviceName, DeviceId, ReportId
| top 100 by Timestamp desc"
$mdeQuery7 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery7
$mdeQuery7.Results

# jscriop[t file creation]
mdeQuery8 = 'DeviceFileEvents 
| where Timestamp > ago(30d)
| where FileName endswith ".jse"'
$mdeQuery8 = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $mdeQuery8
$mdeQuery8.Results

# email link open then smartscreen warning
$mdeQuery8 = 'let smartscreenAppWarnings =
// Query for SmartScreen warnings of unknown executed applications
    DeviceEvents
    | where ActionType == "SmartScreenAppWarning"
    | project WarnTime=Timestamp, DeviceName, WarnedFileName=FileName, WarnedSHA1=SHA1, ActivityId=extractjson("$.ActivityId", AdditionalFields, typeof(string))
    // Select only warnings that the user has decided to ignore and has executed the app.
    | join kind=leftsemi (
            DeviceEvents
            | where ActionType == "SmartScreenUserOverride"
            | project DeviceName, ActivityId=extractjson("$.ActivityId", AdditionalFields, typeof(string)))
         on DeviceName, ActivityId
	| project-away ActivityId;
// Query for links opened from outlook, that are close in time to a SmartScreen warning
let emailLinksNearSmartScreenWarnings =
    DeviceEvents
    | where ActionType == "BrowserLaunchedToOpenUrl" and isnotempty(RemoteUrl) and InitiatingProcessFileName =~ "outlook.exe"
    | extend WasOutlookSafeLink=(tostring(parse_url(RemoteUrl).Host) endswith "safelinks.protection.outlook.com")
    | project DeviceName, MailLinkTime=Timestamp,
        MailLink=iff(WasOutlookSafeLink, url_decode(tostring(parse_url(RemoteUrl)["Query Parameters"]["url"])), RemoteUrl)
    | join kind=inner smartscreenAppWarnings on DeviceName | where (WarnTime-MailLinkTime) between (0min..4min);
// Add the browser download event to tie in all the dots
DeviceFileEvents
| where isnotempty(FileOriginUrl) and InitiatingProcessFileName in~ ("chrome.exe", "firefox.exe", "edge.exe", "brave.exe", "browser_broker.exe")
| project FileName, FileOriginUrl, FileOriginReferrerUrl, DeviceName, Timestamp, SHA1
| join kind=inner emailLinksNearSmartScreenWarnings on DeviceName
| where (Timestamp-MailLinkTime) between (0min..3min) and (WarnTime-Timestamp) between (0min..1min)
| project FileName, MailLink, FileOriginUrl, FileOriginReferrerUrl, WarnedFileName, DeviceName, SHA1, WarnedSHA1, Timestamp
| distinct *'
