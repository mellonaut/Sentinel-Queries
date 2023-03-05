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