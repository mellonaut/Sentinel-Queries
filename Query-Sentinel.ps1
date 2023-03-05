[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$FilePath,

    [Parameter()]
    [string]$WorkspaceName = "sc200",

    [Parameter()]
    [string]$WorkspaceResourceGroup = "sc-200"
)

Connect-AzAccount

$sub = Get-AzSubscription
Set-AzContext -Subscription $sub

$WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $WorkspaceName -ResourceGroupName $WorkspaceResourceGroup).CustomerId

$query = Get-Content $FilePath
$kqlQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query
$kqlQuery.Results