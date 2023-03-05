# [CmdletBinding()]
# param (
#     [Parameter(Mandatory=$true)]
#     [string]$FilePath,

#     [Parameter()]
#     [string]$WorkspaceName = "sc200",

#     [Parameter()]
#     [string]$WorkspaceResourceGroup = "sc-200"
# )
$WorkspaceName = "sc200"
$WorkspaceResourceGroup = "sc-200"


Uninstall-AzureRm

if (!(Get-Module -Name Az.OperationalInsights -ListAvailable)) {
    Write-Host "Installing Az.OperationalInsights module..."
    Install-Module -Name Az.OperationalInsights -Scope CurrentUser -Force -AllowClobber
} else {
    Write-Host "Az.OperationalInsights module is already installed."
}

Import-Module Az.OperationalInsights

if (Get-AzContext -ErrorAction SilentlyContinue) {
    Write-Host "You are already signed in to Azure."
} else {
    Write-Host "You are not signed in to Azure. Please sign in."
    Connect-AzAccount
}

$sub = Get-AzSubscription
Set-AzContext -Subscription $sub
$WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $WorkspaceName -ResourceGroupName $WorkspaceResourceGroup).CustomerId


$FilePath = ".\UEBA\IdentityInfo-FindAccountsPasswordNotRequired.kql"

# Read the contents of the file into an array
$fileContents = Get-Content $FilePath -Delimiter "`n"

# Join the array elements into a single string, starting from the 5th line
$query = ($fileContents[4..($fileContents.Length - 1)] -join "`n").Trim()

# Execute the query using Invoke-AzOperationalInsightsQuery
$result = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query

$result




