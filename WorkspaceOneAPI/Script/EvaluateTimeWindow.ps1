param([string]$LogLevel)

$WorkspaceOneModulePath="C:\Ws1\WorkspaceOneAPI"
$AddTagModulePath="C:\Ws1\WorkspaceOneAPI\Addon"
Unblock-File -Path "$AddTagModulePath\Wso.API.Tags.psm1"
$module = Import-Module "$AddTagModulePath\Wso.API.Tags.psm1" -ErrorAction Stop -PassThru -Force;
Unblock-File -Path "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1"
$module = Import-Module "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1" -ErrorAction Stop -PassThru -Force;

$CurrentTime=(Get-Date)
echo "CurrentTime is $CurrentTime"

$ExtensionPath = "HKLM:\Software\AIRWATCH\Extensions" 

$TagName="TimeWindow_000"

$TimeWindowStart=12
$TimeWindowEnd=13

$InTimeWindow=(($CurrentTime.Hour -ge $TimeWindowStart) -and ($CurrentTime.Hour -le $TimeWindowEnd))

If(!$InTimeWindow){
    echo "Out of time window"
}Else{
    echo "In time window"
}

Set-WSODeviceTag -TagName $TagName -Result $InTimeWindow -CreateTag 
