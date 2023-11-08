<#
.SYNOPSIS
    WorkspaceOneAPI Library
.DESCRIPTION 
    A long description of how the script works and how to use it.
#>

#Module metadata info
$CurrentModuleFileName = (Split-Path $PSCommandPath -Leaf).Replace(".psm1","").Replace(".ps1","")
$ModuleName="$CurrentModuleFileName"

#Registry
$ExtensionPath = "HKLM:\Software\AIRWATCH\Extensions";
$ApiPath = "$ExtensionPath\WorkspaceOneAPI";
$InstallPath="$ExtensionPath\$ModuleName";

#Import the Workspace ONE API module
$WorkspaceOneModulePath = Get-ItemProperty -Path $ApiPath -ErrorAction SilentlyContinue | Select-Object "InstallLocation" -ExpandProperty "InstallLocation" -ErrorAction SilentlyContinue
If(!($WorkspaceOneModulePath)){  Throw "The WorkspaceONEAPI Module is not installed or path was not available.  Module not loaded." }

Unblock-File "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1";
$WSOModule=Import-Module "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1" -ErrorAction Stop -PassThru -Force;

If(!(Test-Path $InstallPath)){ 
    $RegResult=New-Item -Path $InstallPath -Force; 
    $RegResult=New-ItemProperty -Path $InstallPath -Name "InstallLocation" -Value "$PSScriptRoot" -Force 
}

#Setting up Log Location
$logLocation="$($LibPaths.LogPath)\$ModuleName.log"

Function Get-WorkspaceOneApplications{
    param([string]$ApplicationName,[string]$Platform="WinRT",[string]$Status,[hashtable]$ApiSettings)
    $AppSearchEndpoint="api/mam/apps/search?type=app&applicationtype=internal"
    If(![string]::IsNullOrEmpty($Platform)){ $AppSearchEndpoint += "&platform=$Platform" }
    If(![string]::IsNullOrEmpty($ApplicationName)){ $AppSearchEndpoint += "&applicationName=$ApplicationName" }
    If(![string]::IsNullOrEmpty($Status)){ $AppSearchEndpoint += "&status=$Status" }
    $AppSearchResults=Invoke-WorkspaceOneAPICommand -Endpoint $AppSearchEndpoint -ApiSettings $ApiSettings -UseLocal:(!$ApiSettings)
    return $AppSearchResults
}

Function Get-WorkspaceOneApplicationDetails{
    param($AppId, [hashtable]$ApiSettings)
    $AppEndpoint="api/mam/apps/internal/$AppId"
    $AppResult=Invoke-WorkspaceOneAPICommand -Endpoint $AppEndpoint -ApiSettings $ApiSettings -UseLocal:(!$ApiSettings)
    return $AppResult
}

Function Get-WorkspaceOneApplicationMetadata{
    param($SmartGroupName,$OrganizationGroupId="{OrganizationGroupId}",[hashtable]$ApiSettings)
    $SmartGroupSearch="api/mdm/smartgroups/search?name=$SmartGroupName&organizationgroupid=$OrganizationGroupId"
    $SmartGroupSearchResult=Invoke-WorkspaceOneAPICommand -Endpoint $SmartGroupSearch -ApiSettings $ApiSettings -UseLocal:(!$ApiSettings)
    If(!($SmartGroupSearchResult.SmartGroups)){
        Throw "Error, could not retrieve Smart Group"
    }
    $SmartGroup = $SmartGroupSearchResult.SmartGroups | Where Name -eq $SmartGroupName
    If(!($SmartGroup)){
        Throw "Error, no group matching name, '$SmartGroupName'."
    }
    $SmartGroupAppsEndpoint="/api/mdm/smartgroups/$($SmartGroup.SmartGroupID)/apps"
    $SmartGroupAppResult=Invoke-WorkspaceOneAPICommand -Endpoint $SmartGroupAppsEndpoint -ApiSettings $ApiSettings -UseLocal:(!$ApiSettings)

    $CurrentDeviceApps=Get-CurrentDeviceApps -ApiSettings $ApiSettings

    $InstalledApps=$CurrentDeviceApps.app_items | Where "installed_status" -eq "Installed"
    $BundledApps=@()
    If($InstalledApps){
        $BundledApps=($InstalledApps | Select "bundle_id").bundle_id
    }

    $SmartGroupAppResult=$SmartGroupAppResult | Where bundleId -notin $BundledApps#> 

    $AppStores=@()
    For($i=0;$i -lt $SmartGroupAppResult.Count;$i++){
        $App =$SmartGroupAppResult[$i]
        $AppDetails=Get-WorkspaceOneApplicationDetails -AppId $App.Id -ApiSettings $ApiSettings
        If($AppDetails.Status -eq "Active"){
            ($App | Add-Member -MemberType NoteProperty -Name "InstallTimeOutInMinutes" -Value $AppDetails.DeploymentOptions.HowToInstall.InstallTimeoutInMinutes) | Out-Null
            ($App | Add-Member -MemberType NoteProperty -Name "ChangeLog" -Value $AppDetails.ChangeLog) | Out-Null
            ($App | Add-Member -MemberType NoteProperty -Name "Status" -Value $AppDetails.Status) | Out-Null
            ($App | Add-Member -MemberType NoteProperty -Name "Comments" -Value $AppDetails.Comments) | Out-Null
            ($App | Add-Member -MemberType NoteProperty -Name "uuid" -Value $AppDetails.uuid) | Out-Null
            ($App | Add-Member -MemberType NoteProperty -Name "BuildVersion" -Value $AppDetails.BuildVersion) | Out-Null
            ($App | Add-Member -MemberType NoteProperty -Name "AppId" -Value $AppDetails.AppId) | Out-Null
            ($App | Add-Member -MemberType NoteProperty -Name "AppId" -Value $AppDetails.AppId) | Out-Null
            $AppStores+=@($App)
        }
    }
    return $AppStores
}

Function Get-CurrentDeviceApps{
    param([hashtable]$ApiSettings)
     $CurrentDeviceAppEndpoint="API/mdm/devices/{DeviceUuid}/apps/search"
     $CurrentDeviceAppResults=Invoke-WorkspaceOneAPICommand -Endpoint $CurrentDeviceAppEndpoint -ApiSettings $ApiSettings -UseLocal:(!$ApiSettings)
     return $CurrentDeviceAppResults
}

Function Test-LocalAppStatus{
    param([string]$BuildVersion,[string]$Context="System")
    If($Context -ne "System"){
        $Context = ""
    }
    $SIDPath=Get-UserSIDLookup -UsernameLookup $Context
    $AppDeployPath="HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\$SIDPath\$BuildVersion"
    $AppInstallStatus=Get-ItemProperty -Path $AppDeployPath -ErrorAction SilentlyContinue | Select-Object "IsInstalled" -ExpandProperty "IsInstalled" -ErrorAction SilentlyContinue
    return $AppInstallStatus
}