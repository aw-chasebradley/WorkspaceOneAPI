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
    New-Item -Path $InstallPath -Force; 
    New-ItemProperty -Path $InstallPath -Name "InstallLocation" -Value "$PSScriptRoot" -Force 
}

#Setting up Log Location
$logLocation="$($LibPaths.LogPath)\$ModuleName.log"
#ModuleFileName

$SecurityRestriction="{'Ownership':'S','AuthType':1}"
$RegResults=New-ItemProperty -Path $InstallPath -Name "SecurityRestrictions" -Value $SecurityRestriction -Force

#Setting up Log Location
$Script:LogLocation="$($LibPaths.LogPath)\$ModuleName.log"
#ModuleFileName
$CurrentModuleFileName = (Split-Path $PSCommandPath -Leaf).Replace(".psm1","").Replace(".ps1","")

Set-Alias -Name NewObj -Value New-DynamicObject

#Set API endpoints

<#$user_details_endpoint = "/api/system/users/";
$og_search_endpoint = "/api/system/groups/search";
$change_og_endpoint = "/api/mdm/devices/{DeviceId}/commands/changeorganizationgroup/";
#>

Function Get-WsoOrganizationGroupByGroupId{
    [Alias("Get-WsoOrganizationGroup")]
    param([string]$GroupId, [hastable]$ApiSettings)
    $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand 
    $OgSearchEndpoint = "/api/system/groups/search?groupid=$NewGroupId";
    $OgSearchResult = Invoke-WorkspaceOneAPICommand -Endpoint $OGSearchEndpoint -Method "GET" -ApiVersion 2 -UseLocal:(!($ApiSettings))
    If($OgSearchResult.OrganizationGroups){
        return $OgSearchResult
    }
    return
}


Function Set-WsoDeviceOrganizationGroup{
    param($NewGroupId, $ApiSettings)
    
}


Function Get-CurrentWsoDevice{
    param([hashtable]$ApiSettings)
    Begin{
        $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand 
    } Process{
        $CurrentDeviceEndpoint = "/api/mdm/devices/{DeviceId}/";
        $CurrentDeviceResult =  Invoke-WorkspaceOneAPICommand -Endpoint $CurrentDeviceEndpoint -ApiSettings $ApiSettings -UseLocal:(!($ApiSettings))
        If($CurrentDeviceResult){
            return $CurrentDeviceResult
        }
        return
    } 
}


Function Get-WSOCurrentUserId{
    param([hashtable]$ApiSettings)
    Begin{
        $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand 
    } Process{
        $MultiUserSecurityRestrictionsReg=Get-ItemProperty -Path $ModuleInstallPath -ErrorAction SilentlyContinue | Select-Object -Property "SecurityRestrictions" -ExpandProperty "SecurityRestrictions" -ErrorAction SilentlyContinue
        If(!($MultiUserSecurityRestrictionsReg)){ Throw (New-CustomException "Error, unable to load multi-user device restriction settings") }
        $MultiUserSecurityRestrictions=ConvertFrom-Json $MultiUserSecurityRestrictionsReg

        $CurrentUser = Get-CurrentLoggedonUser;
        
        #DEBUG
        $CurrentUser = New-Object -TypeName PSCustomObject -Property @{"Username"="Cenroll"}
        #DEBUG

        $UserSearchEndpoint="/api/system/users/search?username=$($CurrentUser.Username)"
        $UserSearchResults = Invoke-WorkspaceOneAPICommand -Endpoint "$UserSearchEndpoint" -ApiVersion 2 -ApiSettings $ApiSettings -UseLocal:(!($ApiSettings))
        If($UserSearchResults.Users){
            $UserSearchFilter = $UserSearchResults.Users | Where {$_.UserName -EQ "$($CurrentUser.Username)" -and $_.SecurityType -eq $MultiUserSecurityRestrictions.AuthType}
            If($UserSearchFilter){
                return $UserSearchFilter[0].Id.Value
            }
        }
        return
    }
}

Function Set-WSODeviceUser{
    param([hashtable]$ApiSettings)
    Begin{
        $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand 
    } Process{
        Try{
            $MultiUserSecurityRestrictionsReg=Get-ItemProperty -Path $InstallPath -ErrorAction SilentlyContinue | Select-Object -Property "SecurityRestrictions" -ExpandProperty "SecurityRestrictions"
            If(!($MultiUserSecurityRestrictionsReg)){ Throw (New-CustomException "Error, unable to load multi-user device restriction settings") }
            $MultiUserSecurityRestrictions=ConvertFrom-Json $MultiUserSecurityRestrictionsReg
            #Get the current device
            $CurrentDevice=Get-CurrentWsoDevice -ApiSettings $ApiSettings
            
            $CurrentUser = Get-CurrentLoggedonUser 
            If($CurrentUser.Username -eq $CurrentDevice.Username){
                Write-Log2 -Path $Script:LogLocation -ProcessInfo $ProcInfo -Message "PROCESS Current logged on Windows user, '$($CurrentUser.Username)' matches WorkspaceOne UEM user for current device '$($CurrentDevice.Username)'"
                return0
            }

            If($CurrentDevice.Ownership -ne $MultiUserSecurityRestrictions.Ownership){
                Throw (New-CustomException "Error, current device is unauthorized from user change.  Current device /
                    has ownership '$($CurrentDevice.Ownership)', device ownership, '$($MultiUserSecurityRestrictions.Ownership)' is required")
            }

            $CurrentUserId = Get-WSOCurrentUserId -ApiSettings $ApiSettings
            If(!($CurrentUserId)){
                Throw (New-CustomException "Error, no user found with username '$($CurrentUser.Username)', and allowed Security Type, '$($MultiUserSecurityRestrictions.AuthType)'")
            }

            $ChangeUserEndpoint = "/api/mdm/devices/{DeviceId}/enrollmentuser/$CurrentUserId";
            $ChangeUserResults = Invoke-WorkspaceOneAPICommand -Endpoint "$ChangeUserEndpoint" -Method PATCH -ApiVersion 1 -UseLocal:(!($ApiSettings)) 
        } Catch{
            $err=$_.Exception.Message;
            Write-Log2 -Path $Script:LogLocation -ProcessInfo $ProcInfo -Message "END An error has occured, $err" -Level Error
        }
    }
}
