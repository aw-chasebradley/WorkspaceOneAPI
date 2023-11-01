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

Function Get-Applications{
    param([hashtable]$ApiSettings)
    $AppEndpoint="api/mam/apps/search?type=app"
    $AppResults=Invoke-WorkspaceOneAPICommand -Endpoint $AppEndpoint -ApiSettings $ApiSettings -UseLocal:(!$ApiSettings)
    
    return $AppResults
}