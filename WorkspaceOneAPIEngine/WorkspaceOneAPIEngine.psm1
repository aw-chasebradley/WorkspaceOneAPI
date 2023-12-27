<# 
.SYNOPSIS
    WorkspaceOneAPIEngine for importing WorkspaceOneAPI and additional libraries
#>

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Write-Host -ForegroundColor White -Object "IsAdministrator`: $($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" | Out-Null
If( !($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) ) { return }
Write-Host -ForegroundColor White -Object "Loading WorkspaceOneAPIEngine" | Out-Null
$CurrentPath=$PSScriptRoot

#Module metadata info
$CurrentModuleFileName = (Split-Path $PSCommandPath -Leaf).Replace(".psm1","").Replace(".ps1","")
$ModuleName="$CurrentModuleFileName"

#Registry
$ExtensionPath = "HKLM:\Software\AIRWATCH\Extensions";
$ApiPath = "$ExtensionPath\WorkspaceOneAPI";

#Import the Workspace ONE API module
$WorkspaceOneModulePath = Get-ItemProperty -Path $ApiPath -ErrorAction SilentlyContinue | Select-Object "InstallLocation" -ExpandProperty "InstallLocation" -ErrorAction SilentlyContinue
If(!($WorkspaceOneModulePath)){  
    If(Test-Path "$CurrentPath\WorkspaceOneAPI.psm1"){
        $WorkspaceOneModulePath="$CurrentPath"
        Unblock-File "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1";
        $WSOModule=Import-Module "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1" -ErrorAction Stop -PassThru -Force;
    }Else{
        Throw "The WorkspaceONEAPI Module is not installed or path was not available.  Module not loaded." 
    }
}

If(Test-Path $ExtensionPath){
    $InstalledModules=@(Get-ChildItem -Path $ExtensionPath | Where PSChildName -notin @("Cache", "WorkspaceOneAPI") | Select Name, PSChildName)
}

$ExportedFunctions=@()
$ExportedAliai=@()

If($InstalledModules){
    For($i=0;$i -lt $InstalledModules.Count;$i++){
        $InstalledModule=$InstalledModules[$i]
        #Write-Host -ForegroundColor White -Object "Module name: $($InstalledModule.Name)"
        If($InstalledModule.PSChildName -eq "WorkspaceOneAPIEngine"){
            continue;
        }
        $ModuleInstallLocation=Get-ItemProperty -Path "$ExtensionPath\$($InstalledModule.PSChildName)" -ErrorAction SilentlyContinue | Select "InstallLocation" -ExpandProperty "InstallLocation" -ErrorAction SilentlyContinue
        If($ModuleInstallLocation){
            Unblock-File "$ModuleInstallLocation\$($InstalledModule.PSChildName).psm1"
            $WSOModule=Import-Module "$ModuleInstallLocation\$($InstalledModule.PSChildName).psm1" -ErrorAction Stop -PassThru -Force;
            $ExportedFunctions += $WSOModule.ExportedFunctions.Keys
            $ExportedAliai += $WSOModule.ExportedAliases.Keys
        }
    }
}


Unblock-File "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1";
$WSOModule=Import-Module "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1" -ErrorAction Stop -PassThru -Force;
$ExportedFunctions += $WSOModule.ExportedFunctions.Keys
$ExportedAliai += $WSOModule.ExportedAliases.Keys
$ExportedFunctions=$ExportedFunctions | Get-Unique
$ExportedAliai=$ExportedAliai | Get-Unique

#Export-ModuleMember -Function $ExportedFunctions -Alias $ExportedAliai