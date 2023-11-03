param([string]$Message, [string]$Caption)
$host.UI.RawUI.WindowTitle = "WorkspaceOne Hub Notify"
#Registry
$ExtensionPath = "HKLM:\Software\AIRWATCH\Extensions";
$CurrentModuleFileName = (Split-Path $PSCommandPath -Leaf).Replace(".psm1","").Replace(".ps1","")
$ModuleName="$CurrentModuleFileName"

$SharedPath=Get-ItemProperty -Path $ExtensionPath | Select-Object "SharedPath" -ExpandProperty "SharedPath" -ErrorAction SilentlyContinue
If(!($SharedPath)){ Throw "Common library is not installed" }

Unblock-File "$SharedPath\Wso.Logging.psm1";
$GlobalModules = Import-Module "$SharedPath\Wso.Logging.psm1" -ErrorAction Stop -PassThru -Force;

$LogPath=Get-ItemProperty -Path $ExtensionPath | Select-Object "LogPath" -ExpandProperty "LogPath" -ErrorAction SilentlyContinue
$Script:LogFile="$LogPath\HubNotify.log"

if(!($PSScriptRoot)){
    Throw "Error, unable to determine current path"
}

Write-Log2 -Path $Script:LogFile -Message "BEGIN HubNotify Launch Script" -ProcessInfo "[HubNotify.LaunchScript]" -Level Debug

Unblock-File "$PSScriptRoot\HubNotify.ContentBuilder.psm1";
$module = Import-Module "$PSScriptRoot\HubNotify.ContentBuilder.psm1" -ErrorAction Stop -PassThru -Force;

#Send-WorkspaceOneNotificationEx -UniqueId "WorkspaceOneTest" -Message $Message -Caption $Caption

Write-Log2 -Path $Script:LogFile -Message "END HubNotify Launch Script" -ProcessInfo "[HubNotify.LaunchScript]" -Level Debug

#Import Uwp Notifcation Library
$Script:AssemblyName = Get-ChildItem -Path "$PSScriptRoot\bin\Microsoft.Toolkit.Uwp.Notifications.dll"
if (-not ($AssemblyName.Name  -as [type])) {
    Unblock-File $AssemblyName.FullName
    Add-Type -Path $AssemblyName.FullName -ErrorAction Stop
}

$ToastContentBuilder=[Microsoft.Toolkit.Uwp.Notifications.ToastContentBuilder]::new()
$ToastContentBuilder.SetToastDuration([Microsoft.Toolkit.Uwp.Notifications.ToastDuration]::Long) | Out-Null
$ToastContentBuilder.SetToastScenario([Microsoft.Toolkit.Uwp.Notifications.ToastScenario]::Default) | Out-Null
$ToastContentBuilder.AddAppLogoOverride("$PSScriptRoot\Resources\icon.jpeg")
$ToastContentBuilder.AddHeader("Id","Workspace ONE Intellegent Hub",@())
$ToastContentBuilder.AddText("Workspace Intellegent Hub reminder to delete the thing.")
$ToastContentBuilder.SetProtocolActivation(".\Notepad.exe")
$ToastContentBuilder.Show()


