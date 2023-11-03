param([string]$Message, [string]$Caption)

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    Throw "Error, unable to determine current path"
}

$ExtensionPath="HKLM:\SOFTWARE\AirWatch\Extensions"
$shared_path=Get-ItemProperty -Path $ExtensionPath | Select-Object "SharedPath" -ExpandProperty "SharedPath" -ErrorAction SilentlyContinue

If(!($shared_path)){ Throw "Common library is not installed" }

Unblock-File "$current_path\HubNotify.ContentBuilder.psm1";
$module = Import-Module "$current_path\HubNotify.ContentBuilder.psm1" -ErrorAction Stop -PassThru -Force;

& Send-WorkspaceOneNotificationL -Message $Message -Caption $Caption