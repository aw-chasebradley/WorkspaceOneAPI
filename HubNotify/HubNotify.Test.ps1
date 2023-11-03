#Set directory to current script path
$current_path = $PSScriptRoot;
if(!($current_path)){ Throw "Unable to obtain current path" }

Unblock-File "$PSScriptRoot\HubNotify.psm1";
$module = Import-Module "$PSScriptRoot\HubNotify.psm1" -ErrorAction Stop -PassThru -Force;

Send-WorkspaceOneNotification -Message "Hello" -Caption "World"