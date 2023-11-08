$AddTagModulePath="C:\Ws1\WorkspaceOneAPI\Addon"
Unblock-File -Path "$AddTagModulePath\Wso.API.UserManagement.psm1"
$module = Import-Module "$AddTagModulePath\Wso.API.UserManagement.psm1" -ErrorAction Stop -PassThru -Force;

Set-WSODeviceUser