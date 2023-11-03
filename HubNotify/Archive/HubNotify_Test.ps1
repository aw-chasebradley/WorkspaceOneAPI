<#
*
* Hub Notify Utility
* by Chase Bradley
*
#>

#Set directory to current script path
$Global:current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #Developer utility
    $current_path = "$env:SystemRoot\System32\WindowsPowershell\v1.0\Modules\HubNotify";
}

$shared_path = "C:\Temp\Shared"
$Global:logFile="C:\Temp\Logs\Notifications.log"
$GlobalModules = @();
$GlobalImporter = @("$current_path\RunAsUser.psm1");

foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}

function Send-LWorkspaceOneNotification{
    param([string]$Message,[string]$Caption)    
    Try{
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $IsSystem=$currentUser.IsSystem; 
        If($IsSystem){
            & Invoke-CommandAsUser -mycommand "$current_path\SendWorkspaceOneNotification.ps1"  -argument "-Message $Message -Caption $Caption -StoreInReg"
            $Result=Get-Result -Key "NotificationResult"
        }  
    }Catch{
        $err=$_.Exception.Message;
        Write-Log2 -Message "An error has occured running as current user command:$err" -Path $logFile -Level Error
    }
    return $Result
}