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

$InstallPath="HKLM:\Software\AIRWATCH\Extensions"
$ModulePath="$InstallPath\HubNotify"

$log_path="C:\Temp\Logs"
$shared_path = "C:\Temp\Shared"
If(Test-Path $InstallPath){
    $shared_path = Get-ItemProperty -Path $InstallPath | Select-Object "SharedPath" -ExpandProperty "SharedPath"
    $log_path = Get-ItemProperty -Path $InstallPath | Select-Object "LogPath" -ExpandProperty "LogPath"      
} 
$Global:logFile="$log_path\Notifications.log"

$GlobalModules = @();
$GlobalImporter = @("$shared_path\Wso.CommonLib.psm1","$current_path\RunAsUser.psm1");

foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}

function Test-HubNotifyRegistry{
    If(!(Test-Path "HKLM:\Software\AIRWATCH\Extensions\HubNotify\UserStorage")){      
        Write-Log2 -Message "WorkspaceONE.HubNotify::[HKLM:\Software\AIRWATCH\Extensions\HubNotify\UserStorage] does not exist in registry.  Creating..." -Path $logFile -Level Warn            
        New-Item -Path "HKLM:\Software\AIRWATCH\Extensions\HubNotify\UserStorage" -Name "HubNotify" -Force
    }
    $CheckRegistry=Get-ItemProperty "HKLM:\Software\AIRWATCH\Extensions\HubNotify\UserStorage" | Select-Object "NotificationResult"
    If(($CheckRegistry | Measure).Count -lt 1){
        Write-Log2 -Message "WorkspaceONE.HubNotify::Creating registry keyvalue" -Path $logFile -Level Info            
        New-ItemProperty -Path HKLM:\Software\AIRWATCH\Extensions\HubNotify\UserStorage -Name "NotificationResult" -Value "" -Force
    }
}

function Test-HubNotifyRegPermissions{
    $RegItem=Get-Item HKLM:\Software\AIRWATCH\Extensions\HubNotify\UserStorage -Force -ErrorAction Stop
    $currentAccessList = $RegItem.GetAccessControl('Access');
    $currentPermission = $currentAccessList.Access | Where IdentityReference -eq $currentUser.FullName
    If($currentPermission.RegistryRights -eq "SetValue, CreateSubKey, ReadKey" -and $currentPermission.AccessControlType -eq "Allow"){
        return $true
    }
    $currentUser = Get-CurrentLoggedonUser -ReturnObj $true   
    $AccessRule= New-Object System.Security.AccessControl.RegistryAccessRule($currentUser.FullName, "SetValue, CreateSubKey, ReadKey",
                            'ContainerInherit,ObjectInherit', 'None', "Allow");
    $currentAccessList.SetAccessRule($AccessRule)
    Set-Acl -Path HKLM:\Software\AIRWATCH\Extensions\HubNotify\UserStorage -AclObject $currentAccessList  
}


function Set-Result{
    param($Key,$Value)
    #Write-Log2 -Message "WorkspaceONE.HubNotify::Setting notification feedback information in registry, with value: $Value" -Path $logFile -Level Info
    Try{        
        Set-ItemProperty -Path HKLM:\Software\AIRWATCH\Extensions\HubNotify\UserStorage -Name $Key -Value $Value -Force       
    } Catch{
        $err=$_.Exception.Message;
        Write-Log2 -Message "WorkspaceONE.HubNotify::An error has occured setting notifcation result in registry, $err" -Path $logFile -Level Error
    }

}

function Get-Result{
    param($Key)
    Write-Log2 -Message "WorkspaceONE.HubNotify::Getting registry key, $Key. " -Path $logFile -Level Info
    $TimeOut=60;
    Try{        
        $Result=Get-ItemPropertyValueSafe -Path HKLM:\Software\AIRWATCH\Extensions\HubNotify\UserStorage -Name $Key -DefaultVal -1
        While($TimeOut -gt 0 -and $Result -eq -1){
            $Result=Get-ItemPropertyValueSafe -Path HKLM:\Software\AIRWATCH\Extensions\HubNotify\UserStorage -Name $Key -DefaultVal -1
            $TimeOut=$TimeOut-1
            Start-Sleep -Seconds 1
            #Write-Log2 -Message "WorkspaceONE.HubNotify::Result at $TimeOut is $Result." -Path $logFile -Level Info
        }
    }Catch{
        $err=$_.Exception.Message;
        Write-Log2 -Message "WorkspaceONE.HubNotify::An error has occured Getting notifcation result in registry, $err" -Path $logFile -Level Error
    }
    return $Result
}

function Test-CurrentContext() {  
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    return $currentUser.IsSystem; 
}

function Send-WorkSpaceOneNotification{
    param([string]$Message,[string]$Caption,[string]$MessageType="YesNo",[switch]$StoreInReg)
    Write-Log2 -Path $logFile -Message "WorkspaceONE.HubNotify::Sending message"
    Try{
        if (-not ("System.Windows.Forms.MessageBox"  -as [type])){
            [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        }
    }Catch{
        $err=$_.Exception.Message
        Write-Log2 -Message "WorkspaceONE.HubNotify.DotNet::An error has occured, $err" -Path $logFile -Level Error
    }

    Try{
        If($MessageType -eq "YesNo"){
            $Result=[System.Windows.Forms.MessageBox]::Show($Message, $Caption, [System.Windows.Forms.MessageBoxButtons]::YesNo)            
        } ElseIf($MessageType -eq "Alert"){
            $Result=[System.Windows.Forms.MessageBox]::Show($Message, $Caption, [System.Windows.Forms.MessageBoxButtons]::OK)
        }
    }Catch{
        $err=$_.Exception.Message
        Write-Log2 -Message "WorkspaceONE.HubNotify.DotNet::An error has occured, $err" -Path $logFile -Level Error
    }
    If($StoreInReg.IsPresent -and $MessageType -ne "Alert"){
        Set-Result -Key "NotificationResult" -Value $Result
    }
    return $Result
}

function Send-WorkspaceOneNotificationEx{
    param([string]$Message,[string]$Caption="Workspace One Notification",[string]$MessageType="YesNo")    
    $Result=-1

    If(!($Message)){
        Write-Log2 -Path $logFile -Message "WorkspaceONE.HubNotify.DotNet::No message detected. Exiting..." -Level Warn
        return
    }

    Test-HubNotifyRegistry
    Test-HubNotifyRegPermissions
    Set-ItemProperty -Path HKLM:\Software\AIRWATCH\Extensions\HubNotify\UserStorage -Name "NotificationResult" -Value "-1" -Force

    Try{
        If(Test-CurrentContext){
            Write-Log2 -Path $logFile -Message "WorkspaceONE.HubNotify.DotNet::System user detected - attempting impersonation" -Level Info
            & Invoke-CommandAsUser -mycommand "`"Send-WorkspaceOneNotification`" -Message '$Message' -Caption '$Caption' -MessageType '$MessageType' -StoreInReg" 
            If($MessageType -ne "Alert"){
                Write-Log2 -Path $logFile -Message "WorkspaceONE.HubNotify.DotNet::Waiting on registry update" -Level Info
                $Result=Get-Result -Key "NotificationResult"
            }
        } Else {
            Write-Log2 -Path $logFile -Message "WorkspaceONE.HubNotify.DotNet::Running as local user"
            $Result=Send-WorkspaceOneNotification -Message $Message -Caption $Caption -MessageType $MessageType
        }
    }Catch{
        $err=$_.Exception.Message;
        Write-Log2 -Message "An error has occured running as current user command:$err" -Path $logFile -Level Error
    }
    
    return $Result
}

#Export-ModuleMember -Function Invoke-CommandAsUser,Send-WorkspaceOneNotification,Send-WorkspaceOneNotificationEx