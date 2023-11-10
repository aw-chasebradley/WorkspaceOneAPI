<############################################
# File: Uninstall.ps1
# Version: 0.5
# Author: Chase Bradley
# Modified by: Phil Helmling 08 Aug 2019, add onUnlock Task Triggers condition for Create-Task - references "TriggerType":"onUnlock" in setup.manifest
# Setup Shared Device Module

Change Log
2.0
General Fixes
* Fixed to point at correct registry
New Parameters
* 

############################################>

$InstallPath = "HKLM:\Software\AIRWATCH\Extensions";
$shared_path = "C:\Temp\Shared"
$LogPath = "C:\Temp\Logs";
$InstallPathDirs = @();

If(Test-Path $InstallPath){
    $shared_path = Get-ItemProperty -Path $InstallPath | Select-Object "SharedPath" -ExpandProperty "SharedPath" -ErrorAction SilentlyContinue
    $log_path = Get-ItemProperty -Path $InstallPath | Select-Object "LogPath" -ExpandProperty "LogPath" -ErrorAction SilentlyContinue
    $currently_installed=Get-ItemProperty -Path $InstallPath | Select-Object "CurrentlyInstalled" -ExpandProperty "CurrentlyInstalled" -ErrorAction SilentlyContinue
}
$InstallPathDirs += $LogPath;

####GET RIGHTS BACK FIRST####
If(Test-Path "$shared_path\accesspolicies.access"){
    $RawData = [IO.File]::ReadAllText("$shared_path\accesspolicies.access");
    $Access = ConvertFrom-Json -InputObject $RawData;

    $DefaultAccessLogic1 = New-Object -TypeName PSCustomObject -Property @{"User"="Administrator";"Rule"= "NOTIN"}
    $DefaultAccessProperties = @{"AccessLogic"=@($DefaultAccessLogic0,$DefaultAccessLogic1)};
    $AccessRules = @($DefaultAccessProperties);
    $Access.AccessRules = @()
    $Access.AccessRules += $AccessRules;

    $AccessJson = ConvertTo-Json -InputObject $Access -Depth 10;
    Set-Content -Path "$shared_path\accesspolicies.access" -Value $AccessJson

    If((Get-ScheduledTask | where {$_.TaskName -eq "Apply_AccessPolicies" -and 
            $_.TaskPath -eq "\AirWatch MDM\"} | measure).Count -gt 0){
        Start-ScheduledTask -TaskName "Apply_AccessPolicies" -TaskPath "\AirWatch MDM\";
    }

}

$RegKeys=@()
$currently_installed_list=$currently_installed.Split(";")
ForEach($module in $currently_installed_list){
    $ModulePath="$InstallPath"
    If($module -notin @("Shared","GlobalSettings")){
        $ModulePath="$InstallPath\$module"
        $InstalledPath=""
        If(Test-Path $ModulePath){
            $InstalledPath=Get-ItemProperty -Path $ModulePath | Select-Object "InstallLocation" -ExpandProperty "InstallLocation" -ErrorAction SilentlyContinue
            If((Test-Path $InstalledPath) -and ($InstalledPath -notlike "*Modules*")){
               $InstallPathDirs += $InstalledPath
               Remove-Item -Path $InstalledPath -Recurse -Force;
           
            }        
            If($module -ne "Shared","GlobalSettings"){
                $RegKeys += $ModulePath
            }
            Remove-Item -Path "$ModulePath" -Recurse -Force;
        }
    }
}

$Tasks = (Get-ScheduledTask) | where {$_.TaskPath -eq "\AirWatch MDM\"}
ForEach($Task in $Tasks){
    Unregister-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -Confirm:$false
}

#Remove-Item -Path $InstallPath -Force -Recurse