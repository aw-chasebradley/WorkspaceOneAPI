<############################################
# File: SetupEx.ps1
# Version: 2.0
# Author: Chase Bradley
# Modified by: Phil Helmling 08 Aug 2019, add onUnlock Task Triggers condition for Create-Task - references "TriggerType":"onUnlock" in setup.manifest
# Setup Shared Device Module

Change Log
2.0
General Fixes
* Added significant logging overhaul
* More effecicient code
* Fixed an issue where modules were not storing to a set registry key 
* Added a more dynamic way to gather current directory
* Added a way to call parameters from the console
New Parameters
* Added -UseLogLevel which supports Error, Warn and Info, with Error only showing critical Errors and Info showing a Verbose `11
* Added -Force, when switched on will overwrite the existing files/tasks/registry entries even if they already exist 
Scheduled Tasks
* Added the ability to use a command as well as a file for Scheduled tasks
* Fixed an issue where tasks would auto-start even when told not to

############################################>
param([Parameter(Mandatory=$false)]
      [ValidateSet("Error","Warn","Info")]
      [string]$UseLogLevel="Info",
      [switch]$Force
)

$Global:UseLogLevel = $UseLogLevel;
#Test to see if we are running from the script or if we are running from the ISE

$current_path = $PSScriptRoot;
if($current_path -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $envriontment_dir = [System.Environment]::CurrentDirectory;
    If($envriontment_dir.EndsWith(".ps1")){
        $current_path=Split-Path -Path $envriontment_dir
    }
} 
$setup_manifest=""
<#if($current_path -eq ""){
    $current_path="C:\Users\cbradley.DESKTOP-USB51NK\Desktop\ElevateUserPrivileges_Alpha_0.1"
}#>

if(Test-Path "$current_path\setup.manifest"){
    $setup_manifest_file = [IO.File]::ReadAllText($current_path + "\setup.manifest");
    $setup_manifest = ConvertFrom-Json -InputObject $setup_manifest_file -ErrorAction Continue;
    if(!($setup_manifest)){
        Throw "An error has occured, loading setup.manifest."
    }
    $INSTALL_FILES = $true;
}


$LOG_BREAK="`r`n`t`t`t`t`t"

$Global:LogLocation="$current_path\Setup.log"
echo "NEW INSTALLATION STARTING" > $LogLocation;
$AccessPolicyPath = "";


function Write-Log2{ #Wrapper function to made code easier to read;
    [CmdletBinding()]
    Param
    (
        [string]$Message,
        [string]$Path=$logLocation,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Success","Error","Warn","Info")]
        [string]$Level="Info",
        [switch]$UseLocal
    )
    $LogLevels=@{"Error"=1;"Warn"=2;"Info"=3}
    $GlobalLogLevel = "Info"
    If($Global:UseLogLevel){
        $GlobalLogLevel = $Global:UseLogLevel;
    }
    If($LogLevels[$Level] -gt $LogLevels[$GlobalLogLevel]){
        return
    }
    $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
    $FontColor = "White";
    If($ColorMap.ContainsKey($Level)){
        $FontColor = $ColorMap[$Level];
    }
    $DateNow = (Date).ToString("yyyy-mm-dd hh:mm:ss");
    Add-Content -Path $Path -Value ("$DateNow     ($Level)     $Message")
    Write-Host "$Level`t$Message" -ForegroundColor $FontColor;
}

function Test-ItemProperty{
    Param([string]$Path, [string]$Name)
    return (Get-Item -Path $Path).GetValue($Name) -ne $null;
}

function Create-AccessList{
    param([string]$ModuleRegPath="HKLM:\SOFTWARE\AirWatch\ProductProvisioning",
         [string]$InstallPath="C:\Temp\Shared",
         [array]$AccessUsers=@(),
         [array]$AccessRules=@(),
         [int]$SecurityLevel=0,
         [bool]$TestInstall=$false
         )
    $installListDefaults = New-Object -TypeName PSCustomObject -Property @{"Name"="Install";"Type"="Install";"Paths"=@();"RegKeys"=@()};
    $historyListDefaults = New-Object -TypeName PSCustomObject -Property @{"Name"="History";"Type"="History";"Paths"=@();"RegKeys"=@()};
    $systemListDefaults = New-Object -TypeName PSCustomObject -Property @{"Name"="System";"Type"="System";"Paths"=@();"RegKeys"=@()};
    $accessProperties = @{"SecurityLevel"=$SecurityLevel;"BlockList"=@($installListDefaults;$systemListDefaults);"AllowList"=@();"HistoryList"=@($historyListDefaults)};
    If($AccessUsers){
        $accessProperties.Add("AccessUsers",$AccessUsers);
    } ElseIf ($AccessRules){
        $accessProperties.Add("AccessRules",$AccessRules);
    } Else {
        $DefaultAccessLogic0 = New-Object -TypeName PSCustomObject -Property @{"Group"="Users";"Rule"= "IN"}
        $DefaultAccessLogic1 = New-Object -TypeName PSCustomObject -Property @{"User"="Administrator";"Rule"= "NOTIN"}
        $DefaultAccessProperties = @{"AccessLogic"=@($DefaultAccessLogic0,$DefaultAccessLogic1)};
        $AccessRules = @($DefaultAccessProperties);
        $accessProperties.Add("AccessRules",$AccessRules);
    }
    $accesspolicies = New-Object -TypeName PSCustomObject -Property $accessProperties;

    $convertedJson = ConvertTo-Json $accesspolicies -Depth 10;
    Set-Content "$InstallPath\accesspolicies.access" $convertedJson -WhatIf:$TestInstall;

    $AccessPolicyPath = "$InstallPath\accesspolicies.access"

    #If($InstallAccessPolicy){
    New-ItemProperty -Path $ModuleRegPath -Name "AccessPolicy" -Value "$InstallPath\accesspolicies.access" -Force -WhatIf:$TestInstall;
    return $accesspolicies;
}

Function Get-InstallerPath{
    param([string]$Path, $Dictionary)

    If($Path -match "\`$([^\\]*)"){
        $Lookup = $Matches[1];
        If($Dictionary.ContainsKey($Lookup)){
            $Path = $Path.Replace($Matches[0],$Dictionary[$Lookup]);
        }
    }
    return $Path;
}

function Add-AccessPolicyItems{
    param([string]$RegPath,
          [string]$AccessPolicyName,
          [array]$Paths=@(),
          [array]$RegKeys=@(),
          [bool]$TestInstall=$false
    )

    $AccessPolicyFile =  Get-ItemPropertyValue -Path $RegPath -Name "AccessPolicy";  
    If(Test-Path -Path $AccessPolicyFile){
        $RawData = [IO.File]::ReadAllText($AccessPolicyFile);
        $accesspolicies = ConvertFrom-Json -InputObject $RawData;
    } 

    $Policy = $accesspolicies.BlockList | where Name -eq $AccessPolicyName;
    If(($Policy | measure).Count -eq 0){
        $Policy = New-Object -TypeName PSCustomObject -Property @{"Name"="$AccessPolicyName";"Type"="System";"Paths"=@();"RegKeys"=@()};
        $accesspolicies.BlockList += $newAccessPolicy;
    }
    $Policy.Paths += $Paths;
    $Policy.RegKeys += $RegKeys;

    $convertedJson = ConvertTo-Json $accesspolicies -Depth 10;
    Set-Content $AccessPolicyFile $convertedJson -WhatIf:$TestInstall;
}

Function Invoke-HidePaths{
    param($HidePaths,$PathDictionary)

    ForEach($HidePath in $HidePaths){   
        Get-InstallerPath -Path $HidePaths -Dictionary $PathDictionary                    
        If((Test-Path $HidePath)){
            $f=get-item $HidePath -Force
            $f.attributes="Hidden"
        }
    }
}

Function Create-Paths{
    param([string]$Path, $Folders, [bool]$TestInstall)
    $Folders = @();
    $Folders += $Folders;

    $CreatePath = $Path;
    If($CreatePath -match "\`$([^\\]*)"){
    $CreatePath = $CreatePath.Replace($Matches[0],$PathInfo[$Matches[1]]);
    }
    If($ManifestItem."$ManifestAction".Folder){
        $CreatePath = $CreatePath + "\" + $ManifestItem."$ManifestAction".Folder;
        New-Item -Path $CreatePath -ItemType Directory -Force -WhatIf:$TestInstall
    } ElseIf($ManifestItem."$ManifestAction".Folders){
        ForEach($Folder In $ManifestItem."$ManifestAction".Folders){
            $NewPath = $CreatePath + "\" + $Folder;
            New-Item -Path $NewPath -ItemType Directory -Force -WhatIf:$TestInstall
        }
    }
}

function Create-Task{
    Param([string]$TaskPath, [string]$TaskName, [string]$PShellScript, [string]$PSCommand, [string]$Interval, [string]$TriggerType,[bool]$AutoStart=$true,[bool]$TestInstall,[string]$Arguments)
    Try{
        If($PShellScript){
            $Item="File"
            $Command=$PShellScript
        }ElseIf($PScommand){
            $Item="Command"
            $Command=$PSCommand
        }

        #Validate job does not exist
        
        $arg = '-ExecutionPolicy Bypass -' + $Item + ' "' + $Command + '"'
        If($Arguments -ne ""){
            $arg=$arg + " $Arguments"
        }
        $A = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe" -Argument $arg 
        Write-Log2 -Message "WorkspaceOneExtensions::Setup::Task is setup with:$LOG_BREAK`C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe $arg" -Path $Global:LogLocation -Level Info  
        
        If($TriggerType -eq "onUnlock"){
            #Add Windows Unlock trigger
            $stateChangeTriggerClass = Get-CimClass -Namespace ROOT\Microsoft\Windows\TaskScheduler -ClassName MSFT_TaskSessionStateChangeTrigger
            $onUnlockTrigger = New-CimInstance  -CimClass $stateChangeTriggerClass -Property @{ StateChange = 8 } -ClientOnly

            $logonTrigger = $(New-ScheduledTaskTrigger -AtLogOn)
            $T = @(
                            $logonTrigger,
                            $onUnlockTrigger
                        )
        } Else {
			$T = New-ScheduledTaskTrigger -AtLogon
		}
        $P = New-ScheduledTaskPrincipal "System" -RunLevel Highest
        $S = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -StartWhenAvailable -Priority 5
        $S.CimInstanceProperties['MultipleInstances'].Value=3
        If($TriggerType -eq "None") {
            $D = New-ScheduledTask -Action $A -Principal $P -Settings $S
        } Else{
            $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S
        }        

        $MyTask=Register-ScheduledTask -InputObject $D -TaskName "$TaskName" -TaskPath "$TaskPath" -Force -ErrorAction Stop
        Write-Log2 -Message "WorkspaceOneExtensions::Setup::Scheduled task, $TaskName, created.  Details:$LOG_BREAK $MyTask" -Path $Global:LogLocation -Level Info  

        If($Interval){
            $Task = Get-ScheduledTask -TaskName "$TaskName" -TaskPath "$TaskPath";
            $Task.Triggers[0].Repetition.Interval = $Interval;
            $Task.Triggers[0].Repetition.StopAtDurationEnd = $false;         
            $Task | Set-ScheduledTask -User "NT AUTHORITY\SYSTEM";
        }

    } Catch {
        $err = $_.Exception.Message;
        Write-Log2 -Message "WorkspaceOneExtensions::Setup::Error creating task, $TaskName - $err" -Path $Global:LogLocation -Level Error 
    }

    If($AutoStart){
        Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath;
        Write-Log2 -Message "WorkspaceOneExtensions::Setup::Starting scheduled task $TaskName" -Path $Global:LogLocation -Level Info  
    }
}

Function Invoke-Installation{
        Param([object]$MyModule,[bool]$TestInstall=$false,[bool]$Install=$true)
        $InstallAccessPolicy = $false;
        $ModuleName = $MyModule.Name;
        Write-Log2 -Message "WorkspaceOneExtensions::Setup::Starting installation for module: $ModuleName" -Path $Global:LogLocation -Level Info

        $DefaultLogLocation="C:\Temp\Logs"
        If($MyModule.LogLocation){
            $DefaultLogLocation=$MyModule.LogLocation
            Write-Log2 -Message "WorkspaceOneExtensions::Setup::Log location detected in manifest.  Using: $DefaultLogLocation" -Path $Global:LogLocation -Level Info
        }

        $BaseModuleRegPath = "HKLM:\Software\AirWatch\Extensions";
        
        $ModuleRegPath = "$BaseModuleRegPath\$ModuleName";
        If($ModuleName -in @("Shared","GlobalSettings")){
            $ModuleRegPath = $BaseModuleRegPath
        }
        
        $ModuleInstallPath = $MyModule.InstallLocation;
        $ModuleSecurityLevel = $MyModule.SecureInstall;

        $Currentversion = $MyModule.Version;
        If(!$CurrentVersion -and $MyModule.PrimaryModule){
            If(Test-Path "$current_path`\$($MyModule.PrimaryModule).psd1"){
                
                $ModulePath="$current_path`\$($MyModule.PrimaryModule).psd1"
                $Output=Import-LocalizedData -BaseDirectory ($ModulePath | Split-Path -Parent) -FileName ($ModulePath | Split-Path -Leaf) -BindingVariable PrimaryModuleImport
                If($PrimaryModuleImport.ModuleVersion){
                    $Currentversion=$PrimaryModuleImport.ModuleVersion.ToString()
                }
            }
        }
        $ModuleVersionKey = "InstalledVersion"
        If(Test-Path $ModuleRegPath){
                Write-Log2 -Message "WorkspaceOneExtensions::Setup::Existing install detected.  Checking version." -Path $Global:LogLocation -Level Info
                $Previousversion = Get-ItemProperty -Path $ModuleRegPath | Select-Object "$ModuleVersionKey" -ExpandProperty "$ModuleVersionKey" -ErrorAction SilentlyContinue
                Write-Log2 -Message "WorkspaceOneExtensions::Setup::Current installed version is: $Previousversion." -Path $Global:LogLocation -Level Info
                
                If([System.Version]$Previousversion -ge [System.Version]$Currentversion){
                    Write-Log2 -Message "WorkspaceOneExtensions::Setup::$Previousversion is greater to or equal than the current version." -Path $Global:LogLocation -Level Warn                                               
                    If(!($Force.IsPresent)){
                        Write-Log2 -Message "WorkspaceOneExtensions::Setup::-Force flag not detected. Continuing..." -Path $Global:LogLocation -Level Warn   
                        #continue; 
                    }
                }
           
        } Else {
            #Create the new module reg path
            Write-Log2 -Message "WorkspaceOneExtensions::Setup::No install detected creating new path: $ModuleRegPath." -Path $Global:LogLocation -Level Info
            $RegPath=New-Item -Path $ModuleRegPath -Force -WhatIf:$TestInstall;
        }

        $PathInfoString = ""
        $PathInfo = @{};
        $PropertyPaths = $MyModule.PSObject.Properties | where TypeNameOfValue -EQ "System.String";
        ForEach($PPath in $PropertyPaths){
            $PathInfo.Add($PPath.Name, $PPath.Value);
            $PathInfoString += "(" + $PPath.Name + ";" + $PPath.Value + ")";
        }
        $i=0
        ForEach($ManifestItem in $MyModule.Manifest){
            $ManifestAction = $ManifestItem.PSObject.Properties.Name 
            Write-Log2 -Message "WorkspaceOneExtensions::Setup::......................$ModuleName SETUP STEP $i - $ManifestAction....................." -Path $Global:LogLocation -Level Info
           
            If($ManifestAction -eq "CopyFiles" -or $ManifestAction -eq "MoveFiles"){
                $CopyDestination = $ManifestItem."$ManifestAction".Destination;
                $CopyDestination = Get-InstallerPath -Path $CopyDestination -Dictionary $PathInfo
                
                If(!(Test-Path -Path $CopyDestination)){
                    $CopyDir=New-Item -Path $CopyDestination -ItemType Directory -Force -WhatIf:$TestInstall;
                }
                If ($ManifestItem."$ManifestAction".From){
                    $FromFiles = (Get-ChildItem -Path $ManifestItem."$ManifestAction".From -Force | Select-Object FullName).FullName
                } ElseIf ($ManifestItem."$ManifestAction".Files) {
                    $FromFiles = $ManifestItem."$ManifestAction".Files;
                }

                ForEach($InstallFile In $FromFiles){
                    $FileNameDetails=$InstallFile | Split-Path -Leaf
                    $FilePathDetails=$InstallFile | Split-Path
                    If($ManifestAction -Like "CopyFiles"){
                        Try{                            
                            Copy-Item -Path $InstallFile $CopyDestination -Force -WhatIf:$TestInstall;
                            Write-Log2 -Message "WorkspaceOneExtensions::Setup::COPYING FILE: $FileNameDetails $LOG_BREAK`FROM: $FilePathDetails``$LOG_BREAK`TO: $CopyDestination" -Path $Global:LogLocation -Level Info
                        } Catch {
                            $err = $_.Exception.Message
                            Write-Log2 -Message "WorkspaceOneExtensions::Setup::An error has occured COPYING file $InstallFile from $FromFiles to $CopyDestination`:`n`e$err" -Path $Global:LogLocation -Level Info
                        }
                    } ElseIf($ManifestAction -Like "MoveFiles"){
                        Try{
                            Move-Item -Path $InstallFile $CopyDestination -Force -WhatIf:$TestInstall;
                            Write-Log2 -Message "WorkspaceOneExtensions::Setup::MOVING FILE: $FileNameDetails $LOG_BREAK`FROM: $FilePathDetails``$LOG_BREAK`TO: $CopyDestination" -Path $Global:LogLocation -Level Info
                        } Catch {
                            $err = $_.Exception.Message
                            Write-Log2 -Message "WorkspaceOneExtensions::Setup::An error has occured MOVING file $InstallFile from $FromFiles to $CopyDestination`:`n`e$err" -Path $Global:LogLocation -Level Info
                        }
                    }
                } 
            } ElseIf ($ManifestAction -eq "DeleteFiles"){
                ForEach($Delete In $ManifestItem."$ManifestAction"){
                    $DeleteFormatted = Get-InstallerPath -Path $DeleteFormatted -Dictionary $PathInfo
                    Remove-Item -Path $Delete -Force -WhatIf:$TestInstall;
                }
            } ElseIf ($ManifestAction -eq "CreateAccessFile"){
                $AccessInstallLocation = $ManifestItem."$ManifestAction".Location,
                $AccessInstallLocation = Get-InstallerPath -Path $AccessInstallLocation -Dictionary $PathInfo

                $UserList = $ManifestItem."$ManifestAction".UserList;
                $SecurityLevel = $ManifestItem."$ManifestAction".SecurityLevel;

                $AccessRules = $ManifestItem."$ManifestAction".AccessRules;

                $InstallAccessPolicy = Create-AccessList -ModuleRegPath $ModuleRegPath -InstallPath $MyModule.InstallLocation -AccessRules $AccessRules -SecurityLevel $SecurityLevel -AccessUsers $UserList -TestInstall $TestInstall;
            } ElseIf ($ManifestAction -eq "CreatePath" -or $ManifestAction -eq "CreatePaths"){
                 $CreatePath = $ManifestItem."$ManifestAction".Path;
                 If($ManifestItem."$ManifestAction".Folder){
                    $CreateFolders = $ManifestItem."$ManifestAction".Folder;
                 } ElseIf($ManifestItem."$ManifestAction".Folders){
                    $CreateFolders = $ManifestItem."$ManifestAction".Folders;
                 }
                  Create-Paths -Path $CreatePath -Folders $CreateFolders -TestInstall $TestInstall;                               
            } ElseIf ($ManifestAction -eq "CreateRegKeys"){
                $RegKeyPath = $ModuleRegPath
                If($ManifestItem."ManifestAction".Path){
                    $RegKeyPath = $ManifestItem."ManifestAction".Path
                    $RegKeyPath = Get-InstallerPath -Path $RegKeyPath -Dictionary $PathInfo
                }
                If(!(Test-Path $RegKeyPath)){ 
                    Try{                  
                        $MyNewItem=New-Item -Path $RegKeyPath -Force -WhatIf:$TestInstall;
                        Write-Log2 -Message "WorkspaceOneExtensions::Setup::Registry key, $RegKeyPath, has been successfully created." -Path $Global:LogLocation -Level Info 
                    }Catch{
                        $err=$_.Exception.Message;
                        Write-Log2 -Message "WorkspaceOneExtensions::Setup::An error has occured creating registry key, $RegKeyPath`: $err." -Path $Global:LogLocation -Level Error 
                    }
                }
                ForEach($RegKey In $ManifestItem."$ManifestAction".Keys){
                    $KeyName = ($RegKey.PSObject.Properties | Select Name).Name;                                     
                    $KeyValue = $RegKey."$KeyName";
                    $KeyValue = Get-InstallerPath -Path $KeyValue -Dictionary $PathInfo
                    If($ManifestItem."ManifestAction".Path){
                        $RegKeyPath = $ManifestItem."ManifestAction".Path
                        $RegKeyPath = Get-InstallerPath -Path $RegKeyPath -Dictionary $PathInfo
                    }
                    Try{
                        $MyNewItem=New-ItemProperty -Path $RegKeyPath -Name $KeyName -Value $KeyValue -Force -WhatIf:$TestInstall;
                        Write-Log2 -Message "WorkspaceOneExtensions::Setup::Registry key item, $KeyName at $RegKeyPath, has been successfully set to $KeyValue." -Path $Global:LogLocation -Level Info
                    } Catch{
                        $err=$_.Exception.Message;
                        Write-Log2 -Message "WorkspaceOneExtensions::Setup::An error has occured creating registry key item, $RegKeyPath`: $err." -Path $Global:LogLocation -Level Error
                    }
                }
            } ElseIf ($ManifestAction -eq "CreateTask"){
                $TaskName = $ManifestItem."$ManifestAction".Name;
                $TaskPath = $ManifestItem."$ManifestAction".Path;
                If(!$TaskPath){
                    $TaskPath = "\AirWatch MDM\";
                }
                Write-Log2 -Message "WorkspaceOneExtensions::Setup::Creating task $TaskName at path $TaskPath." -Path $Global:LogLocation -Level Info
                $PowerShellFile = Get-InstallerPath -Path $ManifestItem."$ManifestAction".PSFile -Dictionary $PathInfo;
                $PowerShellCommand = Get-InstallerPath -Path $ManifestItem."$ManifestAction".PSCommand -Dictionary $PathInfo;
                If($Install){
                    
                    $TaskInterval = $ManifestItem."$ManifestAction".TaskInterval;
                    $AutoStart = $ManifestItem."$ManifestAction".AutoStart;
                    
                    # always create tasks with -AtLogon trigger, however you can add triggers by updating the Create-Task function. On Windows Unlock ("onUnlock") is now supported.
                    $TriggerType = $ManifestItem."$ManifestAction".TriggerType;
                    $Arguments = $ManifestItem."$ManifestAction".Argument;
                    
                    
                    Try{
                        Create-Task -TaskName $TaskName -TaskPath $TaskPath -PShellScript $PowerShellFile -PSCommand $PowerShellCommand -Interval $TaskInterval -Trigger $TriggerType -AutoStart $AutoStart -TestInstall $TestInstall -Arguments $Arguments;                                 
                    } Catch {
                        $err=$_.Exception.Message
                        Write-Log2 -Message "WorkspaceOneExtensions::Setup::An error has occured, $err" -Path $Global:LogLocation -Level Error  
                    }
                } 
            } ElseIf ($ManifestAction -eq "AccessRule"){
                $AccessPolicyPath =  Get-ItemPropertyValue -Path $ModuleRegPath -Name "AccessPolicy";
                $ManifestPaths = @();
                $ManifestRegKeys = @();
                If($ManifestItem."$ManifestAction".Paths){
                    $Paths = $ManifestItem."$ManifestAction".Paths | % {(Get-InstallerPath -Path $_ -Dictionary $PathInfo)}
                    $ManifestPaths += $ManifestItem."$ManifestAction".Paths;
                }
                If($ManifestItem."$ManifestAction".RegKeys){
                    $ManifestRegKeys += $ManifestItem."$ManifestAction".RegKeys;
                }
                Add-AccessPolicyItems -RegPath $ModuleRegPath -AccessPolicyName "System" -Paths $ManifestPaths -RegKeys $ManifestRegKeys;
            } ElseIf($ManifestAction -eq "HidePaths"){
                $HidePaths = @();
                If($ManifestItem."$ManifestAction".Paths){
                    $HidePaths += $ManifestItem."$ManifestAction".Paths;
                    Invoke-HidePaths -HidePaths $HidePaths -PathDictionary $PathInfo;
                }
            }
            $i=$i+1
        }
        If($CurrentVersion){
            $NewModuleName=New-ItemProperty -Path $ModuleRegPath -Name "InstalledVersion" -Value $Currentversion -Force -WhatIf:$TestInstall;
        }
        If($ModuleInstallPath){
            $NewModuleVersion=New-ItemProperty -Path $ModuleRegPath -Name "InstallLocation" -Value $ModuleInstallPath -Force -WhatIf:$TestInstall;
        }

        $NewModuleName="$NewModuleName".Replace(";","$LOG_BREAK")
        $NewModuleVersion="$NewModuleVersion".Replace(";","$LOG_BREAK")

        Write-Log2 -Message "WorkspaceOneExtensions::Setup::Registry keys written: $NewModuleName, $NewModuleVersion" -Path $Global:LogLocation -Level Info

        $CurrentlyInstalled=Get-ItemProperty -Path $BaseModuleRegPath | Select-Object "CurrentlyInstalled" -ExpandProperty "CurrentlyInstalled" -ErrorAction SilentlyContinue
        If($CurrentlyInstalled){
            $CurrentlyInstalledList=$CurrentlyInstalled.Split(";")
            If($CurrentlyInstalledList -notcontains $ModuleName){
               $CurrentlyInstalled = $CurrentlyInstalled + ";$ModuleName" 
            }
        } Else{
            $CurrentlyInstalled = $ModuleName
        }
        $CurrentlyInstalledDetails=New-ItemProperty -Path $BaseModuleRegPath -Name "CurrentlyInstalled" -Value $CurrentlyInstalled -Force -WhatIf:$TestInstall;

        #Add-AccessPolicyItems -RegPath $ModuleRegPath -AccessPolicyName "Install" -Paths @($ModuleInstallPath) -RegKeys @($ModuleRegPath) -TestInstall $TestInstall;
        Write-Log2 -Message "WorkspaceOneExtensions::Setup::........................COMPLETED MODULE: $ModuleName........................." -Path $Global:LogLocation -Level Info
    }


cd $current_path;

If($INSTALL_FILES){ 
    ForEach($MyModule in $setup_manifest.Modules){
        Invoke-Installation $MyModule;
    }
}
