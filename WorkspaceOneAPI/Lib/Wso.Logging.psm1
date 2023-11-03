<#
*
* Workpsace One Logging 
* by Chase Bradley
*
#>

$current_path = $PSScriptRoot;
$ExtensionPath="HKLM:\Software\AIRWATCH\Extensions\";
$InstallPath="HKLM:\Software\AIRWATCH\Extensions\";
if(Test-Path $InstallPath){
    $current_path = Get-ItemProperty -Path "$InstallPath" | Select-Object "SharedPath" -ExpandProperty "SharedPath" -ErrorAction SilentlyContinue 
}

$CurrentModuleFileName = (Split-Path $PSCommandPath -Leaf).Replace(".psm1","").Replace(".ps1","")

#Logging engine settings
$Script:LogSettings=New-Object -TypeName PSCustomObject -Property @{'LogLevel'=@{'Value'='';'DefaultValue'='Error'};
    'MaxLogSize'=@{'Value'='';'DefaultValue'=1024*2;'MaxValue'=2048;'MinValue'=50};
    'MaxLogHistory'=@{'Value'='';'DefaultValue'=2;'MaxValue'=30;'MinValue'=0};
    'LogFilter'="";
    }

function Get-LogProperty{
    [Alias("Get-WorkspaceOneMaxLogHistory")]
    [Alias("Get-WorkspaceOneMaxLogSize")]
    [Alias("Get-WorkspaceOneLogLevel")]
    [Alias("Get-WorkspaceOneLogFilter")]
    param([string]$PropertyName)
    $InvocationName =$MyInvocation.InvocationName
    If($InvocationName -match "Get`-WorkspaceOne(.*)"){
        If($Script:LogSettings."$($Matches[1])"){
            $PropertyName=$Matches[1]
        } 
    }

    If($Script:LogSettings."$PropertyName"){
        If($Script:LogSettings."$PropertyName"['Value']){
            return $LogSettings."$PropertyName"['Value'];
        } Else {
            $Property = Get-ItemProperty -Path $ExtensionPath | Select-Object "$PropertyName" -ExpandProperty "$PropertyName" -ErrorAction SilentlyContinue
            If($Property){
                $Script:LogSettings."$PropertyName"['Value']=$Property
                return $LogSettings."$PropertyName"['Value']
            } Else{
                return Set-LogProperty -PropertyName "$PropertyName" -Value $LogSettings."$PropertyName"['DefaultValue']
            }
        }
        $Script:LogSettings."$PropertyName"['Value']=$Script:LogSettings."$PropertyName"['DefaultValue']
        return $LogSettings."$PropertyName"['DefaultValue'];
    }   
    return 
}

function Set-LogProperty{
    [Alias("Set-WorkspaceOneMaxLogHistory")]
    [Alias("Set-WorkspaceOneMaxLogSize")]
    [Alias("Set-WorkspaceOneLogLevel")]
    [Alias("Set-WorkspaceOneLogFilter")]
    param([string]$PropertyName, 
        [Parameter(ParameterSetName="General")]
        [string]$Value,
        [Parameter(ParameterSetName="LogLevel")]
        [string]$LogLevel,
        [Parameter(ParameterSetName="MaxSizeKb")]
        [int]$MaxSizeKb
    )
    $InvocationName =$MyInvocation.InvocationName
    If($InvocationName -match "Set`-WorkspaceOne(.*)"){
        If($Script:LogSettings."$($Matches[1])"){
            $PropertyName=$Matches[1]
        } 
    }

    If($Script:LogSettings."$PropertyName" -eq $null){
        Throw "Log Property, '$PropertyName' name does not exists."
    }

    Switch($PSCmdlet.ParameterSetName){
        "LogLevel" { $Value = $LogLevel }
        "MaxSizeKb" { $Value = $MaxSizeKb }
    }
    
    switch($PropertyName){
        "MaxLogHistory" {
            If($Value -gt 30){ $Value=30 }
            ElseIf($Value -lt 0){ $Value=0 }
        }
        "MaxLogSize" {
            If($Value -gt 2048){ $Value=2048 }
            ElseIf($Value -lt 50){ $Value=50 }
        }"LogLevel" {
            If($Value -notin @("Error","Warn","Info","Debug")){
                Throw "Requested log level is not valid."
            }
        }
    }

    $InstallPath="HKLM:\Software\AIRWATCH\Extensions\";
    $SettingValue = Set-ItemProperty -Path $InstallPath -Name $PropertyName -Value $Value -Force
    $Script:LogSettings."$PropertyName"['Value']=$Value
    return $LogSettings."$PropertyName"['Value'] 
}

<#
.SYNOPSIS
This function obfuscates a string intended for logging
.DESCRIPTION
#>  
function New-PrivateString{
    param([string]$InputString,[switch]$Partial,[switch]$Full
    )
    $PrivateStringSymbol="*************"
    If($Full.IsPresent){
            return $PrivateStringSymbol
    }
    If($Partial.IsPresent){
        If( $InputString.Length -gt 5){
                return ($InputString.Substring(0,5) + $PrivateStringSymbol)
        } 
        return $PrivateStringSymbol
    }

    return $InputString
}


$logLocation = "C:\Temp\Logs\UtilitiesLogs.log";
$securityLogLocation = "C:\Temp\Logs\SecurityAudit.log";

function Write-Log2
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        [string]$Path,

         [Parameter(Mandatory=$false)]
        [Alias('LogPosition')]
        [string]$ProcessInfo,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info","Debug")]
        [string]$Level="Info",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoClobber,

        [Parameter(Mandatory=$false)]
        [switch]$FromClass
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process
    {
        If($ProcessInfo){
            $Message="$ProcessInfo $Message";
        }

        $Local:LogLevelSet=@{"Debug"=@("Error","Warn","Info","Debug");"Info"=@("Error","Warn","Info");"Warn"=@("Warn","Error");"Error"=@("Error")}
        $CurrentLocalLogLevel=Get-LogProperty -PropertyName "LogLevel"
        #If the LogLevel is below the 
        If($Local:LogLevelSet[$CurrentLocalLogLevel] -notcontains $Level){
            return;
        }

        If(!([string]::IsNullOrEmpty($Script:LogSettings.LogFilter))){
            If($Message -notlike $Script:LogSettings.LogFilter){
                return;
            }
        }

        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
            }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
            }

        else {
            # Nothing to see here yet.
            }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                If($FromClass){
                    $Host.UI.WriteErrorLine("ERROR:`t$Message")
                    $Host.UI.WriteErrorLine($MyInvocation.PositionMessage);
                }
                Write-Error $Message
                $LevelText = 'ERROR:'
                }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
                }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
                } 
            'Debug' {
                Write-Host -ForegroundColor White -Object "DEBUG:`t$Message" | Out-Null
                #$Host.UI.WriteDebugLine("$Message")
                $LevelText = 'DEBUG:'
                }   
            }


        $LogFile = (Get-ChildItem $Path)
        # Check log file size
        $LogSize = ($LogFile).Length/1KB
        

        $MaxLogSize=Get-LogProperty("MaxLogSize")
        If($LogSize -gt $MaxLogSize){
            $StartNewLogResults=Start-NewLogFile -LogPath $Path     
        }
        
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }

}

function Remove-WorkspaceOneLogs{
    [Namespace("WorkspaceOneLogging")]
    $DefaultLogPath=(Get-ItemProperty $ExtensionPath  -ErrorAction SilentlyContinue | Select-Object "LogPath" -ExpandProperty "LogPath" -ErrorAction SilentlyContinue)
    If(!(Test-Path $DefaultLogPath)){
        Throw "An error has occured, 'unable to determine the default log path'"
    }
    
    $AllLogFiles=Get-ChildItem $DefaultLogPath -Filter "*.log"
    ForEach($LogFile in $AllLogFiles){
        Remove-Item $LogFile.FullName -Force
    }
}

Function Start-NewLogFile{
    param([string]$LogPath)
    If(!(Test-Path $LogPath)){
        #No log ful exists, exit with success
        return $true
    }
    $IsDebug=($Script:LogSettings.LogLevel["Value"] -eq "Debug")
    $LogFile = (Get-ChildItem $LogPath)
    $TempLogPath="$($LogFile.DirectoryName)\Wso.Logging.psm1"
    $FileName = $LogFile.BaseName
    $LogCount=(Get-ChildItem -Path ($LogFile.DirectoryName)  -Filter "$FileName*" | Measure).Count 
    $MaxLogCount=Get-WorkspaceOneMaxLogHistory
    If($IsDebug){ Write-Host -ForegroundColor White -Object "$LogCount logs found.  Max number of logs is $MaxLogCount" | Out-Null }
    ForEach($FileItem in (Get-ChildItem -Path $LogFile.DirectoryName -Filter "$FileName*" | Sort-Object -Property LastWriteTime)){
        If($LogCount -gt $MaxLogCount){
            If($IsDebug){ Write-Host -ForegroundColor White -Object "Log count exceded.  Deleting $($FileItem.FullName)" | Out-Null }
            $RemoveResult=Remove-Item -Path $FileItem.FullName -Force
        } Else{
            If($IsDebug){ Write-Host -ForegroundColor White -Object "Moving $($FileItem.FullName) to $($LogFile.FullName.Replace(".log","$($LogCount-1).log"))" | Out-Null }
            $MoveResults=Move-Item -Path $FileItem.FullName -Destination "$($LogFile.FullName.Replace(".log","$($LogCount-1).log"))" -Force
        }
        $LogCount--;
    }
    return $true
}


function New-WorkspaceOneLog{
    param($ModuleName)
    $DefaultLogPath=(Get-ItemProperty $ExtensionPath  -ErrorAction SilentlyContinue | Select-Object "LogPath" -ExpandProperty "LogPath" -ErrorAction SilentlyContinue)
    If(!(Test-Path $DefaultLogPath)){
        Throw "An error has occured, 'unable to determine the default log path'"
    }
    If([string]::IsNullOrEmpty($ModuleName) -or ($ModuleName -eq "*" )){
        $AllBaseLogFiles=Get-ChildItem $DefaultLogPath | Where Name -NotMatch "(.*)[0-9]{1,3}`.log"
        ForEach($LogFile in $AllBaseLogFiles){
            Start-NewLogFile -LogPath $LogFile.FullName
        }
    } Else{
        Start-NewLogFile -LogPath "$DefaultLogPath\$ModuleName.log"
    }
}

  
Function Get-LogPos {
    [Alias("GetLogPos")]
    param([string]$FileName,[string]$ClassName,[string]$FunctionName,[string]$SourceName="") 
    
    If($ClassName){
        $FileName = "$ClassName"
    }
    If($SourceName){
        $SourceName="$SourceName->"
    }
    return " ({0}) {3}[{1}::{2}] " -f ([Random]::new().Next(999)), $FileName, $FunctionName, $SourceName;
}


Function Get-ModulePaths{
    param ([string]$ExtensionPath="$InstallPath",[string]$ModuleName="WorkspaceOneAPI",[string]$CurrentPath,[switch]$WritePath)
    $LibPaths=@(@{'Path'=$ExtensionPath;'Settings'= @{'SharedPath'="$CurrentPath\Lib"; 'LogPath'="$CurrentPath\Logs"; 'LogLevel'="Error"}}; 
          @{'Path'="$ExtensionPath\$ModuleName";'Settings'=@{'InstallLocation'=$CurrentPath;'Version'=$CurrentVersion;}})
     #This will grab the folderlocations from the registry if available - otherwise will create the new registry key
    #In previous iterations the registry keys had to be created by the installer.  This allows for the files to 
    #stand alone for easier distribution
    $SettingsCopy=@{}
    ForEach($Registry in $LibPaths){
        $RegPath=$Registry['Path']
        $Settings=$Registry['Settings']
        ForEach($SettingItem in $Settings.Keys){
            $RegSetting=Get-ItemProperty -Path $RegPath | Select-Object "$SettingItem" -ExpandProperty "$SettingItem" -ErrorAction SilentlyContinue
            If($RegSetting){      
                $SettingsCopy.Add($SettingItem,$RegSetting)
            } Else {
                If($WritePath){
                    $RegResults=New-ItemProperty -Path $RegPath -Name $SettingItem -Value $Settings["$SettingItem"] -Force
                    $SettingsCopy.Add($SettingItem,$Settings["$SettingItem"])
                }
            }
        }
    }
    $LibPaths=New-Object -Type PSCustomObject -Property $SettingsCopy
     
    return $LibPaths
}

$ExportModule = @("Write-Log2", "Get-LogPos", "Get-ModulePaths", "New-PrivateString","Set-LogProperty","Get-LogProperty","Start-NewLogFile","New-WorkspaceOneLog","Remove-WorkspaceOneLogs")
$ExportAlias = @("Set-WorkspaceOneLogLevel","Set-WorkspaceOneLogFilter","Set-WorkspaceOneMaxLogSize","Set-WorkspaceOneMaxLogHistory")
$ExportAlias += @("Get-WorkspaceOneLogLevel","Get-WorkspaceOneLogFilter","Get-WorkspaceOneMaxLogSize","Get-WorkspaceOneMaxLogHistory")
$ExportAlias += @("GetLogPos")


Export-ModuleMember -Function $ExportModule -Alias $ExportAlias

