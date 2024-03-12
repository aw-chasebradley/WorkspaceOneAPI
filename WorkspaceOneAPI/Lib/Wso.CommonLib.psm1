$ExtensionPath="HKLM:\Software\AIRWATCH\Extensions"

$current_path = $PSScriptRoot;
if(!($current_path)){
    $current_path=Get-ItemProperty "$ExtensionPath" | Select-Object "SharedPath" -ExpandProperty "SharedPath" -ErrorAction SilentlyContinue
}

if(!($current_path)){
    Throw "An error has occured. Path not set"
}

$RootPath=Split-Path $current_path -Parent

$CommonFiles=@("Wso.Logging.psm1","Wso.Cache.psm1", "Wso.Windows.Users.psm1","Wso.WebLib.psm1")
$ExportedFunctions=@()
$ExportedAlias=@()
#Import Libraries and Functions
foreach($File in $CommonFiles){
    Unblock-File "$current_path\$File"
    $module = Import-Module "$current_path\$File" -ErrorAction Stop -PassThru -Force;
    $ExportedFunctions+=$module.ExportedCommands.Keys
    $ExportedAlias+=$module.ExportedAliases.Keys
}

$LibPaths=Get-ModulePaths -ExtensionPath $ExtensionPath -ModulePath "WorkspaceOne" -CurrentPath $RootPath -WritePath
$CurrentModuleFileName = (Split-Path $PSCommandPath -Leaf).Replace(".psm1","").Replace(".ps1","")

$CommonLogLocation="$($LibPaths.LogPath)\Wso.Common.Log"

<#
.AUTHOR
cbradley@vmware.com
.SYNOPSIS
Creates a new PSCustomObject for cleaner syntax
.DESCRIPTION

.OUTPUTS
Returns a custom PS object that has the following attributes
    Username - user1
    Domain - domain.com
    FullName - domain.com\user1 or user1@domain.com
#>
Function New-DynamicObject{
    param(
        [Hashtable]$Properties,
        [Hashtable]$Reserved
    )
    $Object = New-Object -TypeName PSCustomObject
    foreach($Name in $Properties.Keys){
        $Value = $Properties[$Name];
        if($Value.GetType().BaseType.Name -eq "Array" -or
                $Value.GetType().Name -eq "Hashtable"){
            $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value;
        }
        elseif($Value -ne $null){
            $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value;
        }
    }
    if($Reserved.Count -gt 0){
        foreach($Name in $Reserved.Keys){
             $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Reserved[$Name];
        }
    }
    return $Object;
}

Set-Alias -Name NewObj -Value New-DynamicObject

function ConvertTo-Hashtable{
    param([PSCustomObject]$Object)
    $Attributes=($Object | Get-Member -MemberType NoteProperty | Select Name).Name
    $HashTable=@{}
    foreach($Property in $Attributes){
        $HashTable.Add($Property, $Object."$Property") | Out-Null
    }
    return $HashTable
}

<#
.AUTHOR
cbradley@vmware.com
.SYNOPSIS
Gets the serial number of the current machine
.DESCRIPTION
Provides a standardized way to retrieve the serial number on the machine
.OUTPUTS
Returns string 
#>
function Get-DeviceSerial{
     Begin{
        $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "BEGIN Getting local device SerialNumber." -Level Debug
     }Process{
        $SerialNumReg=Get-ItemProperty -Path $ExtensionPath -ErrorAction SilentlyContinue | Select "SerialNumberDebug" -ExpandProperty "SerialNumberDebug" -ErrorAction SilentlyContinue
        If(!([string]::IsNullOrEmpty($SerialNumReg))){
            return $SerialNumReg
        }

        $serialSearch = wmic bios get serialnumber;
        $myserialnumber = $serialSearch[2];
        $myserialnumber = $myserialnumber.Trim();
        Try {
            Add-Type -AssemblyName System.Web
            $myserialnumber = [System.Web.HttpUtility]::UrlEncode($myserialnumber);
        } Catch{
            $err=$_.Exception.Message;
            Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "PROCESS An error has occured using the System.Web.HttpUtility module in .NET to format the serial number`r`n$err" -Level Error
            return; 
        }
        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "END Local device serial number is, '$myserialnumber'." -Level Debug
        return $myserialnumber
    }
}

<#
.AUTHOR
cbradley@vmware.com
.SYNOPSIS
Gets the currently logged in Windows User
.DESCRIPTION
Provides two different built in methods for getting the currently logged in user.  The standard method uses Get-WMIObject to determine
the logged in user.  This method is not compatible with users using remote log in.  In order to allow for remote log in support,
you will need to copy the GetWin32User.cs file into the current directory or include it as part of the installation process.
.OUTPUTS
Returns a custom PS object that has the following attributes
    Username - user1
    Domain - domain.com
    FullName - domain.com\user1 or user1@domain.com
#>
function Get-CurrentLoggedonUser{
    #Check to see if GetWin32User.cs exists at the current location
    If(Test-Path "$current_path\GetWin32User.cs"){
        Try{
            Unblock-File "$current_path\GetWin32User.cs"
            if (-not ([Management.Automation.PSTypeName]'AWDeviceInventory.QueryUser').Type) {
                        [string[]]$ReferencedAssemblies = 'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
                        Add-Type -Path "$current_path\GetWin32User.cs" -ReferencedAssemblies $ReferencedAssemblies -IgnoreWarnings -ErrorAction 'Stop'
            }
            $usernameLookup = [AWDeviceInventory.QueryUser]::GetUserSessionInfo("$env:ComputerName");
            $usernameLookup = $usernameLookup | where {$_.IsCurrentSession} | select @{N='Username';E={$_.NTAccount}};
        } Catch {
            
        }
    } 
    #If Username lookup has not been processed, use Get-WMIOBject to return the user.
    If(!($usernameLookup)){
        $usernameLookup = Get-WMIObject -class Win32_ComputerSystem | select username;
    }
    if($usernameLookup){
        $usernameLookup = $usernameLookup.username;
    }
    #Uses regex
    if($usernameLookup -match "([^\\]*)\\(.*)"){
        $usernameProp = @{"Username"=$Matches[2];"Domain"=$Matches[1];"FullName"=$Matches[0]}
        $usernameLookup = New-Object -TypeName PSCustomObject -Property $usernameProp;
    } elseif($usernameLookup -match "([^@]*)@(.*)"){
        $usernameProp = @{"Username"=$Matches[1];"Domain"=$Matches[2];"Fullname"=$Matches[0]}
        $usernameLookup = New-Object -TypeName PSCustomObject -Property $usernameProp;
    }         
    return $usernameLookup;
}


<#
.SYNOPSIS
This function encodes the credentials for use with REST APIs
.DESCRIPTION
#> 
function New-BasicAuthCredentials{
    param($Username, $Password)
    Begin{
       $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
       Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "BEGIN Encoding credentials for Basic Auth" -Level Info
    }Process{
        Try{
            $UTFEncoded=[System.Text.Encoding]::UTF8.GetBytes("$Username`:$Password");
            $AuthString=[System.Convert]::ToBase64String($UTFEncoded)
            #Special method for obfuscating the credentials
            $PrivateAuthString=New-PrivateString -InputString $AuthString -Partial
            Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "END Username and password successfully encoded, 'Basic $PrivateAuthString'" -Level Info
            return "Basic $AuthString"
        } Catch{
            $err=$_.Excepton.Message;
            Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "END An error has occured using the .NET module, System.Text.Encoding to encode the username and password`r`n$err" -Level Error
            return;
        }
        return;
    }
}

class WorkspaceOneCustomException: System.Exception{
    WorkspaceOneCustomException([string]$Message,[string]$InnerExceptionMessage):
        base ("WorkspaceOne Custom Exception: $Message",[System.Exception]::new($InnerExceptionMessage)) {}
}

function New-CustomException{
    param([string]$Message, [string]$InnerExceptionMessage)
    if([string]::IsNullOrEmpty($InnerExceptionMessage)) { $InnerExceptionMessage = $Message } 
    return [WorkspaceOneCustomException]::new($Message, $InnerExceptionMessage)
}

$ExportedFunctions+=@("New-DynamicObject","Get-DeviceSerial","Get-CurrentLoggedOnUser","New-BasicAuthCredentials","New-CustomException","ConvertTo-Hashtable")
$ExportedAlias+=@("NewObj")

Export-ModuleMember -Function $ExportedFunctions -Alias $ExportedAlias