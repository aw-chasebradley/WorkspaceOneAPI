#####################################################
#Prep scripts.  Run using the select script button. No need to un-comment to run.

<#
#Resets the current Powershell Environment
Invoke-Command { & "powershell.exe" } -NoNewScope # PowerShell 5
#Sets execution bypass policy
Set-ExecutionPolicy -ExecutionPolicy Bypass
#>

#####################################################
#Test Inputs - update these to match your environment
$ApiSettings=@{'Server'="https://as1506.awmdm.com";
            'Username'='bradley';
            'Password'='Ch4s3br!';
            'ApiKey'='Lx2LGBsTWs5HbZ1+Icq0qV/ubU5Zw9OsvlPfh7QQ0eE=';
            'SslThumbprint'='8F DD 6E 38 5B 37 6A 09 A6 3F F7 E7 A7 BF BC E9 F1 BA D5 21';
            'OrganizationGroupId'=10098
            }

$TagName="Firefox"
#For testing on alternative machine set to "" or comment out for testing current machine

$DeviceId=1703634
$SerialNo="VMHfEGr9MFSv"
#####################################################


$EnvironmentPath="HKLM:\Software\AIRWATCH\Extensions"

#Get current path
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    $current_path = "C:\Temp\Shared";
}

#Reset install environment
Remove-Item -Path "$EnvironmentPath" -Recurse -Force

$ModulePath = $current_path

#Preparing 
If(!(Test-Path "$ModulePath\WorkspaceOneAPI.psm1")){
    Throw "Please run script inside the WorkspaceOneAPI path"
}

Unblock-File "$ModulePath\WorkspaceOneAPI.psm1"
$RegModulePath=(Get-Item -Path "$EnvironmentPath\WorkspaceOneAPI" -ErrorAction SilentlyContinue | Select-Object InstallLocation -ExpandProperty InstallLocation -ErrorAction SilentlyContinue)
If(!(Test-Path "$EnvironmentPath\WorkspaceOneAPI") -or !($RegModulePath)){
     #Module is not installed - import to automatically install the WorkspaceOneAPI module
     $wsomodule = Import-Module "$ModulePath\WorkspaceOneAPI" -ErrorAction Stop -PassThru -Force;
}

#Always import the specific api module first before importing the general module.
#Here we are importing the tags module.
If(Test-Path "$ModulePath\Addon\Wso.API.Tags.psm1"){
    #Importing the tags module will block the WorkspaceOne API module
    Unblock-File "$ModulePath\Addon\Wso.API.Tags.psm1"
    $module = Import-Module "$ModulePath\Addon\Wso.API.Tags.psm1" -ErrorAction Stop -PassThru -Force;
    #Re-import the wso api module to gain access to all the additional functions
    $wsomodule = Import-Module "$ModulePath\WorkspaceOneAPI" -ErrorAction Stop -PassThru -Force;
}

#Set the logging level
# Debug - Most detail 
# Info - Alot of detail
# Warning - Only Errors and warnings
# Error - Only Errors
Set-WorkspaceOneLogLevel -LogLevel Info
#Sets the maximum log size
Set-WorkspaceOneMaxLogSize -MaxSizeKb 2048
#Sets the maximum number of logs per module
Set-WorkspaceOneMaxLogHistory -Value 2

Sleep -Seconds 2

New-WorkspaceOneLog -ModuleName "WorkspaceOneAPI"

echo "TESTING TEST-WORKSPACEONEAPILOCALCONFIG: $(Test-WorkspaceOneAPILocalConfig) --> CURRENTLY SHOULD BE EMPTY"
If(!(Test-WorkspaceOneAPILocalConfig)){
    echo "SAVING LOCAL CONFIG"
    $SetLocalConfig=Write-WorkspaceOneAPILocalConfig -ApiSettings $ApiSettings
    echo "LOCAL CONFIG STATUS SET $SetLocalConfig"
    echo "TESTING TEST-WORKSPACEONEAPILOCALCONFIG: $(Test-WorkspaceOneAPILocalConfig) --> SHOULD BE CONFIGURED";
} Else{
    echo "LOCAL CONFIG ALREADY SAVED"
}

Sleep -Seconds 2

If($SerialNo){
    $DeviceId=Get-CurrentWsoDeviceByAltId -DeviceSerial $SerialNo
    $RegInfo=New-ItemProperty -Path "$EnvironmentPath\WorkspaceOneAPI" -Name "SerialNumberDebug" -Value $SerialNo -Force
}

<#If($DeviceId){
    $RegInfo=New-ItemProperty -Path "$EnvironmentPath\WorkspaceOneAPI" -Name "DeviceId" -Value (ConvertTo-EncryptedFile "$DeviceId") -Force
    $RegInfo=New-ItemProperty -Path "$EnvironmentPath\WorkspaceOneAPI" -Name "LastScan" -Value $(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') -Force
}#>

Sleep 2
echo "`r`nCREATING NEW API SESSION"
        
$ApiSesssion=New-WorkspaceOneAPISession -UseLocal

Sleep 2
echo "`r`nTESTING WSO.API.Tags Module"
echo "GETTING TAGID FOR TAG FIREFOX"

$Result=Get-WSOTag -TagName "$TagName"

If(!($Result)){
    return
}

Sleep 2
echo "`r`nTESTING WSODeviceTag"

$result=Set-WSODeviceTag -TagName "$TagName" -Result $true
echo "REMOVE TAG RESULTS: $results"

Sleep 2
echo "`r`nTESTING WSODeviceTag"

$results=Set-WSODeviceTag -TagName "$TagName" -Result $false
echo "REMOVE TAG RESULTS: $results"
