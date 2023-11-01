#Using module .\WorkspaceOneApi.psm1

param([hashtable]$ApiSettings,[string]$TestDeviceSerial,$TestSection=@(),[switch]$Log)
$Module="WorkspaceOneAPI"
#
$ApiSettings=@{'Server'="https://as1506.awmdm.com";
            'Username'='bradley';
            'Password'='Ch4s3br!';
            'ApiKey'='Lx2LGBsTWs5HbZ1+Icq0qV/ubU5Zw9OsvlPfh7QQ0eE=';
            'SslThumbprint'='8F DD 6E 38 5B 37 6A 09 A6 3F F7 E7 A7 BF BC E9 F1 BA D5 21';
            'OrganizationGroupId'=10098
            }

$TestDeviceSerial="VMHfEGr9MFSv"
$TestSection=@("Get-CurrentWsoDeviceByAltId")
$ExtensionPath="HKLM:\Software\AIRWATCH\Extensions\"

$CommonLogLocation=".\WorkspaceOneAPI.Build.log"
If(!(Test-Path "$PSScriptRoot\$Module.psm1")){
    Throw "Please run script inside the WorkspaceOneAPI path"
}
Unblock-File "$PSScriptRoot\$Module.psm1"
Import-Module "$PSScriptRoot\$Module.psm1" -PassThru -ErrorAction Stop -Force

function Test-WorkspaceOneAPI.Functions{
    param([string]$LogLevel="Info",$TestSection=@(),[string]$TestDeviceSerial,[switch]$CleanInstall,[switch]$Log)
    $CurrentLogLevel=Get-ItemProperty -Path $ExtensionPath | Select "LogPath" -ExpandProperty "LogPath" -ErrorAction Stop
    If($CurrentLogLevel -ne $LogLevel){
        $RegResult=New-ItemProperty -Path $ExtensionPath -Name "LogPath" -Value $LogLevel -Force -ErrorAction Stop
    }


    
    If($CleanInstall.IsPresent){
        #Reset install environment
        Remove-Item -Path "$EnvironmentPath" -Recurse -Force
    }

    If($TestDeviceSerial){
        $RegInfo=New-ItemProperty -Path "$ExtensionPath\WorkspaceOneAPI" -Name "SerialNumberDebug" -Value $TestDeviceSerial -Force
    }

    
    $_Section="Get-CurrentWsoDeviceByAltId"
    If(($_Section -in $TestSection) -or (($TestSection | Measure).Count -eq 0)){
        $Device=Get-CurrentWsoDeviceByAltId -DeviceSerial $TestDeviceSerial
        If(!($Device)){
            Write-Log2 -Path $CommonLogLocation -Message "$_Section`: Failed" -Level Info
            return
        }
        Write-Log2 -Path $CommonLogLocation -Message "$_Section`: OK" -Level Info
        Sleep -Seconds 2
    }

    $_Section="Wso.Logging"
    If(($_Section -in $TestSection) -or (($TestSection | Measure).Count -eq 0)){
        Try{
            # Debug - Most detail 
            # Info - Alot of detail
            # Warning - Only Errors and warnings
            # Error - Only Errors
            $Function="Set-WorkspaceOneLogLevel"
            Set-WorkspaceOneLogLevel -LogLevel Info
            #Sets the maximum log size
            $Function="Set-WorkspaceOneMaxLogSize"
            Set-WorkspaceOneMaxLogSize -MaxSizeKb 2048
            #Sets the maximum number of logs per module
            $Function="Set-WorkspaceOneMaxLogHistory"
            Set-WorkspaceOneMaxLogHistory -Value 2

            Write-Log2 -Path $CommonLogLocation -Message "$_Section`: OK" -Level Info
            Sleep -Seconds 2
            }
        Catch{
            $err=$_.Exception.Message
            If($Log.IsPresent){ Write-Log2 -Path $CommonLogLocation -Message "An error has occured testing section, '$_Section': $err" -Level Error}
            Write-Log2 -Path $CommonLogLocation -Message "$_Section`.$Function`: Fail" -Level Info 
            return
        }
    }
    

    $_Section="Set-WorkspaceOneLocalConfig"
    If(($_Section -in $TestSection) -or (($TestSection | Measure).Count -eq 0)){
        Write-WorkspaceOneAPILocalConfig -ApiSettings $ApiSettings
        If(!(Test-WorkspaceOneAPILocalConfig )){
            Write-Log2 -Path $CommonLogLocation -Message "$_Section`: Fail" -Level Info 
            return
        }
        Write-Log2 -Path $CommonLogLocation -Message "$_Section`: OK" -Level Info
        Sleep -Seconds 2
    }

    $_Section="New-WorkspaceOneAPISession"
    If(($_Section -in $TestSection) -or (($TestSection | Measure).Count -eq 0)){
        Try{
            $ApiSesssion=New-WorkspaceOneAPISession -UseLocal
        }Catch{
            $err=$_.Exception.Message
            If($Log.IsPresent){ Write-Log2 -Path $CommonLogLocation -Message "An error has occured testing section, '$_Section': $err" -Level Error}
            Write-Log2 -Path $CommonLogLocation -Message "$_Section`: Fail" -Level Info 
            return
        }
        Write-Log2 -Path $CommonLogLocation -Message "$_Section`: OK" -Level Info
        Sleep -Seconds 2
    }
    
    Remove-Item $CommonLogLocation -Force -ErrorAction SilentlyContinue
    return 0
}

Test-WorkspaceOneAPI.Functions -TestSection $TestSection  -TestDeviceSerial $TestDeviceSerial
#Get-WorkspaceOneAPILookupValue -Endpoint "api/mdm/devices?searchBy=Serialnumber&id={DeviceSerial}" -SearchPattern "{DeviceSerial}" -SearchValue $TestDeviceSerial -LookupValueMap @{"{DeviceId}"="Id.Value"}
