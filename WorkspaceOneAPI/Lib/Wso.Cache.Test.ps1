#Using module .\Wso.Cache.psd1
param($TestSection=@(),[switch]$Log)
$Module="Wso.Cache"

<###################>
Enum ScanResult{
    WSO_API_SUCCESS = 0
    WSO_API_SUCCESS_NO_CHANGE = 2
    WSO_API_FAILED = -1
    WSO_API_AUTHFAILED = -2
    WSO_CACHE_NO_CHANGE = 1
    WSO_CACHE_NO_ENTRY = 11
    WSO_CACHE_EXPIRED = -10
    WSO_CACHE_ERROR = -11
};
<####################>


If(!(Test-Path "$PSScriptRoot\$Module.psm1")){
    Throw "Please run script inside the WorkspaceOneAPI path"
}
Unblock-File "$PSScriptRoot\$Module.psm1"
Import-Module "$PSScriptRoot\$Module.psm1" -PassThru -ErrorAction Stop -Force

$TestSection=@()
$ExtensionPath="HKLM:\Software\AIRWATCH\Extensions\"

$CommonLogLocation=".\Wso.Cache.Build.log"

Unblock-File "$PSScriptRoot\Wso.Logging.psm1"
Import-Module "$PSScriptRoot\Wso.Logging.psm1"

function Test-Wso.Cache.Functions{
    param([string]$LogLevel="Info",$TestSection=@(),[switch]$Log)
    $CurrentLogLevel=Get-ItemProperty -Path $ExtensionPath | Select "LogPath" -ExpandProperty "LogPath" -ErrorAction Stop

    If($CurrentLogLevel -ne $LogLevel){
        $RegResult=New-ItemProperty -Path $ExtensionPath -Name "LogPath" -Value $LogLevel -Force -ErrorAction Stop
    }

    $WsoCache_UTest=New-WsoCacheUnitTest
    $ScanResultTest=@([ScanResult]::WSO_API_FAILED,[ScanResult]::WSO_API_SUCCESS,[ScanResult]::WSO_API_SUCCESS_NO_CHANGE,[ScanResult]::WSO_CACHE_NO_CHANGE)
    $CacheModule="Default"
    $CacheName="Tags"
    $CacheEntries=@{"Firefox"=@{"Id"=27};"Chrome"=@{"Id"=84};"IE"=@{"Id"=99}}

    $_Section="Add-ItemMetadata"
    If(($_Section -in $TestSection) -or (($TestSection | Measure).Count -eq 0)){
        foreach($myScanResult in $ScanResultTest){
            
            $ReturnObject0=$WsoCache_UTest.AddItemMetadata(@{},$myScanResult)
            If($Log.IsPresent){ Write-Log2 -Path $CommonLogLocation -Message "$myScanResult $($ReturnObject0 | Out-String)" -Level Info }
            If(!($ReturnObject0.Count -and ($ReturnObject0.Count -ge 3))){
                Write-Log2 -Path $CommonLogLocation -Message "$_Section`: Failed" -Level Info
                return 1
            } 
            Sleep -Seconds 2
        }
        Write-Log2 -Path $CommonLogLocation -Message "$_Section`: OK" -Level Info   
        Sleep -Seconds 2
    }
    

    $_Section="Set-LocalCacheEntry"
    If(($_Section -in $TestSection) -or (($TestSection | Measure).Count -eq 0)){
        foreach($Tag in $CacheEntries.Keys){
            $result=Set-LocalCacheEntry -Module $CacheModule -CacheName $CacheName -EntryName $Tag -Data $CacheEntries[$Tag] -LastScanResult ([ScanResult]::WSO_API_SUCCESS)
            if(!$result){
                return 1
            }
            Sleep -Seconds 2
        }
        Write-Log2 -Path $CommonLogLocation -Message "$_Section`: OK" -Level Info
        Sleep -Seconds 2
    }

    $_Section="Read-LocalCacheEntry"
    If(($_Section -in $TestSection) -or (($TestSection | Measure).Count -eq 0)){
        $RegResult=New-ItemProperty -Path $ExtensionPath -Name "LogPath" -Value "Debug" -Force
        foreach($Tag in $CacheEntries.Keys){
            $Cache=$WsoCache_UTest.OpenCache($CacheModule,$CacheName)
            $Entry=$WsoCache_UTest.ReadLocalCacheEntry($Cache,$Tag)
            If($Log){ Write-Log2 -Path $CommonLogLocation -Message "$Tag :$($Entry | Out-String)" -Level Info }
        }
        Write-Log2 -Path $CommonLogLocation -Message "$_Section`: OK" -Level Info
        Sleep -Seconds 2
        $RegResult=New-ItemProperty -Path $ExtensionPath -Name "LogPath" -Value $CurrentLogLevel -Force
    }
    
    $_Section="Get-LocalCacheEntry"
    If(($_Section -in $TestSection) -or (($TestSection | Measure).Count -eq 0)){
        $entry=Get-LocalCacheEntry -Module $CacheModule -CacheName $CacheName -EntryName "FAKE"
        If($Log.IsPresent){ Write-Log2 -Path $CommonLogLocation -Message "$Tag : $($entry | Out-String)" -Level Info}
        Sleep -Seconds 2
        foreach($Tag in $CacheEntries.Keys){
            $entry=Get-LocalCacheEntry -Module $CacheModule -CacheName $CacheName -EntryName $Tag
            if(!($entry)){
                Write-Log2 -Path $CommonLogLocation -Message "$_Section`: Fail" -Level Info
                return 1
            }
            If($Log.IsPresent){ Write-Log2 -Path $CommonLogLocation -Message "$Tag : $($entry.Data | Out-String)" -Level Info }
            Sleep -Seconds 2
        }
        Write-Log2 -Path $CommonLogLocation -Message "$_Section`: OK" -Level Info
        Sleep -Seconds 2
    }

    $_Section="Update-LocalCacheEntry"
    If(($_Section -in $TestSection) -or (($TestSection | Measure).Count -eq 0)){
        $CacheEntries.Add("Thunderbird",@{"Id"=5;"Method"="Add"})
        Sleep -Seconds 2
        $i=0;
        foreach($Tag in $CacheEntries.Keys){
            $entry=Update-LocalCacheEntry -Module $CacheModule -CacheName $CacheName -EntryName $Tag -Data @{"Method"="Add"} -LastScanResult $ScanResultTest[$i] -Force
            if(!($entry)){
                Write-Log2 -Path $CommonLogLocation -Message "$_Section`: Fail" -Level Info
                return 1
            }
            $i++;
            If($Log.IsPresent){ Write-Log2 -Path $CommonLogLocation -Message "$Tag : $($entry.Status) " -Level Info }
            Sleep -Seconds 2
        }
        Write-Log2 -Path $CommonLogLocation -Message "$_Section`: OK" -Level Info
        Sleep -Seconds 2
    }

    If($CurrentLogLevel -ne $LogLevel){
        $RegResult=New-ItemProperty -Path $ExtensionPath -Name "LogPath" -Value $CurrentLogLevel -Force
    }
    Remove-Item $CommonLogLocation -Force -ErrorAction SilentlyContinue
    return 0;
}

Test-Wso.Cache.Functions -TestSection $TestSection -Log