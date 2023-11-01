$current_path = $PSScriptRoot;
if(!$current_path){
    $current_path=Get-ItemProperty "HKLM:\Software\AIRWATCH\Extensions" | Select-Object "SharedPath" -ExpandProperty "SharedPath" -ErrorAction SilentlyContinue
}

if(!$current_path){
    Throw "An error has occured. Path not set"
}

Unblock-File "$current_path\Wso.Logging.psm1"
$module = Import-Module "$current_path\Wso.Logging.psm1" -ErrorAction Stop -PassThru -Force;
$ExportedFunctions+=$module.ExportedCommands.Keys

$CurrentModuleFileName = (Split-Path $PSCommandPath -Leaf).Replace(".psm1","").Replace(".ps1","")
$ExtensionPath="HKLM:\Software\AIRWATCH\Extensions"
#$LibPaths=Get-ModulePaths -ExtensionPath $ExtensionPath -ModulePath "WorkspaceOne" 

$CommonLogLocation="$($LibPaths.LogPath)\Wso.Cache.Log"

$CachePaths=@{"WorkspaceOneAPI"="HKLM:\Software\AIRWATCH\Extensions\WorkspaceOneAPI";
    "Default"="HKLM:\Software\AIRWATCH\Extensions\Cache";
    "Global"="HKLM:\HKLM:\Software\AIRWATCH\Extensions"
    }

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


$ScanResultDescription=@{
    [ScanResult]::WSO_API_SUCCESS="API returned{0} success.";
    [ScanResult]::WSO_API_SUCCESS_NO_CHANGE="Cache returned{0} return.  No state change was required."
    [ScanResult]::WSO_CACHE_NO_CHANGE="API returned{0}. No state change was required."
    [ScanResult]::WSO_API_FAILED="API returned{0}.  An error has occured{1}."
}

Function Add-ItemMetadata{
    param([hashtable]$Data=@{},[ScanResult]$LastScanResult=[ScanResult]::WSO_CACHE_NO_CHANGE,[string]$Action="",[string]$Error="",[int]$ExpirationHours)
    $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
    
    If(!([string]::IsNullOrWhiteSpace($Action))){ $Action = " '$Action'" } 
    If(!([string]::IsNullOrWhiteSpace($Error))){ $Error = ", '$Error'"}
    $Now=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    
    $Description=$ScanResultDescription[$LastScanResult] -f $Action, $Error
    $EntryMetadata=@{ 'LastScanResult'=$LastScanResult;
        'LastScanDescription'=$Description;
        'LastLocalScan'=$Now;}

    If($ExpirationHours -gt 0){ $EntryMetadata.Add('ExpirationHours',$ExpirationHours) }

    If($LastScanResult -in @([ScanResult]::WSO_API_SUCCESS,[ScanResult]::WSO_API_SUCCESS_NO_CHANGE)){ $EntryMetadata.Add("LastApiScan",$Now) }
    
    Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "Adding entry metadata, '$(ConvertTo-Json $EntryMetadata -Compress)'" -Level Info

    ForEach($MetadataItem in $EntryMetadata.Keys){
        If($Data.GetType().Name -eq "Hashtable"){
            If($Data.ContainsKey($MetadataItem)){ $Data[$MetadataItem]=$EntryMetadata["$MetadataItem"] }
            Else{ $Data.Add($MetadataItem, $EntryMetadata["$MetadataItem"]) }
        }
    }
    return $Data
}


Function Open-Cache{
    param([string]$Module="WorkspaceOneAPI", [string]$CacheName="")
    
    
    $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
    If([string]::IsNullOrEmpty($CacheName)){
        $CachePath=$Script:CachePaths[$Module]
    }Else{
        $CachePath="$($Script:CachePaths[$Module])\$CacheName"
    }

    Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "BEGIN OPEN CACHE '$cachePath'" -Level Debug 
    

    If(!(Test-Path -Path "$CachePath") -and (![string]::IsNullOrEmpty($CacheName))){
        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "Cache, '$CachePath' does not exist yet." -Level Info
        Try{
            $RegResults=New-Item -Path "$CachePath" -Force
            #Update-LastAccessDate -Cache "$CachePath\$CacheName"
            return "$CachePath"
        }Catch{
            $err=$_.Exception.Message
            Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "Error adding cache, '$err'" -Level Error
            return
        }
    } ElseIf(!(Test-Path -Path "$CachePath") -and ([string]::IsNullOrEmpty($CacheName))){
        Throw (New-CustomException "Module specified was not installed")
    }
    return "$CachePath"
}


Function Write-LocalCacheEntry{
    param([string]$Cache,[string]$EntryName,$Data,[switch]$EncryptData)
    $CacheObjString=ConvertTo-Json -InputObj $Data -Compress
    If($EncryptData.IsPresent){
        $CacheObjString=ConvertTo-EncryptedFile $CacheObjString
        $EntryName="$EntryName`_#"
    }
    $RegWriteResult=New-ItemProperty -Path $Cache -Name $EntryName -Value $CacheObjString -Force
    Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "END Cache entry, '$EntryName', written to Registry with value, '$(New-PrivateString $CacheObjString -Full:($EncryptData.IsPresent))', to local cache at '$(Split-Path $Cache -Leaf)'" -Level Info
    return $true
}

Function Read-LocalCacheEntry{
    param($Cache, $EntryName)
    $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
    $CurrentCacheObj=""
    Try{
        $CurrentCacheEntries=Get-ItemProperty "$Cache" -ErrorAction SilentlyContinue 

        If($CurrentCacheEntries) {
            $CurrentCacheEntries=$CurrentCacheEntries | Get-Member | Where Name -In ("$EntryName","$EntryName`_#") | Sort-Object Name -Descending
        }

        If(!($CurrentCacheEntries)) { 
            Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "REGISTRY RESULT FOR '$EntryName' was empty." -Level Debug 
            return; 
        }
        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "REGISTRY RESULT FOR '$EntryName'':`r`n`t$CurrentCacheEntries" -Level Debug 
        If(($CurrentCacheEntries | Measure).Count -gt 0){ 
            $EntryName=$CurrentCacheEntries[0].Name
            $CurrentCacheEntry=Get-ItemProperty -Path "$Cache" -ErrorAction SilentlyContinue | Select-Object $EntryName -ExpandProperty $EntryName -ErrorAction SilentlyContinue
        }

        If($EntryName.EndsWith("_#")){
            Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "REGISTRY ENTRY, '$EntryName' IS ENCRYPTED" -Level Debug 
            $CurrentCacheEntry = ConvertFrom-EncryptedFile $CurrentCacheEntry
        }
        $CurrentCacheObj=ConvertFrom-Json -InputObject $CurrentCacheEntry
    } Catch{
        $err=$_.Exception.Message
        Throw (New-CustomException "Could retrieve cache entry, '$EntryName', from cache, '$(Split-Path -Path $Cache -Leaf)' with error, $err")
    }
    return $CurrentCacheObj
}

Function Get-LocalCacheEntryProperty{
    param([string]$Module="Default",[string]$CacheName="",[string]$EntryName,[string]$Property)
    $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
    Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "BEGIN Retrieving '$Property' from entry, '$EntryName', from local cache at, '$($CacheName)]'" -Level Info  
    $Cache=Open-Cache -Module $Module -CacheName $CacheName
    If(!($Cache)) { Throw (New-CustomException "Error, unable to open cache.") }       
    $Entry=Get-LocalCacheEntry -Cache $Cache -EntryName $EntryName
    If($Entry."$Property" -ne $null){
        return $Entry."$Property"
    }
    return
}

Function Test-LocalCacheEntry{
     param([Parameter(ParameterSetName="OpenCache")]$Cache,
    [Parameter(ParameterSetName="ClosedCache")]
    [string]$Module="Default", 
    [Parameter(ParameterSetName="ClosedCache")]
    [string]$CacheName="", 
    [string]$EntryName)
    If($PSCmdlet.ParameterSetName -eq "ClosedCache"){
        $Cache=Open-Cache -Module $Module -CacheName $CacheName
        If(!($Cache)) { Throw (New-CustomException "Error, unable to open cache.") }
    }
    
    $CurrentCacheEntries=Get-ItemProperty "$Cache" -ErrorAction SilentlyContinue 

    $CurrentCacheEntry = $CurrentCacheEntries | Select "$EntryName`_#" -ExpandProperty "$EntryName`_#" -ErrorAction SilentlyContinue
    If(($CurrentCacheEntry)){
        return $true
    }

    $CurrentCacheEntry = $CurrentCacheEntries | Select "$EntryName" -ExpandProperty "$EntryName" -ErrorAction SilentlyContinue
    If(($CurrentCacheEntry)){
        return $true
    }
    return $false
}

Function Get-LocalCacheEntry{
    param([Parameter(ParameterSetName="OpenCache")]$Cache,
    [Parameter(ParameterSetName="ClosedCache")]
    [string]$Module="Default", 
    [Parameter(ParameterSetName="ClosedCache")]
    [string]$CacheName="", 
    [string]$EntryName)

    $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
    $LocalCacheEntry=""
    Try{
        $BeginLogLevel="Debug"
        If($PSCmdlet.ParameterSetName -eq "ClosedCache"){
            $BeginLogLevel="Info"
            $Cache=Open-Cache -Module $Module -CacheName $CacheName
            If(!($Cache)) { Throw (New-CustomException "Error, unable to open cache.") }
        }
        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "BEGIN Retrieving entry, '$EntryName', from local cache at, '$(Split-Path -Path $Cache -Leaf)'" -Level $BeginLogLevel 
            
        $CurrentCacheObj = Read-LocalCacheEntry -Cache $Cache -EntryName $EntryName

        If(!($CurrentCacheObj)){  
           Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "END No entry, '$EntryName', found at '$(Split-Path -Path $Cache -Leaf)'" -Level Info
           return
        }
            
        If($CurrentCacheObj.ExirationHours -and $CurrentCacheObj.ApiLastScan){
           $LastScanTime=ConvertTo-DateTime -Time $CurrentCacheObj.ApiLastScan 
            If((Get-Date).Subtract($LastScanTime.ApiLastScan).TotalHours -ge $CurrentCacheObj.ExpirationHours){
                Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "END Entry, '$EntryName', found at '$(Split-Path -Path $Cache -Leaf)', but data has expired." -Level Info
                return
            }
        }
        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "END Cache entry, '$EntryName', retrieved with data '$($CurrentCacheObj)', from local cache at '$(Split-Path -Path $Cache -Leaf)'" -Level Info
        return $CurrentCacheObj
    } Catch{
        $err=$_.Exception.Message;
        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "END An error has occured retrieving entry, '$EntryName', from local cache with Error, '$err'." -Level Error 
        Throw "END An error has occured, '$err'."
    }
    return
}

Function Update-LocalCacheEntry{
    [Alias("Set-LocalCacheEntry")]
    param([string]$Module="Default", [string]$CacheName="", [string]$EntryName, 
        [Parameter(ParameterSetName="MultiUpdate")]
        [hashtable]$Data,
        [Parameter(ParameterSetName="SingleUpdate")]
        [string]$Property,
        [Parameter(ParameterSetName="SingleUpdate")]
        [string]$Value,
        [ScanResult]$LastScanResult=[ScanResult]::WSO_API_SUCCESS,[int]$ExpirationHours=72,[switch]$EncryptData,[switch]$Force)
    $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
    $FunctionAction="Updating"
    Switch($MyInvocation.InvocationName){
        "Set-LocalCacheEntry"{
            $FunctionAction="Overwriting"
        }
    }
    Try{
        $Cache=Open-Cache -Module $Module -CacheName $CacheName
        If(!($Cache)) { Throw (New-CustomException "Error, unable to open cache.") } 
   
        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "$FunctionAction cache entry, '$EntryName' at '$CacheName'." -Level Info    
        
        $Data = Add-ItemMetadata -Data $Data -LastScanResult $LastScanResult -ExpirationHours $ExpirationHours    
        If($PSCmdlet.ParameterSetName -eq "SingleUpdate"){
            $Data=@{"$Property"="$Value"}
        }
        
        #UPDATE SECTION
        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "BEGIN Updating information in entry, '$EntryName', in local cache, '$(Split-Path -Path $Cache -Leaf)'" -Level Info 
        If($FunctionAction -eq "Updating"){
            $CurrentCacheObj=Get-LocalCacheEntry -Cache $Cache -EntryName $EntryName
        }
        
        If($CurrentCacheObj){
            ForEach($Property in $Data.Keys){
                If(($CurrentCacheObj."$Property" -eq $null) -and !([string]::IsNullOrEmpty($Data["$Property"]))){
                    Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "Adding '$Property`:$($Data["$Property"])' to Entry, '$EntryName'" -Level Debug
                    If(!($Force.IsPresent)){
                        Throw New-CustomException "Could not update cache entry" -InnerExceptionMessage  "Property, $Property, does not exist at entry, $EntryName."
                    }
                    $CurrentCacheObj | Add-Member -MemberType NoteProperty -Name $Property -Value $Data["$Property"] -ErrorAction Stop                  
                }ElseIf(($CurrentCacheObj."$Property" -ne $null) -and !([string]::IsNullOrEmpty($Data["$Property"]))){
                    If(!($EncryptData.IsPreset)){Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "Updating '$Property`:$($Data["$Property"])' to Entry, '$EntryName'" -Level Debug }        
                    $CurrentCacheObj."$Property" = $Data["$Property"]
                }Else{
                    Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "Unable to update '$Property`:$($Data["$Property"])' to Entry, '$EntryName'" -Level Debug 
                }
            }
        }Else{
            $CurrentCacheObj=$Data
        }

        $WriteResult=Write-LocalCacheEntry -Cache $Cache -EntryName $EntryName -Data $CurrentCacheObj -EncryptData:($EncryptData.IsPresent)

        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "END $FunctionAction information '$(New-PrivateString $CacheObjString -Full:($EncryptData.IsPresent))' in entry, '$EntryName', in local cache, '$(Split-Path -Path $Cache -Leaf)'" -Level Info 
        
        return $true
    } Catch {
        $err=$_.Exception.Message;   
        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "An error has occured $FunctionAction cache entry, $EntryName. $err." -Level Error
        Throw "An error has occured adding cache entry, $EntryName. $err.";
    }
    return $false
}


function ConvertTo-EncryptedFile{
    param([string]$FileContents)
    $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
    Try{
        $secured = ConvertTo-SecureString -String $FileContents -AsPlainText -Force;
        $encrypted = ConvertFrom-SecureString -SecureString $secured
    } Catch {
        $ErrorMessage = $_.Exception.Message;
        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "An error has occurrred.  Error: $ErrorMessage"
        return "Error";
    }
    return $encrypted;
}

function ConvertFrom-EncryptedFile{
    param([string]$FileContents)
    $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
    Try{
        $decrypter = ConvertTo-SecureString -String $FileContents.Trim() -ErrorAction Stop;
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($decrypter)
        $api_settings = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    } Catch {
        $ErrorMessage = $_.Exception.Message;
        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "An error has occurrred.  Error: $ErrorMessage"
        return "Error: $ErrorMessage";
    }
    return $api_settings
}

function ConvertTo-DateTime{
    param([string]$Time)
    #Accepted formats for date and time
    $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
    Try{
        $provider = [System.Globalization.CultureInfo]::InvariantCulture;
        $DateTimeConverter = [datetime]::ParseExact($Time,"yyyy-MM-dd HH:mm:ss",$provider);
        return $DateTimeConverter;
    } Catch {
        $ErrorMessage = $_.Exception.Message;
        Write-Log2 -Path $CommonLogLocation -ProcessInfo $ProcInfo -Message "An error has occured: $ErrorMessage";
    }
    return;
}

Function New-WsoCacheUnitTest{
    return [WsoCache_UTest]::New()
}

#Class for importing private methods for unit testing
class WsoCache_UTest{ 
    WsoCache_UTest(){}

    [string] ReadLocalCacheEntry([string]$Cache,[string]$Entry){
        return Read-LocalCacheEntry -Cache $Cache -EntryName $Entry
        
    }

    [string] OpenCache([string]$Module,[string]$Cache){
        return Open-Cache -Module $Module -CacheName $Cache
    }
     
    [hashtable] AddItemMetadata([hashtable]$Data=@{},[ScanResult]$LastScanResult){
        return Add-ItemMetadata -Data $Data -LastScanResult $LastScanResult     
    }


    [bool] WriteLocalCacheEntry([string]$Cache,[string]$EntryName,$Data,[bool]$EncryptData=$false){
        $WriteResult=Write-LocalCacheEntry -Cache $Cache -EntryName $EntryName -Data $Data -EncryptData:($EncryptData)
        return $WriteResult
    }
}

Export-ModuleMember -Function @("New-WsoCacheUnitTest","ConvertTo-DateTime","ConvertFrom-EncryptedFile","ConvertTo-EncryptedFile","Get-LocalCacheEntry","Get-LocalCacheEntryProperty","Update-LocalCacheEntry","Test-LocalCacheEntry") -Alias "Set-LocalCacheEntry"