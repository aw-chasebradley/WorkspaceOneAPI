<# 
.SYNOPSIS
    WorkspaceOneAPI Library
.DESCRIPTION 
    A long description of how the script works and how to use it.
#>

#Module metadata info
$CurrentModuleFileName = (Split-Path $PSCommandPath -Leaf).Replace(".psm1","").Replace(".ps1","")
$ModuleName="$CurrentModuleFileName"

#Registry
$ExtensionPath = "HKLM:\Software\AIRWATCH\Extensions";
$ApiPath = "$ExtensionPath\WorkspaceOneAPI";
$InstallPath="$ExtensionPath\$ModuleName";

echo "Using this module"

#Import the Workspace ONE API module
$WorkspaceOneModulePath = Get-ItemProperty -Path $ApiPath -ErrorAction SilentlyContinue | Select-Object "InstallLocation" -ExpandProperty "InstallLocation" -ErrorAction SilentlyContinue
If(!($WorkspaceOneModulePath)){  Throw "The WorkspaceONEAPI Module is not installed or path was not available.  Module not loaded." }

Unblock-File "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1";
$WSOModule=Import-Module "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1" -ErrorAction Stop -PassThru -Force;

If(!(Test-Path $InstallPath)){ 
    $RegResult=New-Item -Path $InstallPath -Force; 
    $RegResult=New-ItemProperty -Path $InstallPath -Name "InstallLocation" -Value "$PSScriptRoot" -Force 
}

#Setting up Log Location
$logLocation="$($LibPaths.LogPath)\$ModuleName.log"
#ModuleFileName


Enum ScanResult{
    WSO_API_SUCCESS = 0
    WSO_API_SUCCESS_NO_CHANGE = 2
    WSO_API_FAILED = -1
    WSO_API_AUTHFAILED = -2
    WSO_CACHE_NO_CHANGE = 10
    WSO_CACHE_NO_ENTRY = 11
    WSO_CACHE_EXPIRED = -10
    WSO_CACHE_ERROR = -11
};


<#
    .SYNOPSIS
    Returns the ID of the Tag from Workspace One API

    .DESCRIPTION
    Uses the Workspace ONE API Endpoint to search for a specific tag
    GET 'api/mdm/tags/search' 

    .PARAMETER TagName
    (Required) [String] Name of the tag in the Workspace ONE UEM console

    .PARAMETER ApiSettings
    (Optional) [Hashtable]  Api configuration in Hashtable formate.  If no configuration 
    object is specified the function will attempt to use the locally stored configuration.

    .OUTPUTS
    Returns the TagId in integer form
    Will return empty if no tag was found matching the search 
#>

Function Get-WSOTag{   
    param([string]$TagName, [hashtable]$ApiSettings)
    Begin{
        $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
        Write-Log2 -Path $logLocation -ProcessInfo $ProcInfo -Message "BEGIN Get Tag, '$TagName', from WorkspaceOne API." -Level Info     
    } Process{
        Write-Log2 -Path $logLocation -ProcessInfo $ProcInfo -Message "BEGIN Searching for tag, '$TagName'." -Level Info  
        #Api endpoint     
        $TagSearchEndpoint = "api/mdm/tags/search?organizationgroupid={OrganizationGroupId}&name=";   
        $TagsJson = Invoke-WorkspaceOneAPICommand -Endpoint ("$TagSearchEndpoint" + $TagName) -UseLocal:(!($ApiSettings))

        #Verify results
        If(($TagsJson.Tags | where TagName -eq $TagName | measure).Count -gt 0){
            $TagId = ($TagsJson.Tags | where TagName -eq $TagName)[0].Id.Value;
            Write-Log2 -Path $logLocation -Message "END Tag, '$TagName', found with Id, '$TagId'" -Level Info
        } Else{
            Write-Log2 -Path $logLocation -Message "END Tag, '$TagName', not found or API request failed." -Level Warn   
        }
        return $TagId
    }
}


<#
    .SYNOPSIS
    Creates a new Tag using the Tag Name specified at the DefaultLocationGroup
    specified in the 

    .DESCRIPTION
    Creates a new Tag using the Tag Name specified.
    API: POST 'api/mdm/tags/addtag'
    
    .PARAMETER TagName
    (Reqired) [String] Name of the tag to be created in the console.  

    .PARAMETER ApiSettings
    (Optional) [Hashtable]  Api configuration in Hashtable formate.  If no configuration 
    object is specified the function will attempt to use the locally stored configuration.
    
    .OUTPUT
    Returns the TagId in integer form.
    Will return empty if no tag was created.
#>

Function Add-WSOTag{
    param([string]$TagName,[hashtable]$ApiSettings)
     Begin{
        $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
        Write-Log2 -Path $logLocation -Message "$LOGPOS++" -Level Info     
    } Process{
        $BodyTemplate = @"
{
    "TagAvatar":"{tagname}",
    "TagName": "{tagname}",
    "TagType": 1,
    "LocationGroupId": {OrganizationGroupId}
}
"@
        $CurrentTime=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Write-Log2 -Path $logLocation -ProcessInfo $ProcInfo -Message "Adding tag, $TagName to the WorkspaceOne UEM Console." -Level Info

        $BodyData = $BodyTemplate.Replace("{tagname}", $TagName);
        $AddTag = Invoke-WorkspaceOneAPICommand -Method Post -Endpoint "api/mdm/tags/addtag" -Headers $Headers -Data $BodyData -UseLocal:(!($ApiSettings));
           
        If($AddTag.Value){
            $TagId = $AddTag.Value;
            Write-Log2 -Path $logLocation -ProcessInfo $ProcId -Message "Tag, $TagName, added successfully. TagId is $TagId." -Level Info
        } Else{
            $Response=$AddTag.Content;
            If($AddTag.StatusCode -eq 400){
                $Response = $Response + "  Tag with name, $TagName may already exists."
            }
            rite-Log2 -Path $logLocation -ProcessInfo $ProcId -Message "$Tag Id failed to add for Tag, $TagName.  Response is:`r`n`t$Response" -Level Warn
            return;
        }
        return $TagId
    
    }
}

 <#
    .SYNOPSIS
    Updates the tag status on a device.  Uses an alias to determine which update function to run.
    Alias Add-WSODeviceTag will add a device while Remove-WSODeviceTag will remove the tag.

    .DESCRIPTION
    Adds or Removes a tag to a device (or set of devices) using the Tag id specified. 
    API: POST 'api/mdm/tags/{tagid}/adddevices'
    API: POST 'api/mdm/tags/{tagid}/removedevices'

    .PARAMETER TagId
    (Required) [int] Id of the tag to add

    .PARAMETER ApiSettings
    (Optional) [Hashtable]  Api configuration in Hashtable formate.  If no configuration 
    object is specified the function will attempt to use the locally stored configuration.

    .OUTPUT
    Returns the results of the Post operation
#>

Function Update-WSODeviceTag{
   
    [Alias("Add-WSODeviceTag")]
    [Alias("Remove-WSODeviceTag")]
    param($TagId, [hashtable]$ApiSettings)
    
    
    Switch($MyInvocation.InvocationName){
        "Add-WSODeviceTag"{
            $TagDeviceEndpoint = "api/mdm/tags/$TagId/adddevices";
            $Action="Add"
        }
        "Remove-WSODeviceTag"{
            $TagDeviceEndpoint = "api/mdm/tags/$TagId/removedevices";
            $Action="Remove"
        }
        default{
            return;
        }
    }
       
    $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand
    Write-Log2 -Path $logLocation -ProcessInfo $ProcInfo -Message "BEGIN Making call to WorkspaceONE API to $Action tag with Id, '$TagId' to local device." -Level Info   
    $BodyTemplate = @"
{
"BulkValues": {
"Value": [
    {DeviceId}
]
}
}
"@       
    $BodyData=$BodyTemplate;      
    $DeviceTagsResults = Invoke-WorkspaceOneAPICommand -Method "POST" -Endpoint $TagDeviceEndpoint -Data $BodyData -UseLocal:(!($ApiSettings));

    $CurrentTime=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    
    If($DeviceTagsResults.StatusCode -eq 400){
        Write-Log2 -Path $logLocation -ProcessInfo $ProcId -Message "END Tag Id did not exist.  Probable cache sync issue." -Level Error
        return [ScanResult]::WSO_API_FAILED
    } ElseIf($DeviceTagsResults.TotalItems){
        Write-Log2 -Path $logLocation -ProcessInfo $ProcId -Message "END $($Action) tag results: `r`n $DeviceTagsResults." -Level Debug
        If($DeviceTagsResults.AcceptedItems -eq 1){
            return [ScanResult]::WSO_API_SUCCESS;
        } elseif ($DeviceTagsResults.FailedItems -eq 1 -and 
            $DeviceTagsResults.Faults.Fault[0].ErrorCode -eq 400){
            return [ScanResult]::WSO_API_SUCCESS_NO_CHANGE;
        }
    } 
    return [ScanResult]::WSO_API_FailED
}


<#
@TODO 
#>
Function Get-CurrentWsoDeviceTags{
    

}

<#
    .SYNOPSIS
    Logic for adding/removing a tag on device.  Allows an on device method for adding/removing tags,
    based on device status.
    
    .DESCRIPTION
    Will either add or remove a tag based on the Result provided to the commandlet.  Uses a local
    cache mechanism to ensure that the function does not call the API every time it is run.  It will
    only call the APIs if the Result changes from the previous attempt.  It is designed to run
    on a loop or within a scheduled sensor/task, to monitor the result of a test on the local machine.
    
    .PARAMETER TagName
    (Required) [String] Required name of the tag that will be added/removed from the device
    
    .PARAMETER Result
    (Required) [Boolean] 

    .PARAMETER ApiSettings
    (Optional) [Hashtable]  Api configuration in Hashtable formate.  If no configuration 
    object is specified the function will attempt to use the locally stored configuration.
    
    .PARAMETER CreateTag
    (Optional) [Switch] If -CreateTag is added to the Commandlet at runtime, the function
    will create a new tag if no tag is found matching the name of the specified tag

    .PARAMETER IsStatic
    (Optional) [Switch] If -IsStatic is specified, the command will add the tag but not 
    remove it dynamically.

    .OUTPUT
    Returns the results of the Post operation
#>

Function Set-WSODeviceTag{
    
    param([string]$TagName, [bool]$Result,[hashtable]$ApiSettings,[switch]$CreateTag, [switch]$IsStatic, [switch]$DisableCache, [switch]$EncryptCache)
        $ProcInfo=GetLogPos -FileName $FileName -FunctionName $MyInvocation.MyCommand
        Write-Log2 -Path $logLocation -ProcessInfo $ProcInfo -Message "BEGIN Evaluating local device tag, '$TagName' for result, '$Result'" -Level Info

        $Test= $PSItem | Select-Object *

        $CurrentTime=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

        $TagId=""       
        $TagStatus="NA"
        $TagStatusCacheName="TagStatus"
        $TagIdCacheName="TagIds"
        $TagCacheEntry=""
        #Try to get the TagId from the  from the LocalCache
        If(!$DisableLocalCache){
            #$TagIdEntry=Get-LocalCacheEntryProperty -Module "$ModuleName" -CacheName "$TagIdCacheName" -EntryName $TagName -Property "Id"
            $TagCacheEntry=Get-LocalCacheEntry -CacheName "$TagStatusCacheName" -EntryName $TagName
            If($TagCacheEntry){
                $TagId=$TagCacheEntry.Id
            }
        }

        #Not using local cache entry
        If(!$TagId){
            If(!($TagId)){ 
                $TagId=Get-WSOTag -TagName $TagName -ApiSettings $ApiSettings
            }
            If(!$TagId -and $CreateTag) {               
            #Add tag
                $TagId=Add-WSOTag -TagName $TagName -ApiSettings $ApiSettings
            }

            If(!$DisableCache){ Update-LocalCacheEntry -CacheName "$TagStatusCacheName" -EntryName $TagName -Data @{"Id"=$TagId;} -LastScanResult WSO_API_SUCCESS -Force }
        }

        #Throw an error if we still don't have the TagId
        If(!$TagId){
            Throw "Unable to retrieve TagId";
        }

        $ScanResult=""
        #Result is True
        $NewCacheEntryMethod=""
        $TagUpdateStatus=[ScanResult]::WSO_CACHE_NO_CHANGE;
        If($Result -eq $true){
            $NewCacheEntryMethod="AddTag"
            If(($TagCacheEntry.Method -ne "AddTag") -or (0 -gt $TagCacheEntry.LastScanResult -ge 10)){
                $TagUpdateStatus=Add-WSODeviceTag -TagId $TagId -ApiSettings $ApiSettings
            }                                       
        } ElseIf($Result -eq $false -and !($IsStatic)){                      
            $NewCacheEntryMethod="RemoveTag"
            If(($TagCacheEntry.Method -ne "RemoveTag") -or (0 -gt $TagCacheEntry.LastScanResult -ge 10)){
                $TagUpdateStatus=Remove-WSODeviceTag -TagId $TagId -ApiSettings $ApiSettings                             
            }
        }
        Update-LocalCacheEntry  -CacheName "$TagStatusCacheName" -EntryName $TagName -Data @{"Method"="$NewCacheEntryMethod"} -LastScanResult $TagUpdateStatus -Force 
        return $myResult
}

$ExportedFunctions = @("Set-WSODeviceTag", "Add-WSOTag", "Get-WSOTag")
Export-ModuleMember -Function $ExportedFunctions 