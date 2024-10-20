﻿<# 
.SYNOPSIS
    WorkspaceOneAPI Library
.DESCRIPTION 
    WorkspaceOneAPI Library for administrative and client-side use.  Extends functionality of WorkspaceONE UEM by allowing 
    admins to run local scripts and make API calls.
.AUTHOR
    cbradley@vmware.com
#>

#Get current path
$current_path = $PSScriptRoot;
If(!($current_path)){ Throw "An Error has occurred, unabled to determine current path" }

#Module metadata info
$ModuleName="WorkspaceOneAPI"
$BuildDate="240214"
$BuildVersion=0
$CurrentVersion="$BuildDate.$BuildVersion"

#Set common folder locations
$ExtensionPath = "HKLM:\Software\AIRWATCH\Extensions" 
$ModuleInstallPath = "$ExtensionPath\$ModuleName";

#Test for module installation.  Allows for stand-alone library deployment. 
If(!(Test-Path "$ModuleInstallPath")){
    $RegResults=New-Item -Path $ModuleInstallPath -Force
}

$regSharedPath=$WorkspaceOneModulePath = Get-ItemProperty -Path $ExtensionPath -ErrorAction SilentlyContinue | Select-Object "SharedPath" -ExpandProperty "SharedPath" -ErrorAction SilentlyContinue
If(!($regSharedPath)){ $sharedPath = "$current_path\Lib" }
Else { $sharedPath=$regSharedPath }

#Get common library items.
Unblock-File "$sharedPath\Wso.CommonLib.psm1"
$module = Import-Module "$sharedPath\Wso.CommonLib.psm1" -ErrorAction Stop -PassThru -Force;

$ProcInfo=GetLogPos -FileName $Global:FileName -FunctionName "LoadLibrary" 

#Gets the different paths needed
$LibPaths=Get-ModulePaths -ExtensionPath $ExtensionPath -ModuleName $ModuleName -CurrentPath $current_path -WritePath
#Global variables needed for use with object
$Script:WSOLogLocation=$LibPaths.'LogPath' + "\WorkspaceOneAPI.log"
$Script:FileName = (Split-Path $PSCommandPath -Leaf).Replace(".psm1","").Replace(".ps1","")

$TLSVersion=""

#Removed TLS1.3 stub as it is currently incompatible with native WebRequest library

#Attempts to set the default TLS version for connection to TLS 1.2
If(!($TLSVersion)){
    Try {
        If( [System.Net.ServicePointManager]::SecurityProtocol -ne [System.Net.SecurityProtocolType]::Tls12){ 
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            Write-Log2 -Path $WSOLogLocation -ProcessInfo $ProcInfo -Message "TLS 1.2 has been successfully enabled." -Level Info
        }
    } Catch {
        $err=$_.Exception.Message;
        Write-Log2 -Path $WSOLogLocation -ProcessInfo $ProcInfo -Message "An error has occurred enabling Tls1.2: $err`r`nExiting..." -Level Error
        return
    }
}

<#
.SYNOPSIS
    WorkspaceOneApiConfigTest Object for creating a new API config
.DESCRIPTION
    Currently only used to store and format settings and is not intended for external use
#>
class WorkspaceOneApiConfig{ 
    $AuthType
    $CertificateSearch
    $BasicAuthCreds
    $OauthConfig

    $Server
    $ApiKey
    $SslThumbprint
    $OrganizationGroupId
    WorkspaceOneApiConfig([Hashtable]$ApiSettings){
        $ProcInfo=GetLogPos -FileName $Script:Filename -ClassName ($this.GetType().Name) -FunctionName "Initialization"        

        If(!$ApiSettings.ContainsKey('AuthType')){
            $this.AuthType="Basic"
        }ElseIf($ApiSettings['AuthType'] -in @('Basic','Certificate','Oauth','OauthCertificate')){
            $This.AuthType=$ApiSettings['AuthType']
        }Else{
            Throw "An error has occured configuring authentication for WorkspaceOneAPI"
        }

        If($ApiSettings.ContainsKey('Oauth')){
            $this.OauthConfig=$ApiSettings['OauthConfig']
        }

        If($this.AuthType -eq "Basic"){
            #Handles how auth is setup and automatically encodes Username and Password for basic auth
            If(($ApiSettings.ContainsKey('Username')) -and $ApiSettings.ContainsKey('Password')){
                $this.BasicAuthCreds=New-BasicAuthCredentials -UserName $ApiSettings['Username'] -Password $ApiSettings['Password']
            } ElseIf($ApiSettings['BasicAuth']) {
                $this.BasicAuthCreds=$ApiSettings['BasicAuth']
            }
        } Else{ 

            If($this.AuthType -in @("Certificate","OauthCertificate")){
                If($ApiSettings.ContainsKey('CertificateSearch')){
                    $this.CertificateSearch=$ApiSettings['CertificateSearch']
                }Else{
                    Throw "An error has occured.  No certificate was specified."
                }
            }  
        
            If($this.AuthType -in @("Oauth","OauthCertificate")){
                If($ApiSettings.ContainsKey('OauthConfig')){
                    $this.OauthConfig=$ApiSettings['OauthConfig']
                }Else{
                    Throw "An error has occured.  No certificate was specified."
                }
            }
        }


        #
        $this.Server=$ApiSettings['Server']
        $this.ApiKey=$ApiSettings['ApiKey']
        $this.SslThumbprint=$ApiSettings['SslThumbprint']

        #Format SSL thumbprint
        $this.SslThumbprint=$this.SslThumbprint.ToString().Replace(" ","").ToLower()
        $this.OrganizationGroupId=$ApiSettings['OrganizationGroupId']   
    }
}


<#START WorkspaceOneAPISession class definition
.SYNOPSIS
    WorkspaceOneApiSession class for creating connections to a Workspace One API service
.DESCRIPTION
    Contains all function and logic for generating API commands
#>
class WorkspaceOneApiSession{
    $Config
    $DeviceId="-1"
    $LookupValues
    $Log="$Script:WSOLogLocation"
    $Filename="$Script:Filename"
    $InstallPath = "HKLM:\Software\AIRWATCH\Extensions\WorkspaceOneAPI"; 

    WorkspaceOneApiSession([Hashtable]$ApiSettings){
        $ProcInfo=GetLogPos -FileName $this.Filename -ClassName ($this.GetType().Name) -FunctionName "Initialization"
        $this.Config=[WorkspaceOneApiConfig]::new($ApiSettings);
        $DeviceInfo=Get-LocalCacheEntry -Module "WorkspaceOneAPI" -EntryName "DeviceId"
        $this.LookupValues=@{"{DeviceUdid}"=-1;"{DeviceId}"=-1;"{OrganizationGroupId}"=-1;"{OrganizationGroupUdid}"=-1}
        $this.LookupValues["{DeviceUuid}"]=$DeviceInfo.Uuid
        $this.LookupValues["{DeviceId}"]=$DeviceInfo.Id
        $this.LookupValues["{OrganizationGroupId}"]=$this.Config.OrganizationGroupId
    }

    static [PSCustomObject]InvokeWorkspaceOneAPICommand([hashtable]$ApiSettings,[string]$Endpoint, $Method, $ApiVersion=1,  $Data=""){
        $ProcInfo=GetLogPos -FileName $Script:Filename -FunctionName "WorkspaceOneRestCommand"        
        $ApiSession=[WorkspaceOneApiSession]::new($ApiSettings);
        $MyResults=$ApiSession.GetResponse($Endpoint, $ApiVersion, $Method, $Data)
        $ApiSession.Config=$null
        $ApiSession=$null
        return $MyResults
    }

    <#
    .SYNOPSIS
    This function creates a new session object using a hashtable
    .DESCRIPTION
    #> 
    static [WorkspaceOneApiSession]CreateNewSession([Hashtable]$ApiSettings){
        return [WorkspaceOneApiSession]::new($ApiSettings);
    }

    [PSCustomObject]GetResponse([string]$Endpoint, $ApiVersion=1, $Method,  $Data=""){
        $ProcInfo=GetLogPos -FileName $Script:FileName -ClassName ($this.GetType().Name) -FunctionName "GetResponse";
        Write-Log2 -Path $this.Log -ProcessInfo $ProcInfo -Message "BEGIN REQUEST Intializing" -Level Debug

        If($Endpoint -match "^api\/.*"){
            $Endpoint = "$($this.Config.Server)/$Endpoint"
        }ElseIf($Endpoint -match "^\/api\/.*"){
            $Endpoint = "$($this.Config.Server)$Endpoint"
        }ElseIf($Endpoint -like "$($this.Config.Server)/api/*"){
            $Endpoint = $Endpoint
        }Else{
            Throw "Error, endpoint not formatted correctly.  Expecting 'api/module/endpoint'"
        }

        $Accept="application/json;version=$ApiVersion"
        $ContentType="application/json;version=$ApiVersion"
        $Headers=@{"aw-tenant-code"=$this.Config.ApiKey}

        $ClientCertificate="";
        If($this.Config.AuthType -eq "Basic"){
            $Headers.Add("Authorization",$this.Config.BasicAuthCreds);
        }Else{
            If($this.Config.AuthType -in @("Certificate","OauthCertificate")){
                $ClientCertificate=Get-ClientAuthCert -CertificateFilters $this.Config.CertificateSearch
            }

            If($this.Config.AuthType -in @("Oauth", "OauthCertificate")){
                $OauthSettings=$this.Config.OauthConfig;
                $OauthToken = Invoke-OauthTokenRequest -IdentityUri $OauthSettings.identityUri -GrantType $OauthSettings.grant_type -ClientId $OauthSettings.client_id -ClientSecret $OauthSettings.client_secret -Scope $OauthSettings.scope
                If($OauthToken){
                     $Headers.Add("Authorization",$OauthToken);
                }
            }
        }

        $SslThumbprint=$this.Config.SslThumbprint;

        #Performs the GetDeviceId function if a reference to the current device is made in the body or the endpoint
        $CurrentDeviceLookup=$false;

        If(($Data -like "*{DeviceId}*") -or ($Endpoint -like "*{DeviceId}*")){
            $CurrentDeviceLookup=$true;
            If(([string]::IsNullOrEmpty($this.LookupValues["{DeviceId}"])) -or ($this.LookupValues["{DeviceId}"] -eq -1)){
                $DeviceIdResult=Get-CurrentWsoDeviceByAltId
                If($DeviceIdResult){
                    $this.LookupValues["DeviceId"]=$DeviceIdResult
                }
            }
        }

        If($this.LookupValues){
            If($CurrentDeviceLookup -and ($this.LookupValues["DeviceId"] -eq -1)){
                Throw (New-CustomException "Unable to obtain DeviceId for this device.  DeviceId is required for requested command.")
            }
            
            #Lookup value replacer
            foreach($LookupValue in $this.LookupValues.Keys){
                $Endpoint=$Endpoint.Replace("$LookupValue",$this.LookupValues[$LookupValue]);      
                If(![string]::IsNullOrEmpty($Data)){
                    $Data=$Data.Replace("$LookupValue",$this.LookupValues[$LookupValue]);
                }
            }

        }

        #Main web request
        #$WebRequest = $this.InvokeSecureWebRequest($Endpoint, $Method, $ApiVersion, $Data)

        $WebRequest = Invoke-SecureWebRequestEx -Endpoint $Endpoint -Method $Method -Accept $Accept -ContentType $ContentType -Headers $Headers -Data $Data -ClientCertificate $ClientCertificate -SslThumbprint $SslThumbprint
            
        Write-Log2 -Path $this.Log -ProcessInfo $ProcInfo -Message "END REQUEST Response status code '$($WebRequest.StatusCode)'" -Level Info
        If($WebRequest.StatusCode -lt 300){                         
            Write-Log2 -Path $this.Log -ProcessInfo $ProcInfo -Message "END REQUEST Response data: '$($WebRequest.Content)'" -Level Debug  
            $ReturnObj = New-Object -TypeName PSCustomObject -Property @{"StatusCode"=$WebRequest.StatusCode};
            If($WebRequest.Content){
                $ReturnObj = ConvertFrom-Json $WebRequest.Content; 
            }

            If((($ReturnObj.total -ne $null) -and ($ReturnObj.total -gt $ReturnObj.page_size))){              
                $SmartObjectId=($ReturnObj | Get-Member -MemberType NoteProperty | Where Name -notin @("page", "page_size", "total","links") | Select Name).Name
                $CurrentPageCount=$ReturnObj.PageSize - ($ReturnObj."$SmartObjectId" | Measure).Count;
                $CurrentPage=$ReturnObj.Page;
                #Paging
                While($CurrentPageCount -eq 0){ 
                    Write-Log2 -Path $this.Log -ProcessInfo $ProcInfo -Message "Start Paging proccess" -Level Debug             
                    $Divider="?"
                    If($Endpoint -match "([^?]*)\?") { $Divider="&" }
                    $WebRequestPaged=Invoke-SecureWebRequestEx -Endpoint "$Endpoint$Divider`page=$($CurrentPage + 1)" -Accept $Accept -ContentType $ContentType -Headers $Headers -Data $Data -ClientCertificate $ClientCertificate -SslThumbprint $SslThumbprint
                    $ReturnObjPaged = ConvertFrom-Json $WebRequestPaged.Content; 
                    $ReturnObj."$SmartObjectId" += @($ReturnObjPaged."$SmartObjectId") 
                    $CurrentPageCount=($ReturnObjPaged.PageSize-($ReturnObj."$SmartObjectId" | Measure).Count)  
                    $CurrentPage=$ReturnObj.Page      
                }
            }ElseIf(($ReturnObj.TotalResults -ne $null)){
                $PagedObject=@{}
                $PageSize=500
                If($Endpoint -match "pagesize\=([0-9]{1,4})"){
                    $PageSizeMatch=$Matches[1]
                    [int]::TryParse($PageSizeMatch, [ref]$PageSize)
                }
                If($ReturnObj.TotalResults -gt $PageSize -and ($Endpoint -notmatch "page\=")){
                    $PagedObject.Add(0, $ReturnObj)
                    $TotalPages=($ReturnObj.TotalResults / $PageSize)
                    $CurrentPage=1
                    While($CurrentPage -lt $TotalPages){
                        $Divider="?"
                        If($Endpoint -match "([^?]*)\?") { $Divider="&" }
                        $WebRequestPaged=Invoke-SecureWebRequestEx -Endpoint "$Endpoint$Divider`page=$($CurrentPage + 1)" -Accept $Accept -ContentType $ContentType -Headers $Headers -Data $Data -ClientCertificate $ClientCertificate -SslThumbprint $SslThumbprint
                        $ReturnObjPaged = ConvertFrom-Json $WebRequestPaged.Content;
                        $PagedObject.Add($CurrentPage, $ReturnObjPaged)
                        $CurrentPage++;
                    }
                    $ReturnObj=$PagedObject
                }
                
            }
            
             
            #This flag pushes the expiration timer for the deviceId cache for stale devices
            If($CurrentDeviceLookup){
                $CacheResult=Update-LocalCacheEntry -Module "WorkspaceOneAPI" -EntryName "DeviceId" -Data @{"LastHttpResult"=200} -LastScanResult WSO_API_SUCCESS -Force -EncryptData
            }
          
            return $ReturnObj;
        } Else{
            $ErrInfo="ERROR"
            If($WebRequest.StatusCode -in @(403,401)){
                $CacheResult=Update-LocalCacheEntry -Module "WorkspaceOneAPI" -EntryName "AuthError" -Data @{"LastHttpResult"=$WebRequest.StatusCode;"Description"="$ErrInfo`::$($WebRequest.Content))"} -LastScanResult WSO_API_FAILED -Force -EncryptData
                $ErrInfo="AUTHENTICATION ERROR"
            }ElseIf($WebRequest.StatusCode -in $(404)){
                $ErrInfo="RESOURCE NOT FOUND"
                If($CurrentDeviceLookup){
                    #If DeviceId was present but we received a 404 there is a chance that the device is un-enrolled/deleted.  Reseting device Id in cache.
                    $CacheResult=Update-LocalCacheEntry -Module "WorkspaceOneAPI" -EntryName "DeviceId" -Data @{"Id"="-1";"LastHttpResult"=404} -LastScanResult WSO_API_SUCCESS -Force -EncryptData
                }
            }ElseIf($WebRequest.StatusCode -in $(400)){
                $ErrInfo="INVALID API REQUEST"
            }
            Write-Log2 -Path $this.Log -ProcessInfo $ProcInfo -Message "END REQUEST [$ErrInfo]-Status Code '$($WebRequest.StatusCode)' ($($WebRequest.Content))"  -Level Error -FromClass
        }

        return $WebRequest;
    }

    [PSCustomObject]Delete([string]$Endpoint, $ApiVersion=1){
        return $this.GetResponse($Endpoint, $ApiVersion, "DELETE", "")
    }

    [PSCustomObject]Post([string]$Endpoint, $ApiVersion=1, $Data){
        return $this.GetResponse($Endpoint, $ApiVersion, "POST", $Data)
    }

    [PSCustomObject]Patch([string]$Endpoint, $ApiVersion=1, $Data){
        return $this.GetResponse($Endpoint, $ApiVersion, "PATCH", $Data)
    }
    

    [PSCustomObject]Get([string]$Endpoint, $ApiVersion=1){
        return $this.GetResponse($Endpoint, $ApiVersion, "Get", "")
    }

   
}
<#END WorkspaceOneAPI Session class#>

Function Get-CurrentWsoDeviceByAltId{
    param([string]$DeviceSerial,[hashtable]$ApiSettings)
    $ProcInfo=GetLogPos -FileName $CurrentModuleFileName -FunctionName $MyInvocation.MyCommand 
    Write-Log2 -Path $Script:WSOLogLocation -ProcessInfo $ProcInfo -Message "BEGIN Getting current DeviceId from the API." -Level Debug

    If(!($DeviceSerial)){
        $DeviceSerial = Get-DeviceSerial
    }
    $DeviceSearchEndpoint = "api/mdm/devices?searchBy=Serialnumber&id=$DeviceSerial";
    $DeviceSearchResult =  Invoke-WorkspaceOneAPICommand -Endpoint $DeviceSearchEndpoint -ApiSettings $ApiSettings -UseLocal:(!($ApiSettings))
    If($DeviceSearchResult -and ($DeviceSearchResult.Id)){
        If($DeviceSearchResult.Enrolled -eq "Unenrolled"){
            return -1
        }
        $DeviceData=@{"Uuid"=$DeviceSearchResult.Uuid;
            "Id"=$DeviceSearchResult.Id.Value;
            "LastHttpResult"=200}
        $CacheResults=Set-LocalCacheEntry -Module "WorkspaceOneAPI" -EntryName "DeviceId" -Data $DeviceData -ExpirationHours (7*24) -Force -EncryptData
        return $DeviceData
    }
    Write-Log2 -Path $Script:WSOLogLocation -ProcessInfo $ProcInfo -Message "END An error has occured retrieving DeviceId. Response: '$($DeviceSearchResult.StatusCode)'" -Level Error
    return -1
}

function Get-OrganizationGroup{
    param($ApiSettings,$OrganizationGroupId)
    If([string]::IsNullOrEmpty($OrganizationGroupId)){
        $OrganizationGroupId = "{OrganizationGroupId}"
    }
    $OrganizationGroupEndpoint="api/system/groups/$OrganizationGroupId"
    $GetOGResult=Invoke-WorkspaceOneAPICommand -Endpoint $OrganizationGroupEndpoint -ApiSettings $ApiSettings -UseLocal:(!($ApiSettings))
    If($GetOGResult){
        return $GetOGResult
    }
    
    $CacheResults=Set-LocalCacheEntry -Module "WorkspaceOneAPI" -EntryName "DeviceId" -Data $DeviceData -ExpirationHours (7*24) -Force -EncryptData
    return
}


function Test-WorkspaceOneAPILocalConfig{
    If(!(Test-LocalCacheEntry -Module "WorkspaceOneAPI" -EntryName "Config" )){
        return $false
    }
    return $true
}

<#
.SYNOPSIS
    Sets the local WorkspaceOneAPI config
.DESCRIPTION
    Sets the local WorkspaceOneAPI config for processing long running scripts and local process heavy API scripts.
.PARAMETER ApiSettings
    Hashtable of the API Settings.  Required KeyValues: Server, 
#>
function Write-WorkspaceOneAPILocalConfig{
    param([Hashtable]$ApiSettings,[string]$ConfigId="")
    #Format SSL thumbprint
    $ApiSettings['SslThumbprint'] = $ApiSettings['SslThumbprint'].Replace(" ","").ToLower()

    #If no auth type is provided use Basic Auth
    If(!$ApiSettings.ContainsKey('AuthType')){
        $ApiSettings.Add('AuthType','Basic')
    }ElseIf($ApiSettings['AuthType'] -in @("Basic","Oauth","Certificate","OauthCertificate")){
        $AuthType=$ApiSettings['AuthType']
    }
    
    #Certificate validation
    If($AuthType -in @("Certificate","OauthCertificate")){
        If(!$ApiSettings.ContainsKey('CertificateSearch')){
            throw "An error has occured.  Certificate authentication was not configured correctly"
        } 
    }

    <#
    'identityUri' 'grant_type' 'client_id' 'client_secret' 'scope'
    #>
    If($ApiSettings['AuthType'] -in @("Oauth","OauthCertificate")){
        If(!$ApiSettings.ContainsKey('OauthConfig')){
            throw "An error has occured.  Oauth Authentication was not configured correctly"
        }Else{
            If(!($ApiSettings['OAuthConfig'].ContainsKey("identityUri") -and 
               $ApiSettings['OAuthConfig'].ContainsKey("grant_type") -and
               $ApiSettings['OAuthConfig'].ContainsKey("client_secret") -and
               $ApiSettings['OAuthConfig'].ContainsKey("client_id"))){
                throw "An error has occured.  Oauth Authentication was not configured correctly"
            }
        }
    }

    If($ApiSettings['AuthType'] -eq 'Basic'){
        If(!$ApiSettings.ContainsKey('BasicAuth')){
            $ApiSettings.Add('BasicAuth',(New-BasicAuthCredentials -UserName $ApiSettings['Username'] -Password $ApiSettings['Password']))
            $ApiSettings.Remove('Username')
            $ApiSettings.Remove('Password')
        }
    }

    $LocalConfigResult=Set-LocalCacheEntry -Module "WorkspaceOneAPI" -EntryName "Config$ConfigId" -Data $ApiSettings -EncryptData -Force -ExpirationHours 0
    return $LocalConfigResult
}

function Read-WorkspaceOneAPILocalConfig{
    param([string]$ConfigId="")
    $ProcInfo=GetLogPos -FileName $Script:Filename -FunctionName $MyInvocation.MyCommand.Name 
          
    $ApiObj = Get-LocalCacheEntry -Module "WorkspaceOneAPI" -CacheName "" -EntryName "Config$ConfigId"
    If(!($ApiObj)){
        Throw "Unable to retrieve Local Workspace One API config."
    }

    $ApiSettings=@{'AuthType'=$ApiObj.AuthType;
            'Server'=$ApiObj.Server;
            'ApiKey'=$ApiObj.ApiKey;
            'SslThumbprint'=$ApiObj.SslThumbprint;
            'OrganizationGroupId'=$ApiObj.OrganizationGroupId
        }

    If($ApiSettings.AuthType -in @('Basic')){
        $ApiSettings.Add("BasicAuth",$ApiObj.BasicAuth) | Out-Null
    }
    If($ApiSettings.AuthType -like '*Certificate*'){
        If($ApiObj.CertificateSearch){
           $ApiSettingsHash = ConvertTo-Hashtable -Object $ApiObj.CertificateSearch 
           $ApiSettings.Add("CertificateSearch",$ApiSettingsHash) | Out-Null
        }
    }
    If($ApiSettings.AuthType -like '*Oauth*'){
        If($ApiObj.OauthConfig){
            $ApiSettingsOauthHash = ConvertTo-Hashtable -Object $ApiObj.OauthConfig 
            $ApiSettings.Add("OauthConfig",$ApiSettingsOauthHash) | Out-Null
        }
    }
    

    return $ApiSettings
}



<#
.SYNOPSIS
    Creates a WorkspaceOneAPISession object for persistant use
.DESCRIPTION
    
.PARAMETER APISettings
    Hashtable of API settings
.PARAMETER UseLocal
    A switch that indicates locally saved API settings should be used
    If Both parameters are set the funciton overrides the current local configuration
.OUTPUT
    
#>
function New-WorkspaceOneAPISession{
    param([Parameter(ParameterSetName = 'Hashtable')]        
        [Hashtable]$ApiSettings,
        [Parameter(ParameterSetName = 'Hashtable')]        
        [Switch]$UseLocal)
        
        If($ApiSettings -and $UseLocal){
            Write-WorkspaceOneAPILocalConfig -ApiSettings $ApiSettings
        } ElseIf(!$ApiSettings -and $UseLocal){
            $ApiSettings=Read-WorkspaceOneAPILocalConfig
        } 

        If(!$ApiSettings){
            Write-Log2 -Path $Script:WSOLogLocation -Message "$LOGPOS::No API settings present" -Level Warn
            return
        }

        return [WorkspaceOneApiSession]::new($ApiSettings)
}


$SeperatorBar="================={0}==================="

<#
.SYNOPSIS
    Command for sending a single WorkspaceOne API command.  Most secure command for client side device connections that require storing local settings.
.DESCRIPTION
    Uses the static command inside the WorkspaceOneAPISession object that creates a single use instance, performs the connection then closes the connection.
    This command was designed to ensure any configurations are only temporarily stored in memory.  This method is more memory and CPU intensive, but should
    provide more security by limiting the amount of time any settings are exposed in memory.
.PARAMETER Endpoint
    Rest API path (Example: /api/mdm/device) 
.PARAMETER Method
    HTTP Method for the Rest API command
.PARAMETER APIVersion
    Value used by server to determine which version of a REST API call to execute
.PARAMETER APISettings
    Allows APISetting Hashtable to be passed
.PARAMETER UseLocal
    UseLocal uses the locally configured settings.  If API settings were also passed,
    this function with override the existing local settings
.PARAMETER StartNewLog
    Starts a brand new log file for this command.  Old log file is archived, but keep in mind
    that there are limited number of default archives (up to 30)
.OUTPUT
#>
Function Invoke-WorkspaceOneAPICommand{
    param([string]$Endpoint, [string]$Method="GET", $ApiVersion=1, $Data, $ApiSettings, [string]$ConfigId, [switch]$UseLocal, [switch]$StartNewLog)
    Begin{
        $ProcInfo=GetLogPos -FileName $Script:Filename -FunctionName $MyInvocation.MyCommand.Name 
        Write-Log2 -Path $WSOLogLocation  -Message ($SeperatorBar -f "Start $Method '$Endpoint'") -Level Info
        Write-Log2 -Path $WSOLogLocation -LogPosition $ProcInfo -Message "BEGIN Creating WorkspaceOneAPI command" -Level Info
    }Process{
        If($ApiSettings -and $UseLocal){
            $WriteResults=Write-WorkspaceOneAPILocalConfig -ApiSettings $ApiSettings -ConfigId $ConfigId
        } ElseIf(!$ApiSettings -and $UseLocal){
            $ApiSettings=Read-WorkspaceOneAPILocalConfig -ConfigId $ConfigId
        }     
        If(!$ApiSettings){
            Write-Log2 -Path $Script:WSOLogLocation -ProcessInfo $LogPos -Message "No API settings present" -Level Warn
            return
        }    
        $Result=[WorkspaceOneApiSession]::InvokeWorkspaceOneAPICommand($ApiSettings, $Endpoint, $Method, $ApiVersion, $Data)
        return $Result
    }End{
        Write-Log2 -Path $WSOLogLocation  -Message ($SeperatorBar -f "End $Method '$Endpoint'")
    }
}

#General WorkspaceOneAPI Commands
$ExportedFunctions = @("New-WorkspaceOneAPISession","Invoke-WorkspaceOneAPICommand","Get-ClientAuthCertTest","Invoke-SecureWebRequestEx","Get-CurrentWsoDeviceByAltId","Get-WorkspaceOneAPILookupValue","Get-OrganizationGroup")

#Local config command
$ExportedFunctions += @("Write-WorkspaceOneAPILocalConfig","Test-WorkspaceOneAPILocalConfig")

#Logging controls commands
$ExportedFunctions += @("Start-NewWorkspaceOneLog","Remove-AllWorkspaceOneLogs")

$ExportedFunctions += @($module.ExportedFunctions.Keys)

Export-ModuleMember -Function $ExportedFunctions -Variable "LibPaths" -Alias @($module.ExportedAliases.Keys)