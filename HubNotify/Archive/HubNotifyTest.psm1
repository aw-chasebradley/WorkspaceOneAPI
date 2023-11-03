<#
*
* Hub Notify Utility
* by Chase Bradley
*
#>

#Set directory to current script path
$Script:current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #Developer utility
    $current_path = "$env:SystemRoot\System32\WindowsPowershell\v1.0\Modules\HubNotify";
}

$ExtensionPath="HKLM:\SOFTWARE\AirWatch\Extensions"
$shared_path=Get-ItemProperty -Path $ExtensionPath | Select-Object "SharedPath" -ExpandProperty "SharedPath" -ErrorAction SilentlyContinue
If(!($shared_path)){ Throw "Common library is not installed" }

$Script:logPath=Get-ItemProperty -Path $ExtensionPath | Select-Object "LogPath" -ExpandProperty "LogPath" -ErrorAction SilentlyContinue

$Script:LogFile="$logPath\HubNotify.log"
$GlobalModules = @();
$GlobalImporter = @("$shared_path\Wso.CommonLib.psm1","$current_path\RunAsUser.psm1");

foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}

#Import Uwp Notifcation Library
$Script:AssemblyName = Get-ChildItem -Path "$current_path\bin\Microsoft.Toolkit.Uwp.Notifications.dll"
if (-not ($AssemblyName.Name  -as [type])) {
    Unblock-File $AssemblyName.FullName
    Add-Type -Path $AssemblyName.FullName -ErrorAction Stop
}


function New-ToastContentBuilder{
    $ContentBuilder=[Microsoft.Toolkit.Uwp.Notifications.ToastContentBuilder]::new();
    $ContentBuilder.SetToastDuration([Microsoft.Toolkit.Uwp.Notifications.ToastDuration]::Long)
    return $ContentBuilder
}

function New-ToastNofication{
    param($InputXML)
    If($InputXML){
        [Windows.Data.Xml.Dom.XmlDocument,Windows.Data,ContentType=WindowsRuntime]
        $ToastXMLBuilder=[Windows.Data.Xml.Dom.XmlDocument]::new()
        #$ToastXMLBuilder=[System.Xml.XmlDocument]::new()
    
        $ToastXMLBuilder.LoadXml($InputXML.OuterXml)
        $Toast=[Windows.UI.Notifications.ToastNotification]::new($ToastXMLBuilder)
    } 
    return $Toast
}

function New-ToastNoficationBasic{
    param($Message,$Caption)
    $HubNotificationObj=[HubNotification]::NewBasic($Message,$Caption)
    return $HubNotificationObj
}

function New-NotificationManagerCompat{
    return [Microsoft.Toolkit.Uwp.Notifications.ToastNotificationManagerCompat]::CreateToastNotifier()
}


function New-ToastDismissButton{
    return [Microsoft.Toolkit.Uwp.Notifications.ToastButtonDismiss]::new()
}

class HubNotification{
    [string]$Style;
    [PSCustomObject]$Metadata=@{};
    
    $ToastContentBuilder;
    
    [PSCustomObject]GetNotificationObject([string]$InputObject){        
        $JsonObject=$null;
        Try{
            $JsonObject=ConvertFrom-Json -InputObject $InputObject;
        }Catch{
            #Error handling for List not found.
            $Error="An error has occured.  " + $_.Exception.Message
            Write-Error -Message $Error -Category InvalidArgument 
            return $null 
        }
        return $JsonObject;
    }

    HubNotification([string]$Input,$ToastContentBuilder){
        
        $this.Metadata=$this.GetNotificationObject($Input)
        $this.ToastContentBuilder = $ToastContentBuilder;
        If($this.Metadata){
            $this.BuildJson($Input)
        }
  
    }

    static [HubNotification]NewBasic([string]$Message,[string]$Caption){
         $InputObject=@'
{
	"toast":{
		"launch":"readMoreArg",
		"template":"ToastGeneric",
		"binding":[
			{"type":"Text",
			 "text":"{Caption}"
			},
			{"type":"AppLogo",
			 "path":"file:///{Path}\\resources\\icon.jpeg"
			},
			{"type":"Button",	 
			 "text":"Accept",
             "activationType":"Background",
			 "action":"{
				  Set-ItemProperty -Path HKLM:\\Software\\AIRWATCH\\Extensions\\HubNotify -Name 'AcceptToast' -Value '1' -Force
			 }"		
			},
			{"type":"ToastButtonDismiss"
			}
		]
	}
}

'@;
        $InputObject=$InputObject.Replace("{Caption}",$Caption);
        #$InputObject=$InputObject.Replace("{Message}",$Message);
        $InputObject=$InputObject.Replace("{Path}",$Script:current_path.Replace("\","\\"));
        return [HubNotification]::new($InputObject, (New-ToastContentBuilder));
    }

    [void]BuildJson([string]$Input){
        If($this.Metadata -and ($this.Metadata | Get-Member -Name "toast")){
            ForEach($Item in $this.Metadata.toast.binding){
                # Check that item has type
                If(!($Item | Get-Member -Name "type")){
                    Write-Warning -Message "Malformed Toast object.  No type specif" -Category InvalidArgument 
                    break;
                } 

                $ItemProperties = ($Item | Get-Member -Type NoteProperty).Name
                Write-Log2 -Path $Script:LogFile -Message "Item type is, $($Item.type)."
                If($Item.type -eq "Text"){
                    # Ensure Text Item contant
                    If($ItemProperties -contains "text"){
                        $this.ToastContentBuilder.AddText($Item.text)
                    } 
                } ElseIf($Item.type -eq "AppLogo"){                   
                    If($ItemProperties -contains "path"){
                        $this.ToastContentBuilder.AddAppLogoOverride($Item.path)
                    } 
                } ElseIf($Item.type -eq "Button"){                    
                    If($ItemProperties -contains "text" -and
                        $ItemProperties -contains "activationType" -and
                        $ItemProperties -contains "action" 
                    ){
                        $this.ToastContentBuilder.AddButton($Item.text,$Item.activationType,"ButtonClick")
                        $CompatMgr = New-NotificationManagerCompat
                        $objectEvent= Register-ObjectEvent -InputObject $CompatMgr -EventName OnActivated -Action {     
                            Try{       
                                $Script:ToastEvent = $Event
                                Invoke-Command -ScriptBlock $Item.action
                            } Catch{
                                $err=$_.Exception.Message
                                Write-Log2 -Path $Script:logFile -Message $err -Level Error
                            }
                        }
                        
                    } 
                } ElseIf($Item.type -eq "ToastButtonDismiss"){
                    $tdb=New-ToastDismissButton
                    $this.ToastContentBuilder.AddButton($tdb)
                }
            }
        }
    }


    [void]ShowXML(){
        $CompatMgr = New-NotificationManagerCompat
                        
    }

    [void]Show(){
        #Write-Log2 -Path $Script:LogFile -Message (($this.ContentBuilder.GetXml()) | Get-Member | Out-String)
        #$myXml=$this.ToastContentBuilder.GetXml();
        #Write-Log2 -Path $Script:LogFile -Message ($this.ContentBuilder.Content | Get-Member | Out-String)
        $this.ToastContentBuilder.Show();
    }
}



function Send-WorkspaceOneNotification{
    param([string]$InputXML,
        [string]$json)
    Write-Log2 -Path $logFile -Message "WorkspaceONE.HubNotify::Send-WorkspaceOneNotification++" -Level Info 

    try{
        $NM=New-NotificationManagerCompat
        $TN=(New-ToastNofication -InputXML $InputXML)

        $NM.Show($TN[1])
    }catch{
        $ErrorMessage=$_.Exception.Message
        Write-Log2 -Message "An error has occured showing message:$ErrorMessage" -Path $logFile -Level Error
    } 
}



function Set-Result{
    param($Key,$Value)
    If(!(Test-Path "HKLM:\Software\AIRWATCH\Extensions")){
        New-Item -Path "HKLM:\Software\AIRWATCH" -Name "Extensions"
    }
    If(!(Test-Path "HKLM:\Software\AIRWATCH\Extensions\HubNotify")){
        New-Item -Path "HKLM:\Software\AIRWATCH\Extensions" -Name "HubNotify"
    }
    
    New-ItemProperty -Path "HKLM:\Software\AIRWATCH\Extensions\HubNotify" -Name $Key -Value $Value 

}

function Get-Result{
    param($Key)
    If(Test-Path "HKLM:\Software\AIRWATCH\Extensions\HubNotify"){
        $Item=Get-Item -Path "HKLM:\Software\AIRWATCH\Extensions\HubNotify"
        Try{
            Get-ItemPropertyValue -Path "HKLM:\Software\AIRWATCH\Extensions\HubNotify" -Name $Key
        }Catch{
            return
        }
    }
}

function Test-CurrentContext() {  
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    return $currentUser.IsSystem; 
}

function Send-WorkspaceOneNotificationJSONExTest{
    param([string]$Message,[string]$Caption)    
    Try{
        If(Test-CurrentContext){
            & Invoke-CommandAsUser -mycommand "Send-WorkspaceOneNotificationJSONTest -Message $Message -Caption $Caption -StoreInReg"
            $Result=Get-Result -Key "NotificationResult"
        } Else{
            $Result=Send-WorkspaceOneNotificationJSONTest -Message $Message -Caption $Caption
        }    
    }Catch{
        $err=$_.Exception.Message;
        Write-Log2 -Message "An error has occured running as current user command:$err" -Path $logFile -Level Error
    }
    return $Result
}


function Send-WorkspaceOneNotificationJSONTest{
    param([string]$Message,[string]$Caption)
    Write-Log2 -Path $logFile -Message "WorkspaceONE.HubNotify::Send-WorkspaceOneNotification++" -Level Info 

    try{
        $NotificationObj=New-ToastNoficationBasic $Message $Caption 
        $NotificationObj.Show()

    }catch{
        $ErrorMessage=$_.Exception.Message
        Write-Log2 -Message "An error has occured showing message:$ErrorMessage" -Path $logFile -Level Error
    } 
}

function Send-DotNetNotificationTest{
    param([string]$Message,[string]$Caption,[switch]$StoreInReg)

    Try{
        if (-not ("System.Windows.Forms.MessageBox"  -as [type])){
            [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        }
    }Catch{
        $err=$_.Exception.Message
        Write-Log2 -Message "An error has occured, $err" -Path $logFile -Level Error
    }

    Try{
        $Result=[System.Windows.Forms.MessageBox]::Show($Message, $Caption, [System.Windows.Forms.MessageBoxButtons]::YesNo)
    }Catch{
        $err=$_.Exception.Message
        Write-Log2 -Message "An error has occured, $err" -Path $logFile -Level Error
    }
    If($StoreInReg.IsPresent){
        Set-Result "NotificationResult" $Result
    }
    return $Result
}

function Send-DotNetNotificationExTest{
    param([string]$Message,[string]$Caption)    
    Try{
        If(Test-CurrentContext){
            & Invoke-CommandAsUser -mycommand "Send-DotNetNotificationTest -Message $Message -Caption $Caption -StoreInReg" 
        } Else {
            Send-DotNetNotificationTest -Message $Message -Caption $Caption
        }
    }Catch{
        $err=$_.Exception.Message;
        Write-Log2 -Message "An error has occured running as current user command:$err" -Path $logFile -Level Error
    }
    Get-Result -Key "NotificationResult"
}

#Export-ModuleMember -Function Send-WorkspaceOneNotification,Invoke-CommandAsUser,Send-WorkspaceOneNotificationJSON,Send-DotNetNotification,Send-DotNetNotificationEx,Send-WorkspaceOneNotificationJSONEx