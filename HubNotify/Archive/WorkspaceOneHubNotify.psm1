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

$Global:RegisteredEvents=@()


function New-WorkspaceOneJSONMessage{
    param([string]$Message,[string]$Caption)
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
			 "action":"Set-ItemProperty -Path 'HKLM:\\Software\\AIRWATCH\\Extensions\\HubNotify' -Name 'AcceptToast' -Value '1' -Force"		
			},
			{"type":"ToastButtonDismiss"
			}
		]
	}
}

'@;
        $InputObject=$InputObject.Replace("{Caption}",$Caption);
        $InputObject=$InputObject.Replace("{Path}",$Script:current_path.Replace("\","\\"));
        
        $ContentBuilder=New-ContentBuilderFromJson -Input $InputObject;
        return $ContentBuilder
}

function New-ContentBuilderFromJson{
    param([string]$Input)
    $ToastContentBuilder=[Microsoft.Toolkit.Uwp.Notifications.ToastContentBuilder]::new();
    $ToastContentBuilder.SetToastDuration([Microsoft.Toolkit.Uwp.Notifications.ToastDuration]::Long)
        
    $Metadata=ConvertFrom-Json $InputObject;

    If($Metadata -and ($Metadata | Get-Member -Name "toast")){
        ForEach($Item in $Metadata.toast.binding){
            # Check that item has type
            If(!($Item | Get-Member -Name "type")){
                Write-Warning -Message "Malformed Toast object.  No type specif" -Category InvalidArgument 
                break;
            } 

            $ItemProperties = ($Item | Get-Member -Type NoteProperty).Name
            #Write-Log2 -Path $Script:LogFile -Message "Item type is, $($Item.type)."
            If($Item.type -eq "Text"){
                # Ensure Text Item contant
                If($ItemProperties -contains "text"){
                    $ToastContentBuilder.AddText($Item.text)
                } 
            } ElseIf($Item.type -eq "AppLogo"){                   
                If($ItemProperties -contains "path"){
                    $ToastContentBuilder.AddAppLogoOverride($Item.path)
                } 
            } ElseIf($Item.type -eq "Button"){                    
                If($ItemProperties -contains "text" -and
                    $ItemProperties -contains "activationType" -and
                    $ItemProperties -contains "action" 
                ){
                    $ToastContentBuilder.AddButton($Item.text,$Item.activationType,"ButtonClick")
                     
                    $CompatMgr = [Microsoft.Toolkit.Uwp.Notifications.ToastNotificationManagerCompat]
                   
                    $MessageData=New-Object PSObject -Property @{"ScriptBlock"=$Item.Action;"LogPath"=$Script:LogFile}
                    $Global:RegisteredEvents += @(Register-ObjectEvent -InputObject $CompatMgr -EventName OnActivated -MessageData $MessageData -Action {
                        Write-Log2 -Path $Event.MessageData.LogPath -Message "Event processessing for $($Event.SourceArgs.Argument). " -Level Info 
                        $MessageGuid=$Event.MessageData.MessageGuid   
                        if ($Event.SourceArgs.Argument -like "ButtonClick*") {   
                            Write-Log2 -Path $Event.MessageData.LogPath -Message "MessageGuid: $MessageGuid.  Running script block,`r`n`t`t$($Event.MessageData.ScriptBlock)"
                            $RegisteredScriptBlock=[ScriptBlock]::Create($Event.MessageData.ScriptBlock)   
                            Invoke-Command -ScriptBlock $RegisteredScriptBlock 
                        }   
                    })
                        
                } 
            } ElseIf($Item.type -eq "ToastButtonDismiss"){
                $tdb=[Microsoft.Toolkit.Uwp.Notifications.ToastButtonDismiss]::new()
                $ToastContentBuilder.AddButton($tdb)
            }
        }
    }
    $Host.UI.RawUI.WindowTitle="WorkspaceOneUEM"
    $ToastContentBuilder.Show();
    return $ToastContentBuilder
}


function Set-Result{
    param($Key,$Value)
    If(!(Test-Path "HKLM:\Software\AIRWATCH\Extensions\HubNotify")){
        New-Item -Path "HKLM:\Software\AIRWATCH\Extensions\HubNotify" -Force
    }
    New-ItemProperty -Path "HKLM:\Software\AIRWATCH\Extensions\HubNotify" -Name $Key -Value $Value -Force
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


function Send-WorkspaceOneNotificationL{
    param([string]$Message,[string]$Caption)
    Write-Log2 -Path $logFile -Message "WorkspaceONE.HubNotify::Send-WorkspaceOneNotification++" -Level Info 
    try{
        $NotificationObj=New-WorkspaceOneJSONMessage $Message $Caption 
    }catch{
        $ErrorMessage=$_.Exception.Message
        Write-Log2 -Message "An error has occured showing message:$ErrorMessage" -Path $logFile -Level Error
    }
    Write-Log2 -Path $logFile -Message "WorkspaceONE.HubNotify::Send-WorkspaceOneNotification--" -Level Info
}

#Export-ModuleMember -Function Send-WorkspaceOneNotification,Invoke-CommandAsUser,Send-WorkspaceOneNotificationJSON,Send-DotNetNotification,Send-DotNetNotificationEx,Send-WorkspaceOneNotificationJSONEx