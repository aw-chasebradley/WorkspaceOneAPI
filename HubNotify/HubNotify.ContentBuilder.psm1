<#
.SYNOPSIS
    HubNotify.ContentBuilder
.DESCRIPTION 
    Library for building notifications
#>

#Module metadata info
$CurrentModuleFileName = (Split-Path $PSCommandPath -Leaf).Replace(".psm1","").Replace(".ps1","")
$ModuleName="$CurrentModuleFileName"

#Registry
$ExtensionPath = "HKLM:\Software\AIRWATCH\Extensions";
$ApiPath = "$ExtensionPath\WorkspaceOneAPI";
$InstallPath="$ExtensionPath\$ModuleName";

$ExtensionPath="HKLM:\SOFTWARE\AirWatch\Extensions"
$shared_path=Get-ItemProperty -Path $ExtensionPath | Select-Object "SharedPath" -ExpandProperty "SharedPath" -ErrorAction SilentlyContinue
If(!($shared_path)){ Throw "Common library is not installed" }

$GlobalModules = @();
$GlobalImporter = @("$shared_path\Wso.CommonLib.psm1");
foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force;
}

If(!(Test-Path $InstallPath)){ 
    $RegResult=New-Item -Path $InstallPath -Force; 
    $RegResult=New-ItemProperty -Path $InstallPath -Name "InstallLocation" -Value "$PSScriptRoot" -Force 
}

$LogPath=Get-ItemProperty -Path $ExtensionPath | Select-Object "LogPath" -ExpandProperty "LogPath" -ErrorAction SilentlyContinue
#Setting up Log Location
$Script:LogFile="$LogPath\$ModuleName.log"
$Script:FileName = (Split-Path $PSCommandPath -Leaf).Replace(".psm1","").Replace(".ps1","")


#Import Uwp Notifcation Library
$Script:AssemblyName = Get-ChildItem -Path "$PSScriptRoot\bin\Microsoft.Toolkit.Uwp.Notifications.dll"
if (-not ($AssemblyName.Name  -as [type])) {
    Unblock-File $AssemblyName.FullName
    Add-Type -Path $AssemblyName.FullName -ErrorAction Stop
}

$Global:RegisteredEvents=@{}

function New-WorkspaceOneJSONMessage{
    param([string]$Message="Administrator Alert",[string]$Caption="Administrator Alert",[string]$ButtonText="Alert",[scriptblock]$ScriptBlock)
         $InputObject=@"
{
	"toast":{
	"launch":"readMoreArg",
    "template":"ToastGeneric",
		"binding":[{"type":"Text",
			 "text":"$Caption"
			},
            {"type":"AppLogo",
			 "path":"file:///$($PSScriptRoot.Replace("\","\\"))\\resources\\icon.jpeg"
			},
			{"type":"Button",	 
			 "text":"$ButtonText",
             "activationType":"Background",
			 "action":"`$RegFeedback=Set-ItemProperty -Path 'HKLM:\\Software\\AIRWATCH\\Extensions\\HubNotify' -Name 'AcceptToast' -Value '1' -Force"		
			},
			{"type":"ToastButtonDismiss"
			}
		]
	}
}

"@;
        $Metadata=ConvertFrom-Json $InputObject;
        return $Metadata
}



function New-ContentBuilderFromJson{
    param([string]$UniqueId,$JsonMessage)
    Begin{
        $ProcInfo=GetLogPos -FileName $Script:Filename -FunctionName $MyInvocation.MyCommand.Name 
        Write-Log2 -Path $Script:LogFile -ProcessInfo $ProcInfo -Message "BEGIN Dynamic content builder" -Level Debug
    }Process{
        $ToastContentBuilder=[Microsoft.Toolkit.Uwp.Notifications.ToastContentBuilder]::new();
        $ToastContentBuilder.SetToastDuration([Microsoft.Toolkit.Uwp.Notifications.ToastDuration]::Long)
            
        If($JsonMessage -and ($JsonMessage | Get-Member -Name "toast")){
            ForEach($Item in $JsonMessage.toast.binding){
                # Check that item has type
                If(!($Item | Get-Member -Name "type")){
                    Write-Warning -Message "Malformed Toast object.  No type specif" -Category InvalidArgument 
                    break;
                } 

                $ItemProperties = ($Item | Get-Member -Type NoteProperty).Name
                $ItemLogMessage="Processing item type is, $($Item.type)-->"

               
  
                If($Item.type -eq "Text"){
                    # Ensure Text Item contant
                    If($ItemProperties -contains "text"){
                        Write-Log2 -Path $Script:LogFile -ProcessInfo $ProcInfo -Message "$ItemLogMessage`Adding text to Content Builder, $($Item.text)." -Level Debug
                        $null=$ToastContentBuilder.AddText($Item.text)
                    } 
                } ElseIf($Item.type -eq "AppLogo"){                   
                    If($ItemProperties -contains "path"){
                        Write-Log2 -Path $Script:LogFile -ProcessInfo $ProcInfo -Message "$ItemLogMessage`Adding image to Content Builder at path, $($Item.path)." -Level Debug
                        $null=$ToastContentBuilder.AddAppLogoOverride($Item.path)
                         
                    } 
                } ElseIf($Item.type -eq "Button"){                    
                    If($ItemProperties -contains "text" -and
                        $ItemProperties -contains "activationType" -and
                        $ItemProperties -contains "action" 
                    ){
                        Write-Log2 -Path $Script:LogFile -ProcessInfo $ProcInfo -Message "$ItemLogMessage`Adding button to Content Builder with text, $($Item.text)." -Level Debug
                        $null=$ToastContentBuilder.AddButton($Item.text,[Microsoft.Toolkit.Uwp.Notifications.ToastActivationType]::Background,"ButtonClick")
                        
                        #Adding event to event manager
                        Write-Log2 -Path $Script:LogFile -ProcessInfo $ProcInfo -Message "$ItemLogMessage`Checking for registration of event: $((Get-EventSubscriber -SourceIdentifier $UniqueId -ErrorAction SilentlyContinue) -ne $null)." -Level Info
                        If(!(Get-EventSubscriber -SourceIdentifier $UniqueId -ErrorAction SilentlyContinue)){                       
                            $CompatMgr = [Microsoft.Toolkit.Uwp.Notifications.ToastNotificationManagerCompat]
                            
                            $MessageData=New-Object PSObject -Property @{"ScriptBlock"=$Item.Action;"LogPath"=$Script:LogFile;"ProcInfo"=$ProcInfo}

                            

                            $Global:RegisteredEvents.Add($UniqueId, 
                                (Register-ObjectEvent -InputObject $CompatMgr -SourceIdentifier "$UniqueId" -EventName OnActivated -MessageData $MessageData -MaxTriggerCount 1 -Action {
                                    $LogPath=$Event.MessageData.LogPath
                                    $ProcInfo=$Event.MessageData.ProcInfo

                                    Write-Log2 -Path $LogPath -ProcessInfo $ProcInfo -Message "EVENT Event processessing for $($Event.SourceArgs.Argument). " -Level Debug 
                                     
                                    if ($Event.SourceArgs.Argument -like "ButtonClick*") {   
                                        Write-Log2 -Path $LogPath -ProcessInfo $ProcInfo -Message "EVENT Running script block,`r`n`t`t$($Event.MessageData.ScriptBlock)" -Level Info
                                        $RegisteredScriptBlock=[ScriptBlock]::Create($Event.MessageData.ScriptBlock)   
                                        Invoke-Command -ScriptBlock $RegisteredScriptBlock

                                    }   
                                    
                                })
                            );
                        } Else{
                            Write-Log2 -Path $Script:LogFile -ProcessInfo $ProcInfo -Message "Event is already registered for $UniqueId." -Level Debug
                        }
                        
                    } 
                } ElseIf($Item.type -eq "ToastButtonDismiss"){
                    $tdb=[Microsoft.Toolkit.Uwp.Notifications.ToastButtonDismiss]::new()
                    $null=$ToastContentBuilder.AddButton($tdb)
                }
            }
        }
        $ToastContentBuilder.Show();
        return $ToastContentBuilder
    }
}

function Send-WorkspaceOneNotificationEx{
    param([string]$Type,[string]$UniqueId,[string]$Message,[string]$Caption,[ScriptBlock]$Action)
    Begin{
        $ProcInfo=Get-LogPos -FileName $Script:Filename -FunctionName $MyInvocation.MyCommand.Name 
        Write-Log2 -Path $logFile -ProcessInfo $ProcInfo -Message "BEGIN Generating WorkspaceOne Toast Notification with args Type: $Type, UniqueId: $UniqueId, Message: $Message, Caption: $Caption" -Level Debug 
    }Process{     
        Try{
            $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
            Write-Log2 -Path $logFile -ProcessInfo $ProcInfo -Message "PROCESS Generating Toast notification under context, $($currentUser.Name)" -Level Info
            If(!($currentUser.IsSystem)){
                $MessageFormat=New-WorkspaceOneJSONMessage -Message $Message -Caption $Caption -ButtonText "Acccept"
                $NewContentBuilder=New-ContentBuilderFromJson -UniqueId $UniqueId -JsonMessage $MessageFormat
            } Else{
                Write-Log2 -Path $logFile -ProcessInfo $ProcInfo -Message "PROCESS Notifications cannont be generated under the System Context.  Use HubNotify.Launch script." -Level Warn
            }
        }Catch{
            $ErrorMessage=$_.Exception.Message
            Write-Log2 -Message "An error has occured showing message:$ErrorMessage" -ProcessInfo $ProcInfo -Path $logFile -Level Error
        }      
    }End{
        Write-Log2 -Path $logFile -Message "END Generating WorkspaceOne Toast Notification" -Level Debug     
    }
}

#Export-ModuleMember -Function Send-WorkspaceOneNotification,Invoke-CommandAsUser,Send-WorkspaceOneNotificationJSON,Send-DotNetNotification,Send-DotNetNotificationEx,Send-WorkspaceOneNotificationJSONEx