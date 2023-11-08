param([string]$LogLevel,[int]$Interval=15)

$WorkspaceOneModulePath="C:\Ws1\WorkspaceOneAPI"
$AddTagModulePath="C:\Ws1\WorkspaceOneAPI\Addon"
Unblock-File -Path "$AddTagModulePath\Wso.API.Tags.psm1"
$module = Import-Module "$AddTagModulePath\Wso.API.Tags.psm1" -ErrorAction Stop -PassThru -Force;
Unblock-File -Path "$AddTagModulePath\Wso.API.WinApps.psm1"
$module = Import-Module "$AddTagModulePath\Wso.API.WinApps.psm1" -ErrorAction Stop -PassThru -Force;
Unblock-File -Path "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1"
$module = Import-Module "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1" -ErrorAction Stop -PassThru -Force;

Set-WorkspaceOneLogLevel -LogLevel "Info"

$CurrentTime=(Get-Date)
echo "CurrentTime is $CurrentTime"

$ExtensionPath = "HKLM:\Software\AIRWATCH\Extensions" 

$AppSmartGroup="Intel Users"
$WorkflowProfile=@{}

$TagName="TimeWindow_000"
$TimeWindowStart=13
$TimeWindowEnd=16

$TimeWindowLimit=($TimeWindowStart-$TimeWindowEnd) * 60

While($true){
    $InTimeWindow=(($CurrentTime.Hour -ge $TimeWindowStart) -and ($CurrentTime.Hour -le $TimeWindowEnd))
    
    If($InTimeWindow){
        Write-Host "IN TIME WINDOWS" -ForegroundColor White -BackgroundColor DarkGreen 
        $TimeLeft=($TimeWindowEnd * 60 * 60) - ((($CurrentTime.TimeOfDay.Hours) * 60 * 60) + ($CurrentTime.TimeOfDay.Minutes * 60) + $CurrentTime.TimeOfDay.Seconds)
        Write-Host "TIME LEFT IN MAIN WINDOW: $([Math]::Round($TimeLeft/60,2)) minutes" -ForegroundColor White -BackgroundColor Black
        Sleep -Seconds 2

        If(!$MyApps){
            $MyApps=Get-WorkspaceOneApplicationMetadata -SmartGroupName $AppSmartGroup
            $MyApps=$MyApps | Sort-Object ChangeLog | Sort-Object InstallTimeOutInMinutes -Descending
        }
        
        If(!$CurrentInstall){
            If($MyApps -and (($MyApps | Measure).Count -gt 0)){
                $MyAppsInWindow=$MyApps | Where-Object {$_.InstallTimeoutInMinutes -lt ($TimeLeft / 60)}
                If($MyAppsInWindow -and (($MyAppsInWindow | Measure).Count -gt 0)){
                    If($MyAppsInWindow[0].InstallTimeOutInMinutes){
                        $CurrentInstall=$MyAppsInWindow[0] 
                        Write-Host "Current Install: $($CurrentInstall.applicationName)" -ForegroundColor White -BackgroundColor DarkGreen  
                    }
                }
            }
        } Else{
            If($CurrentInstall.BuildVersion){
                $AppInstallStatus=Test-LocalAppStatus -BuildVersion $CurrentInstall.BuildVersion -Context "System"
                If($AppInstallStatus -eq "True"){
                    $MyAppsInWindow=$MyAppsInWindow | Where-Object {$_.applicationName -ne $CurrentInstall.applicationName}
                    $CurrentInstall=""
                }
            }
        }
        $Result=Set-WSODeviceTag -TagName $TagName -Result $InTimeWindow       
    }Else{
        Write-Host "OUT OF TIME WINDOW" -ForegroundColor White -BackgroundColor DarkRed
    }
    break;
    Sleep -Seconds $Interval
}