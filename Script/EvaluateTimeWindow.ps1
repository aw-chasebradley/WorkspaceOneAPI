param([string]$LogLevel)



$WorkspaceOneModulePath="C:\Ws1\WorkspaceOneAPI"
$AddTagModulePath="C:\Ws1\WorkspaceOneAPI\Addon"
Unblock-File -Path "$AddTagModulePath\Wso.API.Tags.psm1"
$module = Import-Module "$AddTagModulePath\Wso.API.Tags.psm1" -ErrorAction Stop -PassThru -Force;
Unblock-File -Path "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1"
$module = Import-Module "$WorkspaceOneModulePath\WorkspaceOneAPI.psm1" -ErrorAction Stop -PassThru -Force;

$CurrentTime=(Get-Date)
echo "CurrentTime is $CurrentTime"

$ExtensionPath = "HKLM:\Software\AIRWATCH\Extensions" 

$TagName="TimeWindow_000"

$TimeWindowStart=12
$TimeWindowEnd=13

$InTimeWindow=(($CurrentTime.Hour -ge $TimeWindowStart) -and ($CurrentTime.Hour -le $TimeWindowEnd))

If(!$InTimeWindow){
    echo "Out of time window"
}Else{
    echo "In time window"
}

#Set-WSODeviceTag -TagName $TagName -Result $InTimeWindow -CreateTag 

$ApiSession=New-WorkspaceOneAPISession -UseLocal
$SmartGroupEndpoint="api/mdm/devices/1703634/smartgroups"

$OrganizationGroupResult=Get-OrganizationGroup 
$OrganizationGroupUuid=$OrganizationGroupResult.Uuid


$GetWorkflowEndpoint="api/mdm/workflows?organization_group_uuid=$OrganizationGroupUuid"
$WorkflowResult=$ApiSession.Get($GetWorkflowEndpoint,"2")

foreach($result in $WorkflowResult.results){
    If($result.name -like "*Window*"){
        $WorkflowUUID=$result.workflow_uuid
        $GetWorkflowEndpoint="api/mdm/workflows/$WorkflowUUID"
        $WorkflowResult=$ApiSession.Get($GetWorkflowEndpoint,"2")
        foreach($Entity in $WorkflowResult.workflow_entities){
            $GetWorkflowEntityEndpoint="api/mdm/workflows/$($Entity.entitytype)/search/$($Entity.entityuuid)"
            $EntityEndpoint=$ApiSession.Get($GetWorkflowEntityEndpoint,"2")
            echo $EntityEndpoint
        }
        #echo $WorkflowResult
    }
}

<#$CurrentDeviceSmartGroups=$ApiSesssion.GetResponse("$SmartGroupEndpoint","1","GET","")
ForEach($SmartGoup in $CurrentDeviceSmartGroups.SmartGroups){
    
}#>