cd $PSScriptRoot;

$Modules=@{"WorkspaceOneApi"="$PSScriptRoot\WorkspaceOneAPI";
            "Wso.Cache"="$PSScriptRoot\Lib\Wso.Cache";
            "Wso.CommonLib"="$PSScriptRoot\Lib\Wso.CommonLib";
            "Wso.Logging"="$PSScriptRoot\Lib\Wso.Logging"

}


ForEach($ModuleName in $Modules.Keys){
    $ModulePath=$Modules[$ModuleName]

    Unblock-File "$ModulePath.psm1"
    #Import-Module $ModulePath -ErrorAction Continue -PassThru -Force
    Import-Module "$ModulePath.psd1" -ErrorAction Continue -PassThru -Force
    $ImportedModule=Get-Module -Name $ModuleName -ErrorAction SilentlyContinue

    $ModuleBuildNum=0

    $ModuleVersion=$ImportedModule.Version
    If($ModuleVersion){
        $ModuleBuildVersion=$ModuleVersion.Major
        $ModuleBuildNum=$ModuleVersion.Minor
    }

    $CreateNewManifest=$false
    $File=Get-ChildItem -Path "$ModulePath.psm1"
    $ModuleLastUpdate=$File.LastWriteTime.Date.ToString("yyMMdd")
    If($ModuleVersion){
        If(([int]::Parse($ModuleLastUpdate) -eq $ModuleVersion)){
            $ModuleBuildNum=$ModuleBuildNum++
            $CreateNewManifest=$true
        }ElseIf(([int]::Parse($ModuleLastUpdate) -gt [int]::Parse($ModuleBuildVersion))){
            $ModuleBuildVersion=$ModuleLastUpdate
            $CreateNewManifest=$true
        }
    } Else{
       $ModuleBuildVersion=$ModuleLastUpdate
       $CreateNewManifest=$true
    }

    #Unit test module
    If(Test-Path "$ModulePath`.Test.ps1"){
        $Result=Invoke-Expression -Command "$ModulePath`.Test.ps1"
        If($Result -ne "0"){
            continue;
        }
    }


    If($CreateNewManifest){
        $manifest = @{
            Path              = "$ModulePath.psd1"
            RootModule        = "$ModulePath.psm1" 
            Author            = 'Chase Bradley'
            ModuleVersion     = "$ModuleBuildVersion.$ModuleBuildNum"
        }
        <#Switch($ModuleName){
        }#>
        $WsoAPIBuildNum++
        New-ModuleManifest @manifest
    }
}


