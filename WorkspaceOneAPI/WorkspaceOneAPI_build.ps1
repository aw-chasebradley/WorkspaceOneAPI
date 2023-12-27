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
    $ImportModuleCheck=Import-Module "$ModulePath.psd1" -ErrorAction Continue -PassThru -Force
    If(!$ImportModuleCheck){
        $ImportModuleCheck=Import-Module "$ModulePath.psm1" -ErrorAction Stop -PassThru -Force
    }
    $ImportedModule=Get-Module -Name $ModuleName -ErrorAction SilentlyContinue

    If(($ImportedModule | Measure).Count -gt 1){
        $ImportedModule = $ImportedModule | Where-Object Path -Like "$ModulePath.psm1"
    }

    If(!$ImportedModule){
        Throw "Invalid module"
    }

    $ModuleBuildNum=0
    $ModuleBuildMinor="00"

    $ModuleVersion=$ImportedModule.Version
    If($ModuleVersion.Major -gt 0){
        $ModuleBuildVersion=$ModuleVersion.Major
        $ModuleBuildMinor=$ModuleVersion.Minor
        If($ModuleBuildMinor -lt 10){
            $ModuleBuildMinor="0$ModuleBuildMinor"
        }
        $ModuleBuildNum=$ModuleVersion.Build
    }

    $CreateNewManifest=$false
    $File=Get-ChildItem -Path "$ModulePath.psm1"
    $ModuleLastUpdate=$File.LastWriteTime.Date.ToString("yyMMdd")
    If($ModuleVersion){ 
        If(([int]::Parse($ModuleLastUpdate) -eq [int]::Parse("$ModuleBuildVersion$ModuleBuildMinor"))){
            $ModuleBuildNum=$ModuleBuildNum++
            $CreateNewManifest=$true
        }ElseIf(([int]::Parse($ModuleLastUpdate) -gt [int]::Parse("$ModuleBuildVersion$ModuleBuildMinor"))){
            $ModuleBuildVersion=$File.LastWriteTime.Date.ToString("yyMM")
            $ModuleBuildMinor=$File.LastWriteTime.Date.ToString("dd")
            $CreateNewManifest=$true
        }
    } Else{
       $ModuleBuildVersion=$ModuleLastUpdate
       $CreateNewManifest=$true
    }

    #Unit test module
    <#If(Test-Path "$ModulePath`.Test.ps1"){
        $Result=Invoke-Expression -Command "$ModulePath`.Test.ps1"
        If($Result -ne "0"){
            continue;
        }
    }#>


    If($CreateNewManifest){
        $manifest = @{
            Path              = "$ModulePath.psd1"
            RootModule        = "$ModuleName.psm1" 
            Author            = 'Chase Bradley'
            ModuleVersion     = "$ModuleBuildVersion.$ModuleBuildMinor.$ModuleBuildNum"
        }
        <#Switch($ModuleName){
        }#>
        $WsoAPIBuildNum++
        New-ModuleManifest @manifest
    }
}


