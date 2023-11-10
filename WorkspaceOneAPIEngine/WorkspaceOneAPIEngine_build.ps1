Write-Host -ForegroundColor White -Object "Begin: WorkspaceOneAPIEngine_Build" | Out-Null
cd "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\WorkspaceOneAPIEngine"

$ModulePath="$PSScriptRoot\WorkspaceOneAPIEngine"
$ModuleName="WorkspaceOneAPIEngine"

Unblock-File "$ModulePath.psm1"
#Import-Module $ModulePath -ErrorAction Continue -PassThru -Force
$ModuleResult=Import-Module "$ModulePath.psd1" -ErrorAction SilentlyContinue -PassThru -Force
If(!($ModuleResult)){
    $ModuleResult=Import-Module "$ModulePath.psm1" -ErrorAction Stop -PassThru -Force
}

If(!($ModuleResult)){
    Throw "An, error has coccured.  Could not import module."
}

$ImportedModule=Get-Module -Name $ModuleName -ErrorAction SilentlyContinue
$ModuleBuildNum=0
$ModuleVersion=$ImportedModule.Version
If($ModuleVersion){
    $ModuleBuildVersion=$ModuleVersion.Major
    $ModuleBuildNum=$ModuleVersion.Minor
    Write-Host -ForegroundColor White -Object "Old version: $ModuleBuildVersion.$ModuleBuildNum" | Out-Null
}

$CreateNewManifest=$false
$File=Get-ChildItem -Path "$ModulePath.psm1"
$ModuleLastUpdate=$File.LastWriteTime.Date.ToString("yyMMdd")
If($ModuleVersion){
    If(([int]::Parse($ModuleLastUpdate) -eq [int]::Parse($ModuleBuildVersion))){
        $ModuleBuildNum=$ModuleBuildNum+1
        $CreateNewManifest=$true
    }ElseIf(([int]::Parse($ModuleLastUpdate) -gt [int]::Parse($ModuleBuildVersion))){
        $ModuleBuildVersion=$ModuleLastUpdate
        $CreateNewManifest=$true
    }
} Else{
    $ModuleBuildVersion=$ModuleLastUpdate
    $CreateNewManifest=$true
}
Write-Host -ForegroundColor White -Object "Building version: $ModuleBuildVersion.$ModuleBuildNum" | Out-Null
$manifest = @{
    Path              = '.\WorkspaceOneAPIEngine.psd1'
    RootModule        = 'WorkspaceOneAPIEngine.psm1' 
    Author            = 'Chase Bradley'
    FunctionsToExport = @($ImportedModule.ExportedFunctions.Keys)
    AliasesToExport     = @($ImportedModule.ExportedAliases.Keys)
    ModuleVersion     = "$ModuleBuildVersion.$ModuleBuildNum"
}
Remove-Item $PSScriptRoot\WorkspaceOneApiEngine.psd1 -ErrorAction SilentlyContinue -Force | Out-Null
New-ModuleManifest @manifest

If(Test-Path "$ModulePath`.psd1"){
    Write-Host -ForegroundColor White -Object "End: WorkspaceOneEngine build success." | Out-Null
}