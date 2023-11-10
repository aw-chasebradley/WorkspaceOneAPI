$GitRepoPath="C:\Users\chase\Documents\GitHub\WorkspaceOneAPI"
$WorkingFolderPath="C:\WS1"
$PowerShellModulePath="C:\Windows\System32\WindowsPowerShell\v1.0\Modules"

$Module=Import-Module WorkspaceOneAPIEngine -PassThru -Force

$RootFolders=@("$WorkingFolderPath\WorkspaceOneAPI","$WorkingFolderPath\HubNotify","$WorkingFolderPath\Installer","$WorkingFolderPath\SampleScripts","$PowerShellModulePath\WorkspaceOneAPIEngine")
$BuildDestination="C:\Users\chase\Desktop\WorkspaceOneAPI_$($Module.Version.ToString())\WorkspaceOneAPI"



    foreach($RootFolder in $RootFolders){
        $MyFiles=Get-ChildItem -Path $RootFolder -Recurse -Filter "*.ps*"
        foreach($File in $MyFiles){
            If($File.DirectoryName -Like "$WorkingFolderPath`*"){
                $SubDirectory = $File.DirectoryName.Replace("$WorkingFolderPath\","")
            }ElseIf($File.DirectoryName -Like "$PowerShellModulePath`*"){
                $SubDirectory = $File.DirectoryName.Replace("$PowerShellModulePath\","")
            }
            If(!(Test-Path "$BuildDestination\$SubDirectory")){
                New-Item "$BuildDestination\$SubDirectory" -ItemType Directory -Force
            }

            Copy-Item -Path $File.FullName -Destination "$BuildDestination\$SubDirectory\$($File.Name)" -Force
        }
    }



