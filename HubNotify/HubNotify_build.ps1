cd "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\HubNotify"
$manifest = @{
    Path              = '.\HubNotify.psd1'
    RootModule        = 'HubNotify.psm1' 
    Author            = 'Chase Bradley'
}
New-ModuleManifest @manifest