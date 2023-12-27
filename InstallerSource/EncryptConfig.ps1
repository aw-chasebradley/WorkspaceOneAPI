$current_path=$PSScriptRoot
If(!($current_path)){
    Throw "An error has occured.  Run whole script or change 'current_path' to working directory."
    return
}
$ApiSettings=@{'Server'="https://asXXXX.awmdm.com";
            'Username'='Username';
            'Password'='Password';
            'ApiKey'='ApiKey';
            'SslThumbprint'='6A874FA9CFD46EC6F0DAE0039D710B20196EDB75';
            'OrganizationGroupId'=570
            }

If($ApiSettings.ContainsKey('Username') -and $ApiSettings.ContainsKey('Password')){
    $UTFEncoded=[System.Text.Encoding]::UTF8.GetBytes("$($ApiSettings['Username'])`:$($ApiSettings['Password'])")
    $AuthString=[System.Convert]::ToBase64String($UTFEncoded)
    $ApiSettings.Add("BasicAuth","Basic $AuthString")
    $ApiSettings.Remove('Username')
    $ApiSettings.Remove('Password')
}


$ApiSettingsJson="";
Try{
    $ApiSettingsJson = ConvertTo-Json $ApiSettings -Compress
}Catch{
    $err=$_.Exception.Message
    Throw "An error has occured converting ApiSettings to JSON: $err"
    return
}
 
$KeyFile = "$current_path\AES.key"
$Key = New-Object Byte[] 32   # You can use 16, 24, or 32 for AES
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
$Key | out-file $KeyFile

$ApiSettingsEncrypted=ConvertTo-SecureString -String $ApiSettingsJson -AsPlainText -Force
$ApiSettingsEncrypted | ConvertFrom-SecureString -Key $Key | Out-File "$current_path\apisettings.config" -Force