Function Test-MSDeviceManagement{
    #$CurrentUser=Get-CurrentLoggedonWindowsUser
    $usernameLookup = Get-WMIObject -class Win32_ComputerSystem | select username;
    if($usernameLookup -match "([^\\]*)\\(.*)"){
        $UserProperty = @{"Username"=$Matches[2];"Domain"=$Matches[1];"FullName"=$Matches[0];"Upn"="$($Matches[2])@$($Matches[1])"}
    } elseif($usernameLookup -match "([^@]*)@(.*)"){
        $UserProperty = @{"Username"=$Matches[1];"Domain"=$Matches[2];"Fullname"=$Matches[0];"Upn"="$Fullname"};
    } else{
        Throw "Error, could not retrieve username."
    }
    $usernameLookup = New-Object -TypeName PSCustomObject -Property $UserProperty
    $CurrentUserUpn=$usernameLookup.Upn
    #$CurrentUserSID=Get-UserSIDLookup
    $User = New-Object System.Security.Principal.NTAccount($usernameLookup.Username)
    $CurrentUserSID = $User.Translate([System.Security.Principal.SecurityIdentifier]).value;
    If(!($CurrentUserSID)){
        Throw "Error, could not retrieve user SID."
    }
   
    
    $WorkspaceOneAppDeploymentPath ="HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\Common\{00000000-0000-0000-0000-000000000000}"
    $WorkspaceOneAppDeploymentKey=Get-ItemProperty -Path $WorkspaceOneAppDeploymentPath -ErrorAction SilentlyContinue
    If(!$WorkspaceOneAppDeployment){
        Throw "Error, SFD agent not installed correctly."
    }

    $AppDeployTargetUserSID = $WorkspaceOneAppDeploymentKey | Select-Object TargetedUserSID -ExpandProperty TargetUserSID -ErrorAction SilentlyContinue
    $AppDeployAccountKey = $WorkspaceOneAppDeploymentKey | Select-Object AccountID -ExpandProperty AccountID -ErrorAction SilentlyContinue
    If([string]::IsNullOrEmpty($AppDeployTargetUserSID) -or [string]::IsNullOrEmpty($AppDeployAccountKey)){
        return $false
    }Elseif(($AppDeployTargetUserSID -ne $CurrentUserSID)){
        return $false
    }
    

    $MSEnrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$AppDeployAccountKey"
    $MSEnrollmentKey = Get-ItemProperty -Path $MSEnrollmentPath -ErrorAction SilentlyContinue
    If(!($MSEnrollmentKey)){
        Throw "Error, device is currently not enrolled correctly."
    }

    $MSEnrollmentSID = $MSEnrollmentKey | Select-Object SID -ExpandProperty SID -ErrorAction SilentlyContinue
    $MSEnrollmentUPN = $MSEnrollmentKey | Select-Object UPN -ExpandProperty UPN -ErrorAction SilentlyContinue
    If([string]::IsNullOrEmpty($MSEnrollmentSID) -or [string]::IsNullOrEmpty($MSEnrollmentUPN)){
        Throw "Error, device did not complete MS registration."
    }ElseIf(($MSEnrollmentUPN -ne $CurrentUserUpn) -or ($MSEnrollmentSID -ne $CurrentUserSID)){
        #Example for resolving this mis-match
        #Set-ItemProperty $SIDkey -name SID -Value $UserSID | Out-Null
        #Set-ItemProperty $SIDkey -name UPN -Value $UserUPN | Out-Null
        return $false
    }
    return $true
}