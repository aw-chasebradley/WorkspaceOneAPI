$current_path = $PSScriTptRoot;
if(!$current_path){
    $current_path=Get-ItemProperty "HKLM:\Software\AIRWATCH\Extensions" | Select-Object "SharedPath" -ExpandProperty "SharedPath" -ErrorAction SilentlyContinue
    #Hack for testing
    $current_path="$current_path/Lib"
}


Function Set-LocalData{
    #Authenticate current logged in user
    [Windows.System.User]::GetDefault()
    #[System.DirectoryServices.DirectoryEntry]::new()

}

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

Function Set-DeviceManagementSID{
    param([string]$UserSID, [string]$UserUPN)
    #Set the HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\Common\{00000000-0000-0000-0000-000000000000}.TargetedUserSID key to the CurrentUsers's SID
    $CommonKey ="HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\Common\{00000000-0000-0000-0000-000000000000}"
    $Commonvalue = Get-ItemProperty -Path $CommonKey -ErrorAction SilentlyContinue | Select-Object TargetedUserSID -ExpandProperty TargetUserSID -ErrorAction SilentlyContinue
    If($Commonvalue){
        $RegistryResult=Set-ItemProperty -Path $CommonKey -name TargetedUserSID -Value $UserSID -Force
    }
            
    $AccountIDKey ="HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\Common\{00000000-0000-0000-0000-000000000000}"
    $AccountIDvalue = Get-ItemProperty -Path $AccountIDKey -ErrorAction SilentlyContinue | Select-Object AccountID -ExpandProperty AccountID -ErrorAction SilentlyContinue
    If($AccountIDvalue){
        $EnrollmentsKey = "HKLM:\SOFTWARE\Microsoft\Enrollments\"
        $SIDkey = ($EnrollmentsKey + $AccountIDvalue)
        $SIDvalue = Get-ItemProperty -Path $SIDkey -ErrorAction SilentlyContinue | Select-Object SID -ExpandProperty SID -ErrorAction SilentlyContinue
        $UPNvalue = Get-ItemProperty -Path $SIDkey -ErrorAction UPN | Select-Object UPN -ExpandProperty UPN -ErrorAction SilentlyContinue
    }
    if($SIDvalue) {
        Set-ItemProperty $SIDkey -name SID -Value $UserSID
        Set-ItemProperty $SIDkey -name UPN -Value $UserUPN
    }
} 


<#
.AUTHOR
cbradley@vmware.com
.SYNOPSIS
Gets the user based on the SID
.DESCRIPTION
Gets the username based on the SID for group management functions.
.PARAMETER SID 
A string of the SID
.PARAMETER ignoreGroup 
#>
function Get-ReverseSID{
    Param([string]$SID,[bool]$ignoreGroups=$true)
    Try{      
        $domainJoined = $false;
        $localmachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
        $domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain;
        $domainJoined = (Get-CimInstance -Class CIM_ComputerSystem).PartOfDomain
        if($domainJoined){
            $domain = $localmachine;
        }

        $newSID = Get-WmiObject -Class Win32_UserAccount -Filter ("SID='" + $SID + "'") -ErrorAction Stop;
        if(($newSID | Measure).Count -eq 0 -and $ignoreGroups){
            return "Error:: User not found"
        } elseif (($newSID | Measure).Count -eq 0 -and !$ignoreGroups){
            $newSID = Get-WmiObject -Class Win32_Group -Filter ("SID='" + $SID + "'") -ErrorAction Stop;
        }

        if($newSID){     
            if($domain.ToLower().Contains($newSID.domain.ToLower())){
                #Local user, just return the username
                return $newSID.Name;
            } else {
                #Domain user, just return the username
                return $newSID.Caption;
            }
        }
    } Catch {
        $ErrorMessage = $_.Exception.Message;
        return ("Error:: " + $ErrorMessage);
    }
}



Function Get-UserGroup{
    param([string]$Name,[string]$Domain)
    
    $LocalMachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
    If($Name -match "([^\\]*)\\(.*)"){
        If($Matches[1] -eq "." -or $Matches[1] -eq "local"){
            $Group = Get-WmiObject -Class Win32_Group | Where {$_.Name -eq $Name -and $_.Domain -eq $LocalMachine};
        } Else{
            $Group = Get-WmiObject -Class Win32_Group | Where {$_.Name -eq $Name -and $_.Domain -eq $Matches[2]};
        }
    } ElseIf($Name -match "[^\\]*"){
        If($Domain){
            $Group = Get-WmiObject -Class Win32_Group | Where {$_.Name -eq $Name -and $_.Domain -eq $Domain};
        } Else {
            $Group = Get-WmiObject -Class Win32_Group | Where {$_.Name -eq $Name -and $_.Domain -eq $LocalMachine};
        }
    }
    return $Group;
}


Function Get-GroupMembershipStatus{
    param([string]$Username, [string]$UserDomain, [string]$Group, [string]$GroupDomain)

    $LocalMachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
    if(!$GroupDomain){
        $GroupDomain = $LocalMachine;
    } elseif($GroupDomain -eq "local"){
        $GroupDomain = $LocalMachine;
    }

    if(!$UserDomain){
        $UserDomain = $LocalMachine;
    } elseif($UserDomain -eq "local"){
        $UserDomain = $LocalMachine;
    }
    $GroupLookup = (Get-CimInstance "Win32_GroupUser") | where {$_.GroupComponent.Name -EQ $Group};
    $GroupCount = (($GroupLookup | Select-Object {$_.GroupComponent.Name}, {$_.GroupComponent.Domain} -Unique) | Measure);
    if($GroupCount.Count -gt 1){
        $GroupLookup = $GroupLookup | where {$_.GroupComponent.Domain -eq "GroupDomain"};
        $GroupCount = (($GroupLookup | Select-Object {$_.GroupComponent.Name}, {$_.GroupComponent.Domain} -Unique) | Measure);
    }
    if($GroupCount.Count -eq 1){
        $UserLookup = $GroupLookup | where {$_.PartComponent.Name -EQ $Username -and $_.PartComponent.Domain -EQ $UserDomain}
        if($UserLookup){
            return $true;
        }
    }
    return $false;
}

Function Get-AllKnownUsers{
     $ExceptionUsers = @("$LocalMachine\DefaultAccount","$LocalMachine\Administrator")
     $AllUsers = (Get-CimInstance "Win32_GroupUser") | Select-Object @{Name="Name";Expression={$_.PartComponent.Name}},
            @{Name="Domain";Expression={$_.PartComponent.Domain}},
            @{Name="FullName";Expression={$_.PartComponent.Domain + "\" + $_.PartComponent.Name}},
            @{Name="AccountType";Expression={ If($_.PartComponent.ToString() -match "([^\(]*)\(.*"){ $Matches[1].Trim()  }}} -Unique |
            Where {$_.AccountType -like "Win32_UserAccount" -and $_.Username -notin $ExceptionUsers};
     return $AllUsers;
}


Function Get-UsersInGroup{
    param([string]$Group, [string]$GroupDomain, [array]$Users,
         [ValidateSet("IN","NOTIN")]       
         [string]$SearchType="IN")

    $LocalMachine = (Get-WmiObject -Class Win32_ComputerSystem).Name;
    if(!$GroupDomain){
        $GroupDomain = $LocalMachine;
    } elseif($GroupDomain -eq "local"){
        $GroupDomain = $LocalMachine;
    }

    $GroupLookup = (Get-CimInstance "Win32_GroupUser") | where {$_.GroupComponent.Name -EQ $Group};   
    $GroupCount = (($GroupLookup | Select-Object {$_.GroupComponent.Name}, {$_.GroupComponent.Domain} -Unique) | Measure);
    if($GroupCount.Count -gt 1){
        $GroupLookup = $GroupLookup | where {$_.GroupComponent.Domain -eq "GroupDomain"};
        $GroupCount = (($GroupLookup | Select-Object {$_.GroupComponent.Name}, {$_.GroupComponent.Domain} -Unique) | Measure);
    }
    $UserList = $Users;
    if($GroupCount.Count -eq 1){
        $GroupUserList = $GroupLookup | select @{Name="FullName";Expression={$_.PartComponent.Domain + "\" + $_.PartComponent.Name}},
            @{Name="AccountType";Expression={ If($_.PartComponent.ToString() -match "([^\(]*)\(.*"){ $Matches[1].Trim()  }}} |
            Where {$_.AccountType -like "Win32_UserAccount"};
       
        If($SearchType -EQ "NOTIN"){
            $UserList = $Users | Where {$_.FullName -notin ($GroupUserList | select FullName).FullName};
        } Else{
            $UserList = $Users | Where {$_.FullName -in ($GroupUserList | select FullName).FullName};
        }
        
        return $UserList;
    }
    If($SearchType -EQ "IN"){
       $UserList = @(); 
    }
    return $UsersList;
}


function Get-UserSIDLookup{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$UsernameLookup
    )
        If($usernameLookup -eq "(current_user)" -or $UsernameLookup -eq ""){
            $usernameLookup = Get-CurrentLoggedonUser
        } 
        
        If($usernameLookup.Contains("\")){
            $usernameLookup = $usernameLookup.Split("\")[1];
        } Elseif ($usernameLookup.Contains("@")){
            $usernameLookup = $usernameLookup.Split("@")[0];
        }
        $User = New-Object System.Security.Principal.NTAccount($usernameLookup)
        Try{
            $sid = $User.Translate([System.Security.Principal.SecurityIdentifier]).value;
            return $sid;
        } Catch{
            $ErrorMessage = $_.Exception.Message;
            return ("Error:: " + $ErrorMessage);
        }
    
}

<#
.AUTHOR
cbradley@vmware.com
.SYNOPSIS
Gets the currently logged in Windows User
.DESCRIPTION
Provides two different built in methods for getting the currently logged in user.  The standard method uses Get-WMIObject to determine
the logged in user.  This method is not compatible with users using remote log in.  In order to allow for remote log in support,
you will need to copy the GetWin32User.cs file into the current directory or include it as part of the installation process.
.OUTPUTS
Returns a custom PS object that has the following attributes
    Username - user1
    Domain - domain.com
    FullName - domain.com\user1 or user1@domain.com
#>
function Get-CurrentLoggedonWindowsUser{
    #Check to see if GetWin32User.cs exists at the current location
    If(Test-Path "$current_path\GetWin32User.cs"){
        Try{
            Unblock-File "$current_path\GetWin32User.cs"
            if (-not ([Management.Automation.PSTypeName]'AWDeviceInventory.QueryUser').Type) {
                        [string[]]$ReferencedAssemblies = 'System.Drawing', 'System.Windows.Forms', 'System.DirectoryServices'
                        Add-Type -Path "$current_path\GetWin32User.cs" -ReferencedAssemblies $ReferencedAssemblies -IgnoreWarnings -ErrorAction 'Stop'
            }
            $usernameLookup = [AWDeviceInventory.QueryUser]::GetUserSessionInfo("$env:ComputerName");
            $usernameLookup = $usernameLookup | where {$_.IsCurrentSession} | select @{N='Username';E={$_.NTAccount}};
        } Catch {
            
        }
    } 
    #If Username lookup has not been processed, use Get-WMIOBject to return the user.
    If(!($usernameLookup)){
        $usernameLookup = Get-WMIObject -class Win32_ComputerSystem | select username;
    }
    if($usernameLookup){
        $usernameLookup = $usernameLookup.username;
    }
    #Uses regex
    if($usernameLookup -match "([^\\]*)\\(.*)"){
        $usernameProp = @{"Username"=$Matches[2];"Domain"=$Matches[1];"FullName"=$Matches[0]}
        $usernameLookup = New-Object -TypeName PSCustomObject -Property $usernameProp;
    } elseif($usernameLookup -match "([^@]*)@(.*)"){
        $usernameProp = @{"Username"=$Matches[1];"Domain"=$Matches[2];"Fullname"=$Matches[0]}
        $usernameLookup = New-Object -TypeName PSCustomObject -Property $usernameProp;
    }         
    return $usernameLookup;
}