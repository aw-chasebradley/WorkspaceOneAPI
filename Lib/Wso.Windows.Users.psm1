$current_path = $PSScriTptRoot;
if(!$current_path){
    $current_path=Get-ItemProperty "HKLM:\Software\AIRWATCH\Extensions" | Select-Object "SharedPath" -ExpandProperty "SharedPath" -ErrorAction SilentlyContinue
    #Hack for testing
    $current_path="$current_path/Lib"
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

