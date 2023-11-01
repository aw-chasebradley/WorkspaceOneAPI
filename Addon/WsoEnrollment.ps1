    
    EnterpriseWipeCallback([int]$timeout=300,[int]$interval=5){
        $LOGPOS="[WorkspaceOneAPISession.EnterpriseWipeCallback]"
        $myDeviceId = $this.GetDeviceID()     
        while($timeout -gt 0){
            Write-Log2 -Path $Global:logLocation -Message ("$LOGPOS::Checking EnrollmentStatus to test if " + 
                "Enterprise Wipe is completed.  Timeout is '$timeout s', with interval of '$interval s'.") -Level Info
            $Response = $this.GetResponse("api/mdm/devices/$myDeviceId/", 1, "GET", "")
            If($Response){
                If($Response.EnrollmentStatus -eq "Unenrolled"){
                    Write-Log2 -Location $Global:logLocation -Message "$LOGPOS::EnrollmentStatus is Unenrolled, returning True." -Level Info
                    return $true;
                }
            }
            $timeout=$timeout-$interval;          
            #Implemented to prevent last sleep/log
            Write-Log2 -Path $Global:logLocation -Message "$LOGPOS::EnrollmentStatus is still Enrolled, waiting for $interval s" -Level Info
            Start-Sleep -Seconds $interval              
        }
        Write-Log2 -Path $Global:logLocation -Message "$LOGPOS::EnrollmentStatus is still Enrolled.  Timeout limit reached, returning False." -Level Warn
        return $false;
    }