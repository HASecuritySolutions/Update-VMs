param (   
    [switch]$Install,  
    [switch]$RegularPatch,  
    [switch]$OnDemandPatch,  
    [switch]$Audit, 
    [string]$VMName,
    [string]$VMList,
    [string]$KBs, 
    [switch]$Verbose  
)  
#Load PowerCLI Modules  
Get-Module -ListAvailable VMWare* |Import-Module
   
###User-Controlled Variables### 
#BatchSize parameter determines how many systems are patched at once.  This is important in a virtual environment where patching many hosts simultaneously can cause performance issues 
#Set this value to 0 to never batch and just patch all targeted systems at once 
$BatchSize = 20

#Log File locations 
#LogFile contains data on the current beta group being patched 
$LogFile = $PSScriptRoot + "\logs\Windows_Update_Log.csv" 
#PatchLogs contains the results of patching attempts against each Windows system 
$PatchLogs = $PSScriptRoot + "\logs\Windows_Patching_Results.csv"
#ScriptLog contains the output from the script - this file is useful for reviewing output when running as a scheduled task
$ScriptLog = $PSScriptRoot + "\logs\Update-VMs_Logfile.txt"
#VMFile contains the inventory of VMs, which beta groups they belong to, and their last patch status 
$VMFile = $PSScriptRoot + "\Windows_Patching_Systems.csv"  
$VCenter = @("vc01.domain.local","vc02.domain.local")
$DaysToKeepSnapshots = 1 
###End User-Controlled Variables### 
 
#Other globals 
$global:PatchStatus =@()
$global:RunTime = Get-Date  
foreach($vc in $VCenter){
 Connect-VIServer $vc | Out-Null
} 

[int]$hour = Get-Date -format HH  
 
if($Verbose){  
    $oldverbose = $VerbosePreference  
    $VerbosePreference = "continue"  
}  
Function Log_Verbose_Output($out){
    Write-Verbose $out
    $out | Out-File $ScriptLog -Append
}
 
function Take_VCenter_Snapshot($VM){ 
    $SnapshotSuccess = 0  
    try{  
        $VM | New-Snapshot -name Backup_PriorTo_WindowsUpdates  -Description "Created $(Get-Date) prior to Windows Update script running" -ErrorAction Continue |Out-Null 
        $SnapshotSuccess = 1  
        Log_Verbose_Output (get-date -format s) + " VERBOSE: Successfully took snapshot of $VM"
        
    }  
    catch{  
        Log_Verbose_Output (get-date -format s) + " VERBOSE: Unsuccessful with Snapshot. Skipping $VM" 
    }  
    $SnapshotSuccess 
} 
function Clean_Old_Snapshots($VM){ 
     #Check to see if this VM has a custom attribute overriding the "DaysToKeepSnapshots" value  
        try{  
            $SnapshotDays = $VM| Get-Annotation -CustomAttribute "Snapshot - Days to keep" -ErrorAction SilentlyContinue  
            if($SnapshotDays.Value){  
                [int]$DaysToKeepSnapshots = [convert]::ToInt32($SnapshotDays.Value, 10)  
            }  
        }  
        catch{  
            Log_Verbose_Output $((get-date -format s) + " VERBOSE: No custom snapshot days to keep value set. Continuing with default")
        }  
        #Clean up old snapshots  
        try{  
            Get-Snapshot -VM $VM | Foreach-Object {  
                #Only delete snapshots created by this script (based on name) in case others are creating snapshots for other purposes  
                if(($_.Name -eq "Backup_PriorTo_WindowsUpdates") -And ($_.Created -lt (Get-Date).AddDays(-[int]$DaysToKeepSnapshots))) {  
                    Remove-Snapshot $_ -ErrorAction Continue -Confirm:$false -RunAsync
                    Log_Verbose_Output $((get-date -format s) + " VERBOSE: Deleted old snapshot for $VM")
                }  
            }  
        }  
        catch{  
            Log_Verbose_Output $((get-date -format s) + " VERBOSE: Error: Unable to delete Snapshot(s)... $($_.Exception.Message)")
        }     
} 
function Get_VCenter_VMs($VCenter_Server, $VCenter_Target_Folder){     
    $PatchableVMs = @()  
    $AllVMs = @()
    #Get all Windows servers from VCenter  
    if($VCenter_Target_Folder){
        $AllVMs = Get-Folder $VCenter_Target_Folder | Get-VM |Where-Object {$_.Guest.OSFullName -Like "*Windows*"} | Select-Object -Unique 
    }
    else{
        $AllVMs = Get-VM |Where-Object {$_.Guest.OSFullName -Like "*Windows*"} | Select-Object -Unique 
    }
    #trim list to only include systems with patching windows defined  

    foreach($V in $AllVMs){  
       $PatchSchedule = $V| Get-Annotation -CustomAttribute "Patching - Schedule" -ErrorAction SilentlyContinue  
       if($PatchSchedule.Value){  
           $PatchableVMs += $V  
       }  
    }  
    $PatchableVMs      

} 
function Check_Patch_Status($PatchedVMs, $VMHostname){ 
    Log_Verbose_Output $((get-date -format s) + " DEBUG: Got to Check_Patch_Status with VM(s) to check: $PatchedVMs")
    $VMInventory = Import-Csv $VMFile 
    $VMsLeftToCheck = New-Object System.Collections.ArrayList
    $KillJobsTime = $global:RunTime.AddHours(6) 
    $KillJobNow = 0
    $StatusToLog = ""
    $ScriptBlock = { 
        $RetCode = 0 
        #$SchTask = Get-ScheduledTask -TaskName "PSWindowsUpdate" |Select Name, State 
        #^ is easier than the next line if you're only working with 2012R2 servers.  Using schtasks to support older Windows servers 
        $SchTask = (schtasks.exe /query /tn "PSWindowsUpdate") |Out-String 
        if($SchTask){ 
            if($SchTask -match "Running"){ 
                #Return 1 as scheduled task is still running and we can't batch out additional systems 
                $RetCode = 1 
            } 
            elseif($SchTask -match "Ready"){ 
                #Return 0 as scheduled task is complete and we can move onto the next system 
                $RetCode =0 
            } 
        } 
        $RetCode 
    }
    if($PatchedVMs.Count -eq 1){
        $VMsLeftToCheck.Add($PatchedVMs)
    }
    else{
        $VMsLeftToCheck.AddRange($PatchedVMs)    
    }
    while($VMsLeftToCheck.Count -ne 0){                            
        foreach($VM in $PatchedVMs){ 
            if($VMSLeftToCheck -contains $VM){
                $startTime=(Get-Date)
                Log_Verbose_Output $((get-date -format s) + " VERBOSE: Checking Status of $VM")
                $VM = Get-VM $VM
                $View = get-view $VM 
                $VMHostname = $View.Guest.Hostname

                if(-not $VMHostname){ #BUG FIX: Sometimes, if the system goes down for a reboot at the same time we try to get the hostname from VMWare, the View variable doesn't contain a hostname value.  Using the VM inventory as an alternative to look for the hostname we need to ping
                    foreach($v in $VMInventory){
                        if($v.VMName -eq $VM.Name){
                            $VMHostname = $v.Hostname
                        }
                    }
                }
                #Check for end of maintenance window
                $MaintWindow = $VM| Get-Annotation -CustomAttribute "End Maintenance Window" -ErrorAction SilentlyContinue  
                if($MaintWindow.Value){  
                    #Maint window is defined - make sure we're still in it
                    #Assuming maint window is defined as 0600 and defining the end of the maint window
                    try{
                        $WindowHour = $MaintWindow.Value[1].Substring(0,2)  
                        if((Get-Date -format HH) -le $WindowHour){
                            $KillJobNow = 1
                        }
                    }
                    catch{
                        Log_Verbose_Output $((get-date -format s) + " VERBOSE: Maintenance Window not defined in VCenter.")
                    }
                }

                if((Get-Date) -gt $KillJobsTime){ #We're past 6 hours from initial patching start, kill the job
                    Log_Verbose_Output $((get-date -format s) + "Patching has been occurring for more than 6 hours. Killing the job.")
                    $KillJobNow = 1
                }
                try{
                    if($Session = New-PSSession -ComputerName $VMHostname -ErrorAction SilentlyContinue){  
                        if($KillJobNow -eq 1){
                            $null = Invoke-Command -Session $Session -ScriptBlock {$SchTask = (schtasks.exe /End /tn "PSWindowsUpdate") |out-null}
                            $Status=0
                        }
                        else{
                            $Status = Invoke-Command -Session $Session -ScriptBlock $ScriptBlock 
                        }
                        Remove-PSSession $Session 
                    } 
                    else{ 
                        Log_Verbose_Output $((get-date -format s) + " VERBOSE: Can't connect via PSRemoting to $VM. Moving on.")
                        $StatusToLog = "Unable to connect via PS Remoting to check status of system"
                        $Status =0 
                    }
                }
                catch{
                        Log_Verbose_Output $((get-date -format s) + " Something went wrong with PS Remoting to this server.  Considering the patch job complete.")
                        $Status = 0
                }
            
                if($Status -eq 0){ #Done patching this system
                    Log_Verbose_Output $((get-date -format s) + " VERBOSE: Done Patching $VM")
                    $StatusToLog = "Success" 
                    $VMsLeftToCheck.Remove($VM)

                    #Reconcile VMInventory with UpdatedInventory so that we have up to date last-patch times for each system 
                    foreach($old in $VMInventory){ 
                        if($old.VMName -eq $VM.Name){
                            $old.Last_Patched = (Get-Date)
                            $old.Last_Run_Status = $StatusToLog
                        }
                    } 
                    #HealthCheckAnalysis $VM $VMHostname
                }
                else{
                    Write-Verbose (get-date -format s) + " VERBOSE: Patch job still running on $VM - sleeping 5 minutes then checking again"
                    $StatusToLog = "Success" 
          
                    Start-Sleep -Seconds 300
                }
            }
        }   
    
    }
    $VMInventory | Export-Csv $VMFile      
}  
function Check_Outages($PatchedVMs, $VMHostname) {
    $VMInventory = Import-Csv $VMFile 
    $startTime=(Get-Date)
    Log_Verbose_Output $((get-date -format s) + " VERBOSE: Starting to check for outages")
    $deadHosts = New-Object System.Collections.ArrayList
    $allHostsUp = 0 
    $receivedHostname = 0
    if($VMHostname){
        $receivedHostname = 1
    }

    while($allHostsUp -eq 0){
        foreach($VM in $PatchedVMs) {
            if($receivedHostname -eq 0){
                Log_Verbose_Output $((get-date -format s) + " VERBOSE: Checking $VM for outages")
                $VM = Get-VM $VM
                $View = get-view $VM 
                $VMHostname = $View.Guest.Hostname
                Log_Verbose_Output $((get-date -format s) + " VERBOSE: Checking $VM for outages by connecting to $VMHostname")

                if(-not $VMHostname){ #BUG FIX: Sometimes, if the system goes down for a reboot at the same time we try to get the hostname from VMWare, the View variable doesn't contain a hostname value.  Using the VM inventory as an alternative to look for the hostname we need to ping
                    foreach($v in $VMInventory){
                        if($v.VMName -eq $VM.Name){
                            $VMHostname = $v.Hostname
                        }
                    }
                }
            }

            if(-not (Test-Connection -ComputerName $VMHostname -Count 4 -ErrorAction SilentlyContinue)){
                if($deadHosts -notcontains $VM){
                    $deadHosts.add($VM)
                }
                $timespan = NEW-TIMESPAN –Start $startTime –End (Get-Date)
                Log_Verbose_Output $((get-date -format s) + " VERBOSE: Timespan from time we lost connection to VM is $($timespan.Minutes) Minutes, $($timespan.Seconds) Seconds")
                if($($timespan.Hours) -gt 1){
                    Log_Verbose_Output $((get-date -format s) + " VERBOSE: VM has been down for one hour - rolling back to snapshot")
                    #We've been unable to connect to the target system for an hour - roll back to previous snapshot
                    try{ 
                        $snap = Get-Snapshot -VM $VM | Sort-Object -Property Created -Descending | Select -First 1 
                        Set-VM -VM $VM -SnapShot $snap -Confirm:$false |out-null 
                        Start-VM -VM $VM
                        $ErrorMessage = "CRITICAL: Could not connect to $VM for one hour after patching. Rolling back to snapshot." 
                        SendEmail $ErrorMessage 
                        $StatusToLog = "FAILURE: System did not come back. Rolled back to snapshot"
                    } 
                    catch{ 
                    $ErrorMessage = "CRITICAL: Could not connect to $VM for one hour after patching. UNABLE TO ROLL BACK TO SNAPSHOT - THIS SYSTEM IS DOWN." 
                    SendEmail $ErrorMessage 
                        $StatusToLog = "FAILURE: System did not come back. CRITICAL: Failed to roll back to snapshot"
                    }
                     
                    $deadHosts.Remove($VM)
                }
                else{
                    Log_Verbose_Output $((get-date -format s) + " VERBOSE: Can't ping $VM. Will keep trying for 60 minutes from first notice of it being offline.")
                    start-sleep -seconds 300
                }
            }
            else { #We can ping the host - make sure it wasn't down before
                Log_Verbose_Output $((get-date -format s) + " VERBOSE: $VMHostname is alive")

                if($deadHosts -contains $VM){
                    $deadHosts.Remove($VM)
                }
            }
        }
        if($deadHosts.Count -eq 0){
            $AllHostsUp = 1
            Write-Host "All hosts are up. Exiting"
        }
    }

} 
function Patch_Windows_Systems($VMs,$KBs) {  

    $PatchedVMs = @() 
    $ModulePath = "C:\windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate" 
    $numVMs = $VMs.Count  
    Log_Verbose_Output $((get-date -format s) + " VERBOSE: Working on a total of $numVMs VMs")
 
    if($KBs){
        $KBString = $KBs -join "\,"
        write-verbose "VERBOSE: Specific patches requested.  Only applying these"
        $ScriptCMD = "Import-Module $ModulePath\PSWindowsUpdate.psm1; get-wuinstall -KBArticleID $KBString -AcceptAll -AutoReboot"
    }
    else{
        $ScriptCMD = "Import-Module $ModulePath\PSWindowsUpdate.psm1; get-wuinstall -NotCategory 'Language packs' -AcceptAll -AutoReboot"
                  
    }
    #Process each running VM in the list  
    foreach($VM in $VMs){  
        $VM = Get-VM $VM 
        $View = get-view $VM  
        $Hostname = $View.Guest.Hostname 
         
        #Test connectivity to VM. If we can connect, install updates  
        if($Hostname -And (Test-WSMan -ComputerName $Hostname -ErrorAction SilentlyContinue)){  
            #First, Snapshot VM in case updates cause issues  
            $SnapshotSuccess = Take_VCenter_Snapshot $VM 
            if($SnapshotSuccess -eq 1){ 

                #Invoke-WUInstall doesn't natively support other creds so re-inventing the wheel by copying relevant portions into scriptblock  
                $UpdateScript = {  
                        param($Computer, $ScriptCMD)  
                        $User = [Security.Principal.WindowsIdentity]::GetCurrent()  
                        [String]$TaskName = "PSWindowsUpdate"  
                        
                        Write-Verbose "Create schedule service object"  
                        $Scheduler = New-Object -ComObject Schedule.Service  
      
                        $Task = $Scheduler.NewTask(0)  
                        $RegistrationInfo = $Task.RegistrationInfo  
                        $RegistrationInfo.Description = $TaskName  
                        $RegistrationInfo.Author = $User.Name  
      
                        $Settings = $Task.Settings  
                        $Settings.Enabled = $True  
                        $Settings.StartWhenAvailable = $True  
                        $Settings.Hidden = $False  
                        $Action = $Task.Actions.Create(0)  
                        $Action.Path = "powershell"  
                        $Action.Arguments = "-Command $ScriptCMD"  
                        $Task.Principal.RunLevel = 1   
  
                        $Scheduler.Connect($Computer)  
    
                        $RootFolder = $Scheduler.GetFolder("\")  
                        $SendFlag = 1  
  
                        if($Scheduler.GetRunningTasks(0) | Where-Object {$_.Name -eq $TaskName}){  
                            write-Verbose "Updates already running on this system"  
                        }  
                        try{  
                            $RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | out-null  
                       $RootFolder.GetTask($TaskName).Run(0) | out-null  
                        }  
                        catch{  
                            Write-Verbose "Can't create scheduled task"  
                            continue  
                        }  
                    }  
                #Start remoting session with the target system  
                if($Session = New-PSSession -ComputerName $Hostname -ErrorAction SilentlyContinue){  
                    #Check for PSWindowsUpdate Module  
                    if(Invoke-Command -ScriptBlock {-not (Test-Path "C:\windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate") } -Session $Session){  
                        try{  
                                #If it doesn't exist, create the directory               
                            Invoke-Command -Session $Session {New-Item $ModulePath -Type directory} -ErrorAction Continue  
                            Log_Verbose_Output $((get-date -format s) + " VERBOSE: Didn't find PSWindows Update module on $Hostname - Copying it over")
             
                            #Copy module files over to target system  
                            Copy-Item -Recurse -Path $ModulePath -Destination $ModulePath -ToSession $Session -ErrorAction Continue  
                        }  
                        catch{  
                            "$(Get-Date),$VM,Failure,Couldn't copy files to target" | Out-File -FilePath $PatchLogs -Append  
                        }  
                    }  
  
                    #Install updates (creates scheduled task that runs immediately on target system to run get-wuinstall)  
                    try{  
                        Invoke-Command -Session $Session -ScriptBlock $UpdateScript -ArgumentList $Hostname,$ScriptCMD -ErrorAction Continue  
                        Log_Verbose_Output $((get-date -format s) + " VERBOSE: Successfully started patching job on $VM")

                        $PatchStatusRow = [pscustomobject]@{ Date = $(Get-Date) ; VMName = $VM.Name ; Status = "Success" ; Details = "Patching Started" } 
                        "$(Get-Date),$VM,Success,Patching Started" | Out-File -FilePath $PatchLogs -Append  
                        $PatchedVMs += $VM 
                    }  
                    Catch{  
                        Log_Verbose_Output $((get-date -format s) + " VERBOSE: ERROR: Couldn't create scheduled task on $VM")
                        $PatchStatusRow = [pscustomobject]@{ Date = $(Get-Date) ; VMName = $VM.Name ; Status = "Failure" ; Details = "Couldn't create scheduled task" } 
                        "$(Get-Date),$VM,Failure,Couldn't create scheduled task" | Out-File -FilePath $PatchLogs -Append  
                    }  
                    Remove-PSSession $Session 
                }  
                else{  
                    Log_Verbose_Output $((get-date -format s) + " VERBOSE: ERROR: Couldn't connect via PS Remoting on $VM")
                    $PatchStatusRow = [pscustomobject]@{ Date = $(Get-Date) ; VMName = $VM.Name ; Status = "Failure" ; Details = "Couldn't connect via PS Remoting" }  
                    "$(Get-Date),$VM,Failure,Couldn't connect via PS Remoting" | Out-File -FilePath $PatchLogs -Append           
                }  
            }  
            else{  
                Log_Verbose_Output $((get-date -format s) + " VERBOSE: ERROR: Couldn't create snapshot of $VM")
                $PatchStatusRow = [pscustomobject]@{ Date = $(Get-Date) ; VMName = $VM.Name ; Status = "Failure" ; Details = "Couldn't create snapshot" } 
                "$(Get-Date),$VM,Skip,Couldn't create snapshot" | Out-File -FilePath $PatchLogs -Append  
            } 
        } 
        else{ 
            Log_Verbose_Output $((get-date -format s) + " VERBOSE: ERROR: Couldn't connect to hostname of $VM")
            $PatchStatusRow = [pscustomobject]@{ Date = $(Get-Date) ; VMName = $VM.Name ; Status = "Failure" ; Details = "Couldn't connect to hostname" }  
            "$(Get-Date),$VM,Failure,Couldn't connect to hostname of VM" | Out-File -FilePath $PatchLogs -Append  
            }      
                  
        $global:PatchStatus += $PatchStatusRow 
        Log_Verbose_Output $((get-date -format s) + " VERBOSE: Adding $PatchStatusRow to patchstatus")

        #Bug fix - need to write out error when system can't be patched... Otherwise this script keeps trying before moving to the next group of systems
        $VMInventory = Import-Csv $VMFile 
        foreach($entry in $VMInventory){
            if($entry.VMName -eq $VM.Name -and $PatchStatusRow.Status -eq "Failure"){
                $entry.Last_Patched = Get-Date
                $entry.Last_Run_Status = $PatchStatusRow.Details
            }
        }
        $VMInventory | Export-Csv $VMFile
    }  
    $PatchedVms 
} 
function AuditPatches($hostnames){  
    $AuditFile = "C:\Windows\Temp\Windows_Patch_Audit.csv"  
    $AuditResults = @()  
    $Patches = @()
    foreach($hostname in $hostnames){  
        if($Session = New-PSSession -ComputerName $hostname -ErrorAction SilentlyContinue){ 
            Log_Verbose_Output $((get-date -format s) + " VERBOSE: Connected to $hostname")
            $ModulePath = "C:\windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate"  
  
            #Check for PSWindowsUpdate Module  
            if(Invoke-Command -ScriptBlock {-not (Test-Path "C:\windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate") } -Session $Session){  
                #If it doesn't exist, create the directory  
                Invoke-Command -Session $Session {New-Item $ModulePath -Type directory} 
                Log_Verbose_Output $((get-date -format s) + " VERBOSE: Didn't find PSWindows Update module on $hostname - Copying it over")
                #Copy module files over to target system  
                copy-item -Recurse -Path $ModulePath -Destination $ModulePath -ToSession $Session  
            }  
            $Patches = @(Invoke-Command -Session $Session -ScriptBlock { Import-Module C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\PSWindowsUpdate.psm1; $res = (Get-Wuinstall -ListOnly -NotCategory 'Language packs'); $res} -ErrorAction SilentlyContinue)
            $newRow = [pscustomobject]@{'VMName' = $hostname ; 'Status' = "Success" ; 'NumPatchesAvailable' = $Patches.Count }  
            write-verbose "Found $($Patches.Count) available patches for $hostname"
            Write-Verbose "Patches `n $Patches"
            $AuditResults += $newRow  
            Remove-PSSession $Session 
        }  
        else{ #Couldn't connect
            Log_Verbose_Output $((get-date -format s) + " VERBOSE: Couldn't connect to $hostname")
            $newRow = [pscustomobject]@{'VMName' = $hostname ; 'Status' = "Could not connect via PS Remoting" ; 'NumPatchesAvailable' = "null" }  
            $AuditResults += $newRow  
        }  
    }  
    $AuditResults | Export-Csv $AuditFile
    $out = (get-date -format s) + "Wrote Audit Results to $AuditFile"
    Write-Host $out
    $out |Out-File $ScriptLog -Append
}  

function SendEmail($ErrorMessage){ 
    $From = "fromAddress@domain.com"
    $To = "toAddress@domain.com" 
    $Subject = "Failed Health Check after Patching" 
    $SMTPServer = "server" 
    $SMTPPort = "587" 
    #If run non-interactive don't use get-credential
    Send-MailMessage -From $From -to $To -Subject $Subject -Body $ErrorMessage -SmtpServer $SMTPServer -port $SMTPPort -UseSsl -Credential (Get-Credential) 
}  

function HealthCheckAnalysis($VMs, $VMHostname){ 
     #for each VM, check if they have a healthcheck script at C:\scripts\healthcheck.ps1  
     #Run the healthcheck and if we receive a 1 assume success, 0 assume failure 
     #If healthcheck fails, roll back to last snapshot. 
     $VMInventory = Import-Csv $VMFile 
     foreach($VM in $VMs){ 
        $RetrySeconds = 60 
        $RetryTimes = 5 
        $RetrySuccess = 0 
        $ret = "0" 
        if(-not $VMHostname){
            foreach($v in $VMInventory){
                if($v.VMName -eq $VM.Name){
                    $Hostname = $v.Hostname
                }
            }
        }
        do{ #loop a few times in case the server is rebooting and we can't get a healthcheck 
            if(Test-WSMan -ComputerName $Hostname -ErrorAction SilentlyContinue){ 
                $RetrySuccess = 1 
                if(Invoke-Command -ScriptBlock {-not (Test-Path "C:\scripts\healthcheck.ps1") } -Credential $Cred -ComputerName $Hostname){ 
                    #Health Check Script doesn't exist, assume success and don't roll back from snapshot 
                    Log_Verbose_Output $((get-date -format s) + "Couldn't find healthcheck script at C:\Scripts\Healthcheck.ps1 on $Hostname")
                    $ret = "1" 
                } 
                else{ 
                    $ret = Invoke-Command -Scriptblock {C:\Scripts\healthcheck.ps1} -Credential $Cred -ComputerName $Hostname 
                    if($ret -eq "0"){ 
                        $rollbackSuccess ="1" 
                        Log_Verbose_Output $((get-date -format s) + " VERBOSE: Healthcheck failed on $Hostname. Reverting to last snapshot.")

                        try{ 
                            $snap = Get-Snapshot -VM $VM | Sort-Object -Property Created -Descending | Select -First 1 
                            Set-VM -VM $VM -SnapShot $snap -Confirm:$false |out-null 
                        } 
                        catch{ 
                            $rollbackSuccess = "0" 
                        } 
                        if($rollbackSucess -eq "1"){ 
                            $ErrorMessage = "Health check failed after patching on $Hostname.  Successfully rolled back to snapshot of system prior to patching." 
                        } 
                        else{ 
                            $ErrorMessage = "CRITICAL: Health check failed after patching on $Hostname.  Not able to roll back to snapshot of system prior to patching." 
                        } 
                        SendEmail $ErrorMessage 
                    } 
                    elseif($ret -eq "1"){ 
                        Log_Verbose_Output $((get-date -format s) + "Successful patching")

                    } 
                } 
            } 
            else{ #Can't connect to server, wait 60 seconds and retry again 
                $RetryTimes++ 
                Start-Sleep $RetrySeconds 
            } 
        } 
        while($RetrySuccess -eq 0 -and $RetryTimes -lt 5) 
    } 
} 

# Starting script here based on switches provided by user/scheduled task
if($Install){  
    
    if(-Not (Test-Path C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate)){
        Log_Verbose_Output $((get-date -format s) + " VERBOSE: Installing PSWindowsUpdate Module")
        Save-Module -Name PSWindowsUpdate -Path C:\Windows\System32\WindowsPowerShell\v1.0\Modules
        Install-Module -Name PSWindowsUpdate -RequiredVersion 1.5.2.2
    }
   Log_Verbose_Output $((get-date -format s) + "Starting Initial Run. Gathering VMs")
    
    $global:VMs = Get_VCenter_VMs
 
    $VMFileContent =@()  
      
    write-host "# of VMs = " $global:VMs.Count  
    write-host "Parsing beta groups" 
 

    foreach($VM in $global:VMs){  
        $BetaGroup = "0"  
        $View = get-view $VM  
        $VMName = $VM.Name  
        $Hostname = $View.Guest.Hostname  
        $IP = $View.Guest.IPAddress  
        if(-not $IP){  
            $IP = "null"  
        }  
        $OS = $VM.Guest.OSFullName  
        $PatchSchedule = $VM| Get-Annotation -CustomAttribute "Patching - Schedule" -ErrorAction SilentlyContinue  
        $PatchSchedule = $PatchSchedule.Value  
        if($PatchSchedule -eq ""){
            $PatchSchedule = "Daily 0000"
        }

        $VCenterBetaGroup = $VM| Get-Annotation -CustomAttribute "BetaGroup" -ErrorAction SilentlyContinue 

        try{
            $a = [convert]::ToInt32($VCenterBetaGroup.Value, 10)
            $BetaGroup = [string]$a
        }
        catch{
            Log_Verbose_Output $((get-date -format s) + " VERBOSE: No predefined beta group found for $VMName.  Skipping this VM.")
        }
        if($BetaGroup -ne ""){ #if beta group is defined in VCenter Attribute, use whatever is already defined 
            Log_Verbose_Output $((get-date -format s) + " VERBOSE: Found predefined beta group for $VMName.  This VM is in Beta Group $BetaGroup")
        } 
        if($BetaGroup -ne "" -and $BetaGroup -ne "0"){
            $newRow = [pscustomobject]@{ VMName = $VMName ; Hostname = $Hostname ; IP_Address = $IP ; OS = $OS ; PatchSchedule = $PatchSchedule ; Beta_Group = $BetaGroup ; Last_Patched = "null"; Last_Run_Status = "null" }  
            $VMFileContent += $newRow   
        }  
    }  

    $VMFileContent | Export-Csv $VMFile  
 
 
    [string]$month = (get-date).month 
    [string]$year = (get-date).year 
    $firstdayofmonth = [datetime] ([string]$month + "/1/" + [string]$year) 
    $patchTues = (0..30 | % {$firstdayofmonth.adddays($_) } | ? {$_.dayofweek -like "Tue*"})[1] 
    if($(Get-Date) -gt $patchTues){ 
 
        [string]$month = $(Get-Date).AddMonths(1).Month 
        $firstdayofmonth = [datetime] ([string]$month + "/1/" + [string]$year) 
        $patchTues = (0..30 | % {$firstdayofmonth.adddays($_) } | ? {$_.dayofweek -like "Tue*"})[1] 
    } 
 
 
    #Now that the inventory and beta groups are complete, install the script as a scheduled task 
    $scriptToInstall = $PSScriptRoot + "\Update-VMs.ps1" 
    schtasks.exe /create /TN "VCenter_Windows_Updates" /tr "powershell -file $ScriptToInstall -RegularPatch -Verbose" /sc minute /mo 30 /SD $patchTues.ToString("MM/dd/yyyy") /st $patchTues.toString("hh:mm") 
    Write-Host "Install Finished successfully.  Scheduled task is configured to start on the next patch Tuesday, $patchTues" 
    Write-Host "IMPORTANT: Change scheduled task to run as service account with appropriate privileges to target Windows systems" 
}  
elseif($RegularPatch){  
    $BetaGroupVMs = @()  
    $VMsToPatch = @()  
    $LogFileContents = @()  
    $PassesFromLogFile = @()  
    $BetaCounter = 0  
    $firstWeek = 0 
    $BetaToPatch = 0 #Patch up to this Beta Group 
    $Pass = ""  
    $global:RunTime = Get-Date  
    #Make sure we have the file of systems with priorities and patch windwos  
    if(-not (Test-Path $VMFile)){  
        Write-Host "Inventory file not found.  Please run this script again with -Install prior to running with -RegularPatch flag"  
        Exit  
    }  
    if(-not (Test-Path $LogFile)){  
        #Must be first run of patching - start with beta 1 group  
        Log_Verbose_Output $((get-date -format s) + " VERBOSE: First run of patching, starting with beta 1 group and creating logfile at $LogFile")
        $LogRow = [pscustomobject]@{ Date = $global:RunTime ; Beta = "1" }   
        $Pass = "1"  
        $firstWeek = 1 
        #Write entry to log file showing that we are starting on Beta1 Group  
        $LogRow | Export-Csv $LogFile  
    }  
    else{  
        $CurrentStatus = Import-Csv $LogFile  
        $LastRun = $CurrentStatus[-1]  
        $Pass = $LastRun.Beta
        [datetime]$OneWeekAgo = $global:RunTime.AddDays(-7) 
        #First week of running we have to be careful about what systems are patched and adhere to the beta schedule 
        if($OneWeekAgo -lt [datetime]$CurrentStatus[0].Date){ #we're in the first week 
            $firstWeek = 1 
        } 
        else{ 
            $firstWeek = 0 
        } 
    }  
 
    $DayOfWeek = $global:RunTime.DayOfWeek 
    if($DayOfWeek -eq "Tuesday" -and $firstWeek -eq 1){  
        $BetaToPatch = 1    
    } 
    elseif($DayOfWeek -eq "Wednesday" -and $firstWeek -eq 1){ 
        $BetaToPatch = 2 
    } 
    elseif($DayOfWeek -eq "Thursday" -and $firstWeek -eq 1){ 
        $BetaToPatch = 2 
    } 
    elseif($DayOfWeek -eq "Friday" -and $firstWeek -eq 1){ 
        $BetaToPatch = 3 
    } 
    elseif($DayOfWeek -eq "Saturday" -and $firstWeek -eq 1){ 
        $BetaToPatch = 3 
    } 
    elseif($DayOfWeek -eq "Sunday" -and $firstWeek -eq 1){ 
        $BetaToPatch = 3 
    } 
    elseif($DayOfWeek -eq "Monday" -and $firstWeek -eq 1){ 
        $BetaToPatch = 4 
    } 
    else{ #we're not in the first patch cycle of the month anymore - patch everything 
        $BetaToPatch = 4 
    } 
    #Import all VMs for the beta group we're patching  
    $VMInventory = Import-Csv $VMFile  
    $VMInventory.Count  
    foreach($v in $VMInventory){  
        if(([convert]::ToInt32($v.Beta_Group, 10)) -le $BetaToPatch){  
            $BetaGroupVMs += $v  
        }  
    }  
    #Now that we have the current Beta Group VMs, figure out which ones still need patches  
    $PassesFromLogFile = Import-CSV $LogFile  
    $FirstRunOfCycle = [datetime]$PassesFromLogFile[0].Date  
      
    foreach($Beta in $BetaGroupVMs){  
        if(($Beta.Last_Patched -ne "null") -and ([datetime]$Beta.Last_Patched -gt [datetime]$FirstRunOfCycle)){  
            $BetaCounter++  
            #This beta system has already been patched during this patch cycle 
            Log_Verbose_Output $((get-date -format s) + "Skipping $Beta.VMName as it has already been patched")
            Continue  
        }  
        elseif($Beta.PatchSchedule -like "*Daily*"){  
            #Figure out when window starts and see if we are in it  
            $PatchHour = $Beta.PatchSchedule.split(" ")  
            $PatchHour = $PatchHour[1].Substring(0,2)  
            if([int]$PatchHour -eq $hour ){#we're in patch window  
                
                $VMsToPatch += $Beta.VMName  
            }  
            else{ 
                Log_Verbose_Output $((get-date -format s) + " VERBOSE: Skipping $Beta as it is not in patch window")
            } 
        }  
        else{  
            Log_Verbose_Output $((get-date -format s) + "Patching schedule is not daily ... Skipping for now")

        }  
    }  
    if($BetaCounter -eq $BetaGroupVMs.Count){  
        #All Vms in this beta group have been patched. Update the Pass # for the next run  
        [int]$PassAsInt32 = [convert]::ToInt32($Pass, 10)  
        $PassAsInt32++  
        $LogRow = [pscustomobject]@{ Date = $global:RunTime ; Beta = [string]($PassAsInt32) }  
        Log_Verbose_Output $((get-date -format s) + "All VMs in Beta cycle are completed")
    }  
    else{ #Systems still need to be patched 
        $BeingPatchedArray = New-Object System.Collections.ArrayList 
        $VMsLeftToPatch = New-Object System.Collections.ArrayList 
        $PatchStatusTimer = @()
        $VMsLeftToPatch.AddRange($VMsToPatch) 
        $AllPatched = 0 
        $PatchedVMs = @()
        Log_Verbose_Output $((get-date -format s) + "About to patch " + $VMsToPatch.Count + " VMs")
        #First clean up any old snapshots that exist to avoid cluttering VCenter 
        foreach($Vname in $VMsToPatch){ 
            $VM = Get-VM -Name $Vname 
            Clean_Old_Snapshots $VM 
        } 
        if($VMsToPatch.Count -gt $BatchSize -and $BatchSize -ne 0){ #If the number of systems to patch is greater than our max batch size, implement batching 
            Log_Verbose_Output $((get-date -format s) + " DEBUG: patching based on batch size.")
            while($VMsLeftToPatch.Count -ne 0 -or $BeingPatchedArray.Count -gt 0){ #while there are still systems left to patch 
                $BeingPatchedCounter = $BeingPatchedArray.Count 
                while($BeingPatchedCounter -lt $BatchSize -and $VMsLeftToPatch.Count -gt 0){ #patch if we have systems left to patch and until we hit our batch limit 
                    $VM = $VMsLeftToPatch[0] 
                    $res = Patch_Windows_Systems $VM 
                    if($res){
                        $BeingPatchedArray.Add($VM) #Keep track of which systems are being patched 
                        $VMsLeftToPatch.Remove($VM) 
                        $BeingPatchedCounter++ 
                        $PatchedVMs += $res
                        Log_Verbose_Output $((get-date -format s) + " DEBUG: Added $VM to BeingPatchedArray.  BeingPatchedArray now looks like: $BeingPatchedArray - VMSLeftToPatch: $VMsLeftToPatch")
                    }
                    else{ #something went wrong and the server wasn't patched... don't check status
                        Log_Verbose_Output $((get-date -format s) + " ERROR: Not logging status of $VM since patch function returned no result")
                        $VMsLeftToPatch.Remove($VM)
                    }
                } 
                Start-Sleep -s 60 #Sleep for 1 minute prior to checking in on patched VMs 
                foreach($VMBeingPatched in $BeingPatchedArray){ 
                    $VM = Get-VM -Name $VMBeingPatched 
                    #Log_Verbose_Output (get-date -format s) + " DEBUG: Checking status of $VMBeingPatched - status should be updated in inventory VM once complete"
                    $Status = Check_Patch_Status $VM 
                    if($Status -eq 0){
                        $BeingPatchedArray.Remove($VMBeingPatched)
                        #$out = (get-date -format s) + " DEBUG: Status came back clean for $VMBeingPatched - removing it from list of current patching and adding another node if it exists"
                    }
                } 
            } 
        } 
        elseif($VMsToPatch.Count -gt 0){ #we can fit all systems in single batch 
            Log_Verbose_Output $((get-date -format s) + " All systems can fit in single batch - patching all at once")
            $PatchedVMs = Patch_Windows_Systems $VMsToPatch 
            $Status = Check_Patch_Status $PatchedVMs 
        } 
        if($VMsToPatch.Count -gt 0 -and $PatchedVMs){ #Bug Fix where we were checking for outages even if nothing was patched
            $LogRow = [pscustomobject]@{ Date = $global:RunTime ; Beta = $Pass }  
            #Patching has completed. It can take up to 10 minutes after the patch is completed to start a reboot. 
            Log_Verbose_Output $((get-date -format s) + " Patching complete - sleeping 10 minutes then checking for outages")
            Start-Sleep -Seconds 600

            Check_Outages $PatchedVMs
        }
    }  
    
    Export-Csv $LogFile -inputobject $LogRow -append -Force  
}  
elseif($Audit){  
    if($VMName){
        $VM = Get-VM $VMName  -ErrorAction SilentlyContinue
        if($VM){
            $View = get-view $VM   
            $Hostname = $View.Guest.Hostname 
            Log_Verbose_Output (get-date -format s) + " VERBOSE: Auditing Patches for $VMName with hostname of $Hostname"

        }
        else{
            Log_Verbose_Output $((get-date -format s) + " VERBOSE: Can't find VM with this name. Trying to connect directly as a hostname")
            $Hostname = $VMName
        }
        AuditPatches $Hostname 
    }
    elseif($VMList){
        $hostnames = @()
        $VMNames = Get-Content $VMList
        foreach($server in $VMNames){
            $VM= Get-VM $server  
            if($VM){
                $View = get-view $VM   
                $Hostname = $View.Guest.Hostname
                $hostnames += $Hostname
                Log_Verbose_Output $((get-date -format s) + " VERBOSE: Auditing Patches $Hostname")
            }
        }
        AuditPatches $hostnames
    } 
    else{ 
        Log_Verbose_Output $((get-date -format s) + " VERBOSE: No VM defined, running against all VMs")
        $global:VMs = Get_VCenter_VMs
        AuditPatches $global:Vms  
    } 
}  
elseif($OnDemandPatch){  
    if($VMName){        
        $AllVMs = @()
        $VM = Get-VM $VMName | Select-Object -Unique 
        $View = Get-View $VM
        $VMHostname = $View.Guest.HostName
        Clean_Old_Snapshots $VM 
        Log_Verbose_Output $((get-date -format s) + " Starting to patch $VMName with hostname of $VMHostname")

        if($KBs){
            $null = Patch_Windows_Systems $VMName $KBs
        }
        else{
            $null = Patch_Windows_Systems $VMName
        }
        Check_Patch_Status $VMName
        #Patching has completed. It can take up to 10 minutes after the patch is completed to start a reboot. 
        Log_Verbose_Output $((get-date -format s) + " Patching complete on $VMName - sleeping 10 minutes then checking for outages")
        Start-Sleep -Seconds 600
        
        Check_Outages $VMName $VMHostname
    }
    elseif($VMList){
        if($VMList -imatch "all"){#Get all VMs from VCenter and Patch them
            $AllVMs = Get-VM |Where-Object {$_.Guest.OSFullName -Like "*Windows*"} | Select-Object -Unique
            if($KBs){
                $null = Patch_Windows_Systems $AllVMs $KBs
            }
            else{
                $null = Patch_Windows_Systems $AllVMs 
            }
            Check_Patch_Status $AllVMs
            #Patching has completed. It can take up to 10 minutes after the patch is completed to start a reboot. 
            Log_Verbose_Output $((get-date -format s) + " Patching complete on $VMName - sleeping 10 minutes then checking for outages")
            Start-Sleep -Seconds 600
            Check_Outages $AllVMs 
        }
        else {
                try{
                    $servernames = Get-Content $VMList

                }
                catch{
                    Write-Host -ForegroundColor Red "ERROR: Unable to read VMList file provided.  Please correctly enter the path of the file containing the list of VMs and try again."
                }
                foreach($server in $servernames){
                    $v= Get-VM $server -ErrorAction SilentlyContinue
                    $AllVMs += $v
                }
                if($KBs){
                    $null = Patch_Windows_Systems $AllVMs $KBs
                }
                else{
                    $null = Patch_Windows_Systems $AllVMs 
                } 
                Check_Patch_Status $AllVMs
                #Patching has completed. It can take up to 10 minutes after the patch is completed to start a reboot.  
                Log_Verbose_Output $((get-date -format s) + " Patching complete on $VMName - sleeping 10 minutes then checking for outages")
                Start-Sleep -Seconds 600
                Check_Outages $AllVMs 
            
            
        }

    } 
    else{ 
        Write-Host -ForegroundColor Red "ERROR: Need to supply -VMName or -VMList if requesting -OnDemandPatch" 
    } 
  
}  
else{  
    write-host "Script requires one of the following arguments"  
    write-host "-Install creates a scheduled task for automated patching after inventorying systems and building patch beta groups based on criticality"  
    write-host "-RegularPatch should not be run manually as it kicks off regular patching cycle on systems discovered via -Install"  
    write-host "-AuditPatches inventories systems and checks for available patches on each system"  
    write-host "-OnDemandPatch takes a system as an argument and immediately applies available patches"  
}  

Disconnect-VIServer * -Confirm:$false

if($Verbose){  
    $VerbosePreference = $oldverbose  
}  
 


