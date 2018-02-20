# Update-VMs
Snapshot, patch, health-check, and potentially roll-back Windows VMs

### Overview 
This script inventories all VMs in VCenter specified and rolls out patches within defined patch windows to all systems over the course of 1 week.  

When a machine is in its patching window, the script takes a snapshot of the VM (and removes any old snapshots created by the script), installs Windows patches, and then runs a healthcheck script (if it exists) at C:\scripts\healthcheck.ps1.  If the healthcheck is not succesful or if the system is not accessible for a period of time after patching, the script rolls the VM back to the snapshot taken prior to patching and sends an email to alert administrators.

### Getting Started

Tag all of your VMs that you want patched with the following attributes:

- "Patching - Schedule" in format of Daily 0000 for patching at midnight, Daily 1200 for patching at noon, etc.
- "BetaGroup" in format of 1,2,3,4 to define the sequence in which VMs are patched (see below for more details)

Run the script with the -Install flag to inventory all VMs that can be patched based on the above attributes.
  
### Detailed Process

- Initial Run (-Install Flag) 
  - Get all Systems from source (default: VCenter)
  - Creates beta groups based on patching windows and criticality (if defined in VM properties)
  - Installs scheduled task to run patching jobs starting on the next Patch Tuesday and running every 30 minutes to patch any system in a patching window

- Scheduled Task 
  - Executes on Patch Tuesday at midnight for initial run patching against Beta1 Systems whenever they are in their patch windows (as defined in VCenter)
  - Every 30 minutes run through list to check if Beta1 systems are in patching window 
  - If in patching window, apply latest patches 
  - Wait 1 day
  - Patch all Beta 2 systems in their windows
  - Wait 1 day
  - Patch all Beta 3 systems in their windows
  - Wait 2 days
  - Patch all Beta 4 (all remaining) systems in their windows

### Switches  

-Install 

    -Inventory VMs from VCenter and build patch beta groups
    
    -Installs self as a scheduled task to run every 30 minutes and patch systems according to beta schedule and patch windows  
    
-Audit 

    -Takes -VMName as argument and queries for available patches
    
-RegularPatch 

    -Apply patches based on patching windows and according to beta group schedule (Should be run in scheduled task) 
    
-OnDemandPatch 

    -Takes -VMName as argument and immediately applies available patches 
    
-VMName

    -Name of single VM to patch or audit
    
-VMList

    -Filename containing individual VM names line by line
    
    OR
    
    -"-VMList all" will patch or audit all VMs in VCenter
    
-KBs

    -List of specific patches to apply when running OnDemandPatch
    
-Verbose 

    -Print detailed logging of script activities
 


