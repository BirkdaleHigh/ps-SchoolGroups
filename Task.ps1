# This file will hold function that wrap up the module cmdlets into proceduces that are run in a sequence.
# Currently serving as a reference of how each cmdlet is composed to complete the task it's designed to do.
# i.e. update empleeNumber details



# Register a scheduled task to sync users
#1. create action
    #a. Apply adno to users
    #b. Sync class/form groups
    #c sync class/form group members
#2. create trigger
    #a. watch report for changes
#3. register task
    #a register report to run

Function Start-Sync(){
    <#
    .SYNOPSIS
        Begin syncing the groups and users.
    .DESCRIPTION
        This command uses many of the included cmdlets in this module. Each step can be done individually and separatly by directly accessing those cmdlets.

        Order of operations;
            1. Watch for the update of the source lists from last run
            2. Run the MIS report to export an updated source list
            3. Add/Remove the groups that need to exist
            4. Add/Remove the members of the groups
            5. report success/failue
    .EXAMPLE
        C:\PS> Start-Sync
        Perform the series of tasks to match the MIS user/group stucture to Active Directory
    #>
}

function Start-UpdateAllEmplyeeNumber {
    Get-MissingEmployeeNumber -intake 2017 -PassThru | Search-MISAdmissionNumber | Update-EmployeeNumber
    Get-MissingEmployeeNumber -intake 2016 -PassThru | Search-MISAdmissionNumber | Update-EmployeeNumber
    Get-MissingEmployeeNumber -intake 2015 -PassThru | Search-MISAdmissionNumber | Update-EmployeeNumber
    Get-MissingEmployeeNumber -intake 2014 -PassThru | Search-MISAdmissionNumber | Update-EmployeeNumber
    Get-MissingEmployeeNumber -intake 2013 -PassThru | Search-MISAdmissionNumber | Update-EmployeeNumber
}

Function Import-NewIntake{
    $csv = import-csv (new-report -name "Import to Active Directory" -Destination ($env:TEMP + "\intake-" + (get-date).ToFileTimeUtc() + ".csv") )
    $ad = $csv | import-simsUser
    $ad | New-SchoolUser
}

Export-ModuleMember -function @()
