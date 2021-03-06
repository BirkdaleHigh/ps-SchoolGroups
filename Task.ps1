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

Function Start-Sync() {
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

function Start-UpdateEmployeeNumber {
    Param(
        [ValidateScript( { foreach ($year in $psitem) { ValidateIntake $year } })]
        [int[]]
        $Intake
    )
    foreach ($year in $Intake) {
        Get-MissingEmployeeNumber -intake $year -PassThru | Search-MISAdmissionNumber | Update-EmployeeNumber
    }
}

function Start-FormSync{
    <#
    .SYNOPSIS
        Create new for AD groups where they don't exist. Delete groups found in the AD not from the last report.
    .DESCRIPTION
        Use new-report to maintain current data, Try test-form separately fist to view effects
    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        None
    .NOTES
        General notes
    #>
    Test-Form -Filter 'List' | New-Form
    Test-Form -Filter 'AD' | Remove-ADGroup
}

Function Get-NewIntake {
    <#
    .SYNOPSIS
    Overall task to setup the new student year from sims
    .DESCRIPTION
    Work in Progress
    1. run a specfic report (different from the sync report) from sims.net "Import to Active Directory"
    2. Import that CSV
    3. convert that import into user objects
    .EXAMPLE
    
    #>
    import-csv (new-report -name "Import to Active Directory" -Destination ($env:TEMP + "\intake-" + (get-date).ToFileTimeUtc() + ".csv") ) |
        import-simsUser
}

function Reset-AllIntakePassword {
    <#
    .SYNOPSIS
        Reset all AD Passwords for an intake year
    .DESCRIPTION
        Generate passwords to reset accounts with and output those to pipe to a file.

        Internally uses Reset-ADPassword on each account from the AD OU.
    .EXAMPLE
        C:\PS> Reset-AllIntakePassword -Intake 2016 | export-csv -NoTypeInformation ".\2016-users.csv"
        Reset all AD account passwords for the 2016 intake year OU and create CSV file of the accounts information including passwords.
    #>
    [CmdletBinding(SupportsShouldProcess = $true,
        ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateScript( { ValidateIntake $psitem })]
        [string]$Intake
    )
    Process {
        if ($pscmdlet.ShouldProcess("All users in $intake year", "Reset AD password")) {
            Get-ADUser -SearchBase "OU=$intake,OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL" | Reset-ADPassword
        }
    }
}

. "$PSScriptRoot\User.ps1"
function Reset-ExamUser {
    [cmdletbinding()]
    Param(
        # Reset specific exam account
        [ValidateRange(0,[int]::MaxValue)]
        [int[]]$Number
    )
    $Number |
        Get-ExamUser |
        Reset-ADPassword |
        Sort-Object { [int]$_.surname } |
        Format-Table username, password, seatnumber
}

function Get-EmailListToCorrect {
    Foreach ($user in Get-IncorrectSimsEmail) {
        $address = (Get-SchoolUser -EmployeeNumber $user.EmployeeNumber -errorAction 'SilentlyContinue' | where-object enabled).EmailAddress
        Add-Member -InputObject $user -NotePropertyName 'CorrectEmail' -NotePropertyValue $address -PassThru
    }
}


function New-SchoolUser {
    [cmdletbinding(SupportsShouldProcess, DefaultParameterSetName = "Default")]
    Param(
        # Users prefferred First name
        [Parameter(Mandatory,
            ValueFromPipelineByPropertyName)]
        [string]$Givenname,

        # Users preferred Surname
        [Parameter(Mandatory,
            ValueFromPipelineByPropertyName)]
        [string]$Surname,

        # Unique ID matching MIS source
        [Parameter(ValueFromPipelineByPropertyName,
            ParameterSetName = "student")]
        [ValidatePattern('^00\d{4}$')]
        [string]$EmployeeNumber,

        # Unique ID from MIS DB source
        [Parameter(ValueFromPipelineByPropertyName)]
        [int]$ID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$DisplayName = "$Givenname $Surname",

        [Parameter(Mandatory,
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            ParameterSetName = "student")]
        [ValidateScript( { ValidateIntake $psitem })]
        [string]$intake,

        # Maximum number of duplicate usernames to increment through when creating accounts
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Max = $MAX_RETRY_NEW_USER -or 4,

        # Account type to be processed
        [Parameter(ParameterSetName="Default")]
        [ValidateSet("Student", "Staff", "Exam")]
        [string]$Type = "Student"
    )
    Process {
        $PSBoundParameters.remove('Type')
        switch ($Type) {
            "student" { New-Student @PSBoundParameters }
            "exam"    { New-ExamUser @PSBoundParameters }
            Default   { New-Staff @PSBoundParameters }
        }
    }
}
