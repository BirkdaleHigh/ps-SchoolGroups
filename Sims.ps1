class SimsUser {
    [string]$Givenname
    [string]$Surname
    [string]$EmployeeNumber
    [int]$EmployeeID
    [string]$YearGroup
    [string]$DisplayName = ("{0} {1}" -f $this.Givenname,$this.Surname)
    [string]$Email

    # CSV Imported Object Parameters
    SimsUser([PSCustomObject]$PipedObject){
        $this.Givenname      = $PipedObject.forename
        $this.Surname        = $PipedObject.'Legal Surname'
        $this.EmployeeNumber = ([int]$PipedObject.adno).toString('000000')
        $this.EmployeeID     = [int]$PipedObject.Person_id # Person_id from students report, just id when from pre-admission report
        $this.YearGroup      = $PipedObject.year
        $this.DisplayName    = ("{0} {1}" -f $this.Givenname,$this.Surname)
        $this.Email          = $PipedObject.'Primary Email'
    }

    [boolean] validEmail(){
        if($this.email -notlike '*@birkdalehigh.co.uk'){
            return $False
        }
        $ad = Get-SchoolUser -EmployeeNumber $this.EmployeeNumber
        if($ad.emailaddress -eq $this.Email){
            return $True
        } else {
            return $False
        }
    }
}

function Import-SimsUser {
    Begin {
        setupModule
    }
    Process {
        $script:UniqueUsers |
            New-SimsUser
    }
}

function New-SimsUser {
    [cmdletBinding()]
    param(
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
            $InputObject
        )
    Process {
        [SimsUser]::new($InputObject)
    }
}

function Get-IncorrectSimsEmail() {
    Import-SimsUser |
        where-object { -not $psitem.validEmail() } |
        sort-object intake, surname
}

function New-Report{
    <#
    .SYNOPSIS
        Run the report for a new list of group memberships
    .DESCRIPTION
        Runs the names Sims.net report if found in the users "My Reports" location that
        generates the list of group details to sync other services with.

        Report contains all users with admission number repeated for each group IDs membership
    .EXAMPLE
        PS C:\> New-Report
        Runs the report to store in a temporary location for other cmldets to use.
    .INPUTS
        Execution path for Sims.net reporter
    .OUTPUTS
        CSV Document containing user and group memberships
    .NOTES
        when running "trusted" the Sim.net user must have the required report in the "My Reports" location.
        This report can be imported from this modules "SimsReports/" Folder, named "All Student Class Memberships.RptDef"

        Command path example
        "$simsPath to CommandReporter.exe" /TRUSTED /REPORT:"Users 'My Reports' Report Name" /OUTPUT:$Destination
    #>
    Param(
        # Path to cli commandReporter, installed with Sims.net
        [Parameter()]
        [string]
        $Executable = ( ${env:ProgramFiles(x86)} + "\SIMS\SIMS .net" + "\CommandReporter.exe" )

        , # Filepath for the report destination save location
        [Parameter()]
        [string]
        $Destination = $env:TEMP + "\ClassMembers-" + (get-date).ToFileTimeUtc() + ".csv"

        , # Report Name must be found in the users "My Reports" location
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name = "Student ID Class Membership"

        , # Secify a Sims.net username to run as
        [Parameter(ParameterSetName='User')]
        [ValidateNotNullOrEmpty()]
        [string]
        $User

        , # Password for the Sims.net user
        [Parameter(ParameterSetName='User')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Password
    )

    $command = @()

    if($User){
        $command += "/USER:`"$User`""
        $command += "/PASSWORD:`"$Password`""
    } else {
        $command += '/TRUSTED'
    }

    $command += "/REPORT:`"$Name`""
    $command += "/OUTPUT:`"$Destination`""

    write-Debug ("Executable Path: " +$Executable)
    Start-Process -FilePath $Executable -ArgumentList $command -Wait -RedirectStandardError (join-path $env:TEMP "ClassMembers-SimsErrorOutput.log")

    get-item $Destination | write-output
}
