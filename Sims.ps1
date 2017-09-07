class SimsUser {
    [string]$Givenname
    [string]$Surname
    [string]$EmployeeNumber
    [string]$DisplayName
    [string]$Intake
}

function Import-SimsUser {
    param(
        # Sims report user list
        [Parameter(mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $user
    )
    Process {
        $obj = [SimsUser]@{
            'Givenname'      = $user.'Legal Forename';
            'Surname'        = $user.'Legal Surname';
            'EmployeeNumber' = ([int]$user.adno).toString('000000');
            'DisplayName'    = "$($user.'Preferred Forename') $($user.'Preferred Surname')";
            'Intake' = $user.'Year of Entry';
        }
        Write-Output $obj
    }
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
        $Name = "All Student Class Memberships"

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
    start-process -FilePath $Executable -ArgumentList $command -Wait

    get-item $Destination | write-output
}
