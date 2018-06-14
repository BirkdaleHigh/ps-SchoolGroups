class SimsUser {
    [string]$Givenname
    [string]$Surname
    [string]$EmployeeNumber
    [string]$Intake
    static [string]$DisplayName = "$Givenname $Surname"
}

function Import-SimsUser {
    Begin {
        setupModule
        $simsFields = @(
            'adno'
            'Forename'
            'Legal Surname'
            'Year'
        )
    }
    Process {
        $script:SimsReport |
            Select-Object -Unique -Property $simsFields |
            New-SimsUser
    }
}

function New-SimsUser {
    [cmdletBinding(DefaultParameterSetName="Default")]
    param(
        # Sims report user list
        [Parameter(ParameterSetName="Object",
                   Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        [PSObject]
        $user

        , # Parameter help description
        [Parameter(ParameterSetName="Default",
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Adno')]
        [string]
        $EmployeeNumber

        , # Parameter help description
        [Parameter(ParameterSetName="Default",
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Forename')]
        [string]
        $Givenname

        , # Parameter help description
        [Parameter(ParameterSetName="Default",
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Legal Surname')]
        [string]
        $Surname

        , # Parameter help description
        [Parameter(ParameterSetName="Default",
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Year')]
        [string]
        $Intake
        )
    Process {
        Switch($PSCmdlet.ParameterSetName){
            'Object' {
                write-warning "Used Object"
                $obj = [SimsUser]@{
                    'Givenname'      = $user.'Forename'
                    'Surname'        = $user.'Legal Surname'
                    'EmployeeNumber' = ([int]$user.adno).toString('000000')
                    'Intake' = $user.'Year'
                }
            }
            Default {
                write-warning "Used Default"
                $obj = [SimsUser]$PSBoundParameters
            }
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
