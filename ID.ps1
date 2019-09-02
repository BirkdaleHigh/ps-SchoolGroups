function Get-MissingEmployeeID{
    <#
    .SYNOPSIS
    Are user accounts missing EmployeeIDs

    .DESCRIPTION
    Search an entire year (which is shorthand to the OU) for enabled user accounts without the EmployeeID filled in.

    Employee Number is the unique Admission number from our MIS, and is the linchpin around how users are identified across IT systems.



    .PARAMETER PassThru
    Return user AD objects with a missing employee number

    .EXAMPLE
    Get-MissingEmployeeID -intake 2017
    success

    No users are missing an EmployeeID field

    .EXAMPLE
    Get-MissingEmployeeID -intake 2016
    incorrect: 1

    One user is missing an EmployeeID
    .EXAMPLE
    Get-MissingEmployeeID -intake 2016 -PassThru

    DistinguishedName : CN=16TestA,OU=2016,OU=...
    EmployeeID        :
    Enabled           : True
    GivenName         : Account
    Name              : 16TestA
    ObjectClass       : user
    SamAccountName    : 16TestA
    Surname           : Test
    UserPrincipalName : 16TestA@ORG

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    Param(
        [switch]
        $PassThru

        , # Search all users in an intake year
        [Parameter()]
        [ValidateScript({ValidateIntake $psitem})]
        [string]$intake = (get-date).year
    )
    $userFilter = @{
        Filter = '(enabled -eq $true) -and (EmployeeID -notlike "*")'
        SearchBase = "OU=$intake,$($script:config.ou.students)"
        Properties = 'EmployeeID'
    }
    Write-Verbose "Query for enabled users under OU: $($userFilter.SearchBase)"

    $users = Get-ADUser @userFilter

    if(-not $PassThru){
        $Numbered = $users |
            Measure-Object |
            Select-Object -ExpandProperty Count
        if($Numbered -eq 0){
            "All enabled accounts have an EmployeeID for intake: $intake"
        } else {
            "Incorrect: $numbered missing EmployeeIDs for intake: $intake"
        }
    } else {
        Write-Output $users
    }
}

function Search-MISID{
    [CmdletBinding()]
    Param(
        # Active Directory account of user
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Microsoft.ActiveDirectory.Management.ADUser[]]$Identity
    )
    Begin {
        setupModule
    }
    Process{
        ForEach($ADUser in $Identity){
            $script:UniqueUsers | Foreach-Object {
                if( ($ADUser.givenname -eq $psitem.Forename) -and ($ADUser.surname -eq $psitem.Surname.replace("`'",'').replace(" ",'-')) ){
                    $ADUser.EmployeeID = $psitem.Person_id
                    write-output $ADUser
                }
            }
        }
    }
}

function Update-EmployeeID {
    [CmdletBinding()]
    Param(
        # Active Directory account of user
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateScript({$psitem.PSobject.Properties.Name -contains "EmployeeID"})]
        [Microsoft.ActiveDirectory.Management.ADUser[]]$Identity
    )
    Process{
        ForEach ($User in $Identity) {
            try{
                Set-ADUser -identity $User.DistinguishedName -add @{EmployeeID = $User.EmployeeID} -ErrorAction Stop
            } catch {
                Throw $psitem
            }
            Write-Output $User
        }
    }
}
