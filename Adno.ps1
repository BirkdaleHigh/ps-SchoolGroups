function Get-MissingEmployeeNumber{
    <#
    .SYNOPSIS
    Are user accounts missing EmployeeNumbers

    .DESCRIPTION
    Search an entire year (which is shorthand to the OU) for enabled user accounts without the EmployeeNumber filled in.

    Employee Number is the unique Admission number from our MIS, and is the linchpin around how users are identified across IT systems.



    .PARAMETER PassThru
    Return user AD objects with a missing employee number

    .EXAMPLE
    Get-MissingEmployeeNumber -intake 2017
    success

    No users are missing an employeenumber field

    .EXAMPLE
    Get-MissingEmployeeNumber -intake 2016
    incorrect: 1

    One user is missing an EmployeeNumber
    .EXAMPLE
    Get-MissingEmployeeNumber -intake 2016 -PassThru

    DistinguishedName : CN=16TestA,OU=2016,OU=...
    EmployeeNumber    :
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
    Param(
        [switch]
        $PassThru

        , # Search all users in an intake year
        [Parameter()]
        [ValidateScript({ValidateIntake $psitem})]
        [string]$intake = 2016
    )
    $userFilter = @{
            Filter = '(enabled -eq $true) -and (employeeNumber -notlike "*")'
            SearchBase = "OU=$intake,OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL"
            Properties = 'employeeNumber'
        }
    $users = Get-ADUser @userFilter

    if(-not $PassThru){
        $Numbered = $users |
            Measure-Object |
            Select-Object -ExpandProperty Count
        if($Numbered -eq 0){
            "success"
        } else {
            "incorrect: $numbered"
        }
    } else {
        Write-Output $users
    }
}

function Search-MISAdmissionNumber{
    [CmdletBinding()]
    Param(
        # Active Directory account of user
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Microsoft.ActiveDirectory.Management.ADUser[]]$Identity

        ,# MIS dataset of users to search
        $Searchbase = $script:SimsReport
    )
    Begin {
        setupModule
        write-verbose "Searching $($SearchBase | measure | select -expandproperty count) records."
    }
    Process{
        $Identity | Foreach {
            $ad = $_
            $Searchbase | Foreach {
                    if( ($ad.givenname -eq $psitem.Forename) -and ($ad.surname -eq $psitem.'Legal Surname'.replace("`'",'').replace(" ",'-')) ){
                        $ad.EmployeeNumber = $psitem.adno
                        write-output $ad
                    }
                }
            }
    }
}

function Update-EmployeeNumber {
    [CmdletBinding()]
    Param(
        # Active Directory account of user
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateScript({$psitem.PSobject.Properties.Name -contains "EmployeeNumber"})]
        [Microsoft.ActiveDirectory.Management.ADUser[]]$Identity
    )
    Process{
        ForEach ($User in $Identity) {
            try{
                Set-ADUser -identity $User.DistinguishedName -add @{EmployeeNumber = $User.EmployeeNumber} -ErrorAction Stop
            } catch {
                Throw $psitem
            }
            Write-Output $User
        }
    }
}
