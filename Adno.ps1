function Get-MissingEmployeeNumber{
    <#
    .SYNOPSIS
    Are user accounts missing EmployeeNumbers, Normal input is informations, use -passthru to get the user objects back into powershell

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
        Filter = '(enabled -eq $true) -and (employeeNumber -notlike "*")'
        SearchBase = "OU=$intake,$($script:config.ou.students)"
        Properties = 'employeeNumber'
    }
    Write-Verbose "Query for enabled users under OU: $($userFilter.SearchBase)"

    $users = Get-ADUser @userFilter

    if(-not $PassThru){
        $Numbered = $users |
            Measure-Object |
            Select-Object -ExpandProperty Count
        if($Numbered -eq 0){
            "All enabled accounts have an EmployeeNumber for intake: $intake"
        } else {
            "Incorrect: $numbered missing EmployeeNumbers for intake: $intake"
        }
    } else {
        Write-Output $users
    }
}

function Search-MISAdmissionNumber{
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Compare forename/surname as best we can between AD and MIS to match up the MIS number for the employeenumber
    .DESCRIPTION
        This command is best used by taking the results piped from `Get-MisssingEmplyeenNumber -passthru`

        Updates the users AD object with the MIS number, it does not write back to the AD, see Update-EmployeeNumber

        Anything this can't find but still returns from get-missingEmplyeeNumber you'll have to manually fix in AD, it's either changed names in MIS or some other data error.
    .EXAMPLE
        PS C:\> Get-MissingEmployeeNumber -intake 2019 -PassThru | Search-MISAdmissionNumber
        AD user object with the employeeNumber attribute applied from MIS, Would be used to pipe into set-aduser or better would be `Update-EmplyeeNumber`
    .INPUTS
        Microsoft.ActiveDirectory.Management.ADUser
    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADUser
    #>
    Param(
        # Active Directory account of user
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Microsoft.ActiveDirectory.Management.ADUser[]]$Identity
    )
    Process{
        ForEach($ADUser in $Identity){
            $script:UniqueUsers | Foreach-Object {
                if( ($ADUser.givenname -eq $psitem.Forename) -and ($ADUser.surname -eq $psitem.Surname.replace("`'",'').replace(" ",'-')) ){
                    $ADUser.EmployeeNumber = $psitem.adno
                    write-output $ADUser
                }
            }
        }
    }
}

function Update-EmployeeNumber {
    [CmdletBinding()]
    <#
    .SYNOPSIS
        Wrapper to Set-ADUser that requires and validates the EmplyeeNumber attribute.
    .DESCRIPTION
        Any AD user object from Get-ADUser won't by default include the EmployeeNumber field, this wrapper ensures AD objects you pipe to it DO have that field.

        The manualy way to get this would be `get-aduser -properties employeeNumber`
    .EXAMPLE
        PS C:\> Get-MissingEmployeeNumber -intake 2019 -PassThru | Search-MISAdmissionNumber | Update-EmployeeNumber
        quickly fix al lthe easy-wins from searching the MIS export
    .INPUTS
        Microsoft.ActiveDirectory.Management.ADUser
    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADUser
    .NOTES
        General notes
    #>
    Param(
        # Active Directory account of user
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateScript({
            if(
                ($psitem.PSobject.Properties.Name -contains "EmployeeNumber") -and
                ($null -ne $psitem.EmployeeNumber) -and
                ('' -ne $psitem.EmployeeNumber)
                ) {
                    return $true
                }
            Throw "EmployeeNumber not set for $psitem"
        })]
        [Microsoft.ActiveDirectory.Management.ADUser[]]$Identity
    )
    Process{
        ForEach ($User in $Identity) {
            if($null -eq $User.EmployeeNumber -or '' -eq $user.EmployeeNumber){
                Throw "EmployeeNumber not set for $($user.DistinguishedName)"
            }
            try{
                Set-ADUser -identity $User.DistinguishedName -add @{EmployeeNumber = $User.EmployeeNumber} -ErrorAction Stop
            } catch {
                Throw $psitem
            }
            Write-Output $User
        }
    }
}
