function Get-MissingEmployeeNumber{
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
        $identity | foreach {
            set-aduser -identity $identity.DistinguishedName -EmployeeNumber $identity.EmployeeNumber -PassThru
        }
    }
}