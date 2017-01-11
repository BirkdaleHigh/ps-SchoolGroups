function Update-EmployeeNumber{
    [CmdletBinding(DefaultParameterSetName='Default')]
    Param(
        # Users to update the emplyeeNumber of
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [SimsUser[]]$Identity

        , # Search all users in an intake year
        [Parameter(ParameterSetName='Search')]
        [ValidateScript({
            $year = (get-date).year
            if( ($PSItem -le $year) -and ($PSItem -ge $year-5) ){
                return $true
            } else {
                Throw "$psitem is not an active intake year."
            }
        })]
        [string]$intake = 2016
    )

    get-aduser -SearchBase "OU=$intake,OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL" -Filter 'enabled -eq $true' |
        foreach{
            $ad = $_
            $Identity | foreach {
                if(($ad.givenname -eq $psitem.givenname) -and ($ad.surname -eq $psitem.surname)){
                    $ad | set-aduser -EmployeeNumber $psitem.adno
                }
            }
    }
}

function Test-EmployeeNumber{
    Param(
        [switch]
        $PassThru

        , # Search all users in an intake year
        [Parameter()]
        [ValidateScript({
            $year = (get-date).year
            if( ($PSItem -le $year) -and ($PSItem -ge $year-5) ){
                return $true
            } else {
                Throw "$psitem is not an active intake year."
            }
        })]
        [string]$intake = 2016
    )
    $userFilter = @{
            Filter = '(enabled -eq $true) -and (employeeNumber -notlike "*")'
            SearchBase = "OU=$intake,OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL"
            Properties = 'employeeNumber'
        }
    $users = Get-ADUser @userFilter
    $Numbered = $users |
        Measure-Object |
        Select-Object -ExpandProperty Count

    if(-not $PassThru){
        if($Numbered -eq 0){
            "success"
        } else {
            "incorrect: $numbered"
        }
    } else {
        Write-Output $users
    }
}
