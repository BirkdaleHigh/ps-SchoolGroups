function New-SchoolUser{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$Givenname,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$Surname,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern('^00\d{4}$')]
        [string]$EmployeeNumber,

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$DisplayName = "$Givenname $Surname",

        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({
            [int]$year = (get-date).year
            [int]$test = $PSItem
            if( ($test -le $year) -and ($test -ge $year-5) ){
                return $true
            } else {
                Throw "$test is not an active intake year."
            }
        })]
        [string]$intake
    )
    Process{
        [string]$year = $intake
        $username = ($year.Remove(0,2) + $surname + $Givenname[0])

        if($username.length -gt 20){
            Throw "$username is over 20 characters"
        }

        if(Get-ADUser -Filter {EmployeeNumber -eq $EmployeeNumber} -Outvariable duplicatenumber){
           Throw "$employeeNumber already exists as $duplicatenumber"
        }

        new-aduser -EmployeeNumber $EmployeeNumber `
            -GivenName $Givenname `
            -Surname $surname `
            -name $username `
            -DisplayName $DisplayName `
            -Path "OU=$year,OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL" `
            -ProfilePath "\\bhs-fs01\profiles$\Students\$year Students" `
            -HomeDirectory "\\bhs-fs01\home$\Students\$year Students\$username" `
            -HomeDrive 'N:' `
            -ScriptPath 'kix32 Students.kix' `
            -UserPrincipalName "$username@BHS.INTERNAL" `
            -AccountPassword (ConvertTo-SecureString -AsPlainText -Force "password") `
            -ChangePasswordAtLogon $true `
            -Enabled $true
    }
}

function New-CAUser{
    <#
    .SYNOPSIS
        Create a subject specific user account
    .DESCRIPTION
        Create a user account for controlled assessment work.
        By Making the account subject specific admins can delegate managing access and logon times as there's no other subjects use of the account to impact.
    .EXAMPLE
        get-aduser example | new-causer -SubjectCode Hi -intake 2016
        Explanation of what the example does
    .NOTES
        Development improvements:
        - Could put the users in a better subject-specific OU Path. Currently manually done.
        - Could guess the intake year from the OU path of the sipplied identity
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$Identity,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Ar','Bi','Bt','Bu','Ch','Cs','Dr','En','Fo','Fr','Gg','Hi','It','Ma','Mu','Pe','Ph','Re','Rm','Sc','Sp','Te','Xl')]
        [string]$SubjectCode,

        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({
            $year = (get-date).year
            if( ($PSItem -le $year) -and ($PSItem -ge $year-5) ){
                return $true
            } else {
                Throw "$psitem is not an active intake year."
            }
        })]
        [string]$intake
    )
    Process{
        [string]$year = $intake
        $username = $Identity.SamAccountName.Insert(0, $SubjectCode)

        if($username.length -gt 20){
            Throw "$username is over 20 characters"
        }

        $identity | new-aduser
            -name $username `
            -Path "OU=$year,OU=Controlled Assessment,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL" `
            -ProfilePath "\\bhs-fs01\profiles$\Students\$year Students CA" `
            -HomeDirectory "\\bhs-fs01\ca\Intake $year\$username" `
            -HomeDrive 'N:' `
            -ScriptPath 'kix32 Students.kix' `
            -UserPrincipalName "$username@BHS.INTERNAL" `
            -AccountPassword (ConvertTo-SecureString -AsPlainText -Force "password") `
            -ChangePasswordAtLogon $true `
            -Enabled $true
    }
}

function New-CAClassMember {
    <#
    .SYNOPSIS
        Add user to CA Class Group
    .DESCRIPTION
        Long description
    .NOTES
        General notes
    #>
    Param(
        # Class code of the ad group to get e.g. 11D_hi1
        $ClassCode
        , # User intake year
        [Parameter(Mandatory=$true)]
        [ValidateScript({
            $year = (get-date).year
            if( ($PSItem -le $year) -and ($PSItem -ge $year-5) ){
                return $true
            } else {
                Throw "$psitem is not an active intake year."
            }
        })]
        [string]$Intake
    )
    $class = Get-ClassProperty $ClassCode -ErrorAction Stop
    Get-ADGroupMember $class.Code | get-aduser | new-causer -SubjectCode $class.id -intake $Intake
}

function Reset-ADPassword{
    <#
    .SYNOPSIS
        Reset all AD Passwords
    .DESCRIPTION
        Generate passwords to reset accounts with and output those to pipe to a file.
    .EXAMPLE
        C:\PS> Reset-AllADPasswords -Intake 2016 | export-csv -NoTypeInformation ".\2016-users.csv"
        Reset all AD account passwords for the 2016 intake year OU and create CSV file of the accounts information including passwords.
    .NOTES
        Replace this with a more specific function to reset passwords that require AD accounts as input.
    #>
    [CmdletBinding(SupportsShouldProcess=$true,
                   ConfirmImpact='High')]
    Param(
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser[]]$Identity
    )
    Process{
        if ($pscmdlet.ShouldProcess($Identity.DistinguishedName, "Reset Account Password")){
            get-aduser -Identity $identity.DistinguishedName -properties employeeNumber |
                foreach {
                    $password = "reset" + (get-random -Minimum 100 -Maximum 999)

                    Set-ADAccountPassword -Identity $psitem.samAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force)
                    Set-aduser -Identity $psitem.samAccountName -ChangePasswordAtLogon $true
                    Enable-ADAccount -Identity $psitem.samAccountName

                    $psitem |
                        Select-Object EmployeeNumber,@{
                            name='Forname';expression={ $_.Givenname }
                        },@{
                            name='Username';expression={ $_.SamAccountName }
                        } |
                        Add-member -MemberType NoteProperty -Name Password -Value $password -PassThru
                }
        }
    }
}

function Find-UnchangedPassword {
    Param(
        # Intake year group to search
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({
            $year = (get-date).year
            if( ($PSItem -le $year) -and ($PSItem -ge $year-5) ){
                return $true
            } else {
                Throw "$psitem is not an active intake year."
            }
        })]
        [string]$Intake
    )
    get-aduser -Filter {enabled -eq $True} -SearchBase "OU=$Intake,OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL" -properties employeeNumber, passwordlastSet |
        where 'passwordLastSet' -eq $null
}

function Test-HomeDirectory{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param(
        [Parameter(ParameterSetName='Default',
                   Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        $Identity,
        [Parameter(ParameterSetName='Year Group',
                   Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({
            $year = (get-date).year
            if( ($PSItem -le $year) -and ($PSItem -ge $year-5) ){
                return $true
            } else {
                Throw "$psitem is not an active intake year."
            }
        })]
        [string]$intake
    )

    $user = Get-ADUser -identity $Identity -Properties HomeDirectory
    if($intake){
        $user = get-aduser -SearchBase "OU=$intake,OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL" -Filter * -Properties HomeDirectory
    }
    $user | where {
        (test-path $_.homeDirectory) -eq $false
    }

}
