﻿function New-SchoolUser{
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
        [ValidateScript({ValidateIntake $psitem})]
        [string]$intake,

        # Block creation of user folder
        [switch]$NoHome
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

        $user = @{
            EmployeeNumber = $EmployeeNumber
            GivenName = $Givenname
            Surname = $surname
            name = $username
            DisplayName = $DisplayName
            Path = "OU=$year,OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL"
            ProfilePath = "\\bhs-fs01\profiles$\Students\profile"
            HomeDirectory = "\\bhs-fs01\home$\Students\$year Students\$username"
            HomeDrive = 'N:'
            ScriptPath = 'kix32 Students.kix'
            UserPrincipalName = "$username@BHS.INTERNAL"
            AccountPassword = ConvertTo-SecureString -AsPlainText -Force "password"
            ChangePasswordAtLogon = $true
            Enabled = $true
        }

        new-aduser @user

        $account = Get-ADUser $username -properties HomeDirectory,EmployeeNumber

        if(-not $NoHome){
            $account | New-HomeDirectory > $null
        }

        Write-Output $account

    }
}

function New-CADirectory{
    <#
    .SYNOPSIS
        Create a folder specific to user account by intake year and subject
    .DESCRIPTION
        Controlled assessments have their own work area to easy marking, specify access controls.

        This folder can be mapped as a separate drive for students to use by mebership of AccessCAShared.
        This group membership allows the policy "Add - Drive J - CA Work" to map the drive '\\bhs-fs01\ca'.
        Access based enumeration takes care of simplify the folders users will see in this drive.

        Alternatively they can be used as the home directory when the user is a member of DisableHomeFolder.
        The policy "Set - Drive N - CA Home Path" can target a drive map to this path
    .INPUTS
        Microsoft.ActiveDirectory.Management.ADUser
    .OUTPUTS
        System.IO.DirectoryInfo
    .EXAMPLE
        Get-ADGroupMember 10c_im1 | New-CADirectory -SubjectName iMedia -intake 2014
        Will create in this case 26 folders of the usernames from the 10c_Im1 gorup membership at
        the path \\bhs-fs01\CA\Intake 2014\iMedia\%username% with fullControl folder permissions by each username.
    .NOTES
        TODO: Validate subject name against Get-ClassProperty for consistancy.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$Identity,

        # Full subject name e.g. 'Computer Science'
        [Parameter(Mandatory=$true,
                   Position=2,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$SubjectName,

        # Intake Year
        [Parameter(Mandatory=$true,
                   Position=1,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ValidateIntake $psitem})]
        [string]$intake
    )
    Begin {
        [string]$year = $intake
        [string]$PathRoot = "\\bhs-fs01\CA\Intake $Year"
        [string]$PathSubject = join-path $PathRoot $SubjectName

        # Validate intake path exists or to be created
        if(-not (Test-Path $PathRoot)){
            Write-Warning "Mising $PathRoot. Ensure AccessCAShared has read/execute to access this folder only"
            $invalidRoot = $true
        }
        if(-not (Test-Path $PathSubject)){
            Write-Warning "Mising $PathSubject. Ensure desired CA_Intake_Subject group has read/execute to access this folder only"
            $invalidsubject = $true
        }
        if($invalidRoot -and -$invalidSubject){
            Throw "Please Fix path errors to continue."
        }

        $Propagation = [System.Security.AccessControl.PropagationFlags]::None
        $Type =[System.Security.AccessControl.AccessControlType]::Allow
    }
    Process {
        # Create user folder for each username, assigning onwership permission.
        $Identity | foreach-Object {
            # TODO: Handle an existing directory with a warning
            try {
                $Directory = new-item -ItemType Directory -Path (Join-Path $PathSubject $psitem.samAccountName) -ErrorAction stop
            } catch [System.IO.IOException] {
                Write-Warning $psitem.exception.message
                return
                # skip the loop for this user.
            } catch {
                throw $psitem
                # Break with the full error for troubleshooting.
            }
            $item = get-acl $Directory

            $Principal = New-Object System.Security.Principal.NTAccount($psitem.samAccountName)
            $Entry = New-Object System.Security.AccessControl.FileSystemAccessRule($Principal, 'FullControl', 'ContainerInherit,ObjectInherit', $Propagation, $Type)
            $item.AddAccessRule($Entry)
            Set-ACL $item.path $item
            Get-Item $item.path
        }

    }
    end {
        # TODO: Test each folder exists and permissions for user applied
    }
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
                            name='Forename';expression={ $_.Givenname }
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
        [ValidateScript({ValidateIntake $psitem})]
        [string]$Intake
    )
    get-aduser -Filter {enabled -eq $True} -SearchBase "OU=$Intake,OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL" -properties employeeNumber, passwordlastSet |
        where 'passwordLastSet' -eq $null
}

function New-HomeDirectory{
    param(
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({$psitem.PSobject.Properties.Name -contains "HomeDirectory"})]
        [Microsoft.ActiveDirectory.Management.ADUser[]]$Identity
    )
    Process{
        $Identity | where { (Test-HomeDirectory $psitem).result -eq $false } | foreach {
            $location = New-Item -ItemType Directory -Path $psitem.homeDirectory

            $Propagation = [System.Security.AccessControl.PropagationFlags]::None
            $Type =[System.Security.AccessControl.AccessControlType]::Allow
            $Principal = New-Object System.Security.Principal.NTAccount($psitem.samAccountName)

            $Entry = New-Object System.Security.AccessControl.FileSystemAccessRule($Principal, 'FullControl', 'ContainerInherit,ObjectInherit', $Propagation, $Type)

            $ACL = Get-ACL $location
            $ACL.AddAccessRule($Entry)

            Set-ACL $psitem.homeDirectory $ACL

            Write-Output $location
        }
    }
}

function Test-HomeDirectory{
    [CmdletBinding(DefaultParameterSetName='Default')]
    param(
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({$psitem.PSobject.Properties.Name -contains "HomeDirectory"})]
        [Microsoft.ActiveDirectory.Management.ADUser[]]
        $Identity
    )
    Process{
        $identity | foreach {
            try {
                $test = (Test-Path $psitem.homeDirectory -ErrorAction stop) -or $false
            } catch [System.UnauthorizedAccessException] {
                $test = 'AccessDenied'
            } catch {
                Write-Error $error[0]
            }
            [pscustomobject]@{
                Path = $psitem.homeDirectory
                Result = $test
            }
        }
    }
    # $user = Get-ADUser -identity $Identity -Properties HomeDirectory
    # if($intake){
    #     $user = get-aduser -SearchBase "OU=$intake,OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL" -Filter * -Properties HomeDirectory
    # }
    # $user | where {
    #     (test-path $_.homeDirectory) -eq $false
    # }

}

function Get-SchoolUser {
    <#
    .SYNOPSIS
        Get AD Users with properties useful to school administration
    .DESCRIPTION
        As well as providing a shortcut to useful AD properties it can also easily search for users by common first and last names.

        Output can include disabled user accounts so be mindful with your results.

        Note that by default the exact username will be queried. Specify named parameters to search by either first and/or last names.
        Names can have wild cards appened
    .EXAMPLE
        PS C:\> get-schooluser student
        Gets the specific username "student" details

        GivenName         : Student
        Surname           : Orgname
        SamAccountName    : student
        DistinguishedName : CN=Student Orgname,OU=Test,OU=ORG,DC=ORG,DC=INTERNAL
        Enabled           : True
        HomeDirectory     : \\org-server01\files\students\Test\student
        EmployeeNumber    : 000000
        EmailAddress      : student@example.com
    .EXAMPLE
        PS C:\> Get-SchoolUser -Givenname jack | measure
        Measuring the number of users whose first name is "jack".

        Count    : 87
    .EXAMPLE
        PS C:\> Get-SchoolUser -Givenname jack | where enabled | measure
        Measuring the number of enabled accounts with a givenname of "jack".

        Count    : 21
    .EXAMPLE
        PS C:\> Get-SchoolUser ben | measure
        This assumes the exact user account name is asked for.

        Get-ADUser : Cannot find an object with identity: 'ben'
    .EXAMPLE
        PS C:\> Get-SchoolUser -forename ben | measure
        This assumes the exact user account name is asked for.
        ben* would actully return 19 users to account for benjamin etc.

        Count    : 5
    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADUser
    .NOTES
        General notes
    #>
    [CmdletBinding(DefaultParameterSetName='Specific')]
    Param(
        # Search by first name
        [Parameter(Position=0, ParameterSetName='Search')]
        [alias('Forename','Firstname')]
        [string]
        $Givenname = '*'

        , # Search by surname
        [Parameter(Position=1, ParameterSetName='Search')]
        [alias('Lastname')]
        [string]
        $Surname = '*'

        , # User Logon Name
        [Parameter(Position=0, Mandatory, ParameterSetName='Specific', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string[]]
        $SamAccountName
    )
    Begin{
        $props = @(
            'HomeDirectory',
            'EmployeeNumber',
            'EmailAddress'
        )
        $outputFields = @(
            'GivenName',
            'Surname',
            'SamAccountName',
            'DistinguishedName',
            'Enabled'
        ) + $props
    }
    Process{
        switch($PsCmdlet.ParameterSetName){
            'Specific' {
                $SamAccountName | Get-ADUser -properties $props |
                    Select-Object -Property $outputFields |
                    Write-Output
                return
            }
            'Search' {
                $queryString = "(&(objectClass=user)(sn=$Surname)(givenname=$givenname))"
                Write-Verbose "LDAP Query String: $queryString"
                Get-ADUser -LDAPfilter $queryString -properties $props |
                    Select-Object -Property $outputFields |
                    Write-Output
            }
        }

    }
}