$MAX_RETRY_NEW_USER = 4

function New-Staff{
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        # Users prefferred First name
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$Givenname,

        # Users preferred Surname
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$Surname,

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$DisplayName = "$Givenname $Surname",

        # Maximum number of duplicate usernames to increment through when creating accounts
        [ValidateRange(0,[int]::MaxValue)]
        [int]$Max = $MAX_RETRY_NEW_USER
    )
    Begin{

    }
    Process{

        $username = CreateUsername -Username ($Givenname[0] + $surname) -Max $Max
        $password = CreatePassword

        $user = @{
            GivenName = $Givenname
            Surname = $surname
            name = $username
            DisplayName = $DisplayName
            EmailAddress = "$username@birkdalehigh.co.uk"
            Path = "OU=Staff,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL"
            HomeDirectory = "\\bhs-fs02\home`$\Staff\$username"
            HomeDrive = 'N:'
            ScriptPath = 'kix32 Staff.kix'
            UserPrincipalName = "$username@BHS.INTERNAL"
            AccountPassword = ConvertTo-SecureString -AsPlainText -Force $password
            ChangePasswordAtLogon = $true
            Enabled = $true
        }

        CreateADUser -UserObject $user -Password:$password
    }
}

function New-Student{
    <#
    .SYNOPSIS
        Creates a new student by our required format
    .DESCRIPTION
        Sets the groups, right username pattern and conflict logic.

        You need to pipe this through new-homedirectory or it won't make the folder.
        Calling that from this command resulted in being too fast and failing as we got to making
        the folder before all the DC's would agree the user existed, therefor couldn't set permission.
    .EXAMPLE
        PS C:\> New-Student -Givenname Jim -Surname Kirk -EmployeeNumber "000001" -Intake 2019 | New-HomeDirectory
        New student generated as 19kirkJ, if that already existed you'd get 19KirkJ1 etc.
        User object returned with a default generated password and the AD groups have been set.
    .NOTES
        Maintain "Add-GroupStudent" to reflect the groups required.
    #>
    [cmdletbinding(SupportsShouldProcess=$true,DefaultParameterSetName="Default")]
    Param(
        # Users prefferred First name
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$Givenname,

        # Users preferred Surname
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]$Surname,

        # Unique ID matching MIS student admission number source
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern('^00\d{4}$')]
        [ValidateScript({
            try {
                $existing = Get-SchoolUser -EmployeeNumber $psItem -ErrorAction Stop
            } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
                return $true
            }
            Throw "MIS ID($psItem) exists as employeenumber: $($existing.employeenumber), $($existing.samaccountname)"
        })]
        [string]$EmployeeNumber,


        [Parameter(Mandatory=$true,
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName="preAdmission",
        Position=1,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ValidateIntake $psitem})]
        [string]$intake,

        # Maximum number of duplicate usernames to increment through when creating accounts
        [ValidateRange(0,[int]::MaxValue)]
        [int]$Max = $MAX_RETRY_NEW_USER,

        # Organization wide Unique ID number, possible from MIS that all users have
        [Parameter(Position=1,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName="preAdmission",
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [int]$ID
    )
    Begin{

    }
    Process{

        $username = CreateUsername -Username ($intake.Remove(0,2) + $Surname + $Givenname[0]) -Max $Max
        $password = CreatePassword

        $user = @{
            Office = [string]$ID # field re-used by Edulink for an ID
            EmployeeID = [string]$ID # field should be used by Edulink for a person ID, and for staff
            GivenName = $Givenname
            Surname = $surname
            name = $username
            DisplayName = $Givenname
            EmailAddress = "$username@birkdalehigh.co.uk"
            Path = "OU=$intake,OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL"
            HomeDirectory = "\\bhs-fs01\home`$\Students\$intake Students\$username"
            HomeDrive = 'N:'
            ScriptPath = 'kix32 Students.kix'
            UserPrincipalName = "$username@BHS.INTERNAL"
            SamAccountName = $username
            AccountPassword = ConvertTo-SecureString -AsPlainText -Force $password
            ChangePasswordAtLogon = $true
            Enabled = $true
        }
        if($EmployeeNumber){
            # EmployeeNumber used as ADNO from MIS that's more appropriete for class data
            # Students only however, and doesn't exist until on-roll, and UPN is too PII as well as may not exist from primary school import
            # EmplyeeID should hold the MIS database ID that's autogenerated, good for all users.
            $user.Add('EmployeeNumber', $EmployeeNumber)
        }

        CreateADUser -UserObject $user -Password:$password | Add-GroupStudent
    }
}

function New-ExamUser{
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        # Maximum number of desired exam accounts
        [ValidateRange(0,[int]::MaxValue)]
        [int]$Max = $MAX_RETRY_NEW_USER
    )
    Process{
        $username = CreateUsername -Username 'Exam' -Max $Max
        $password = CreatePassword

        $user = @{
            GivenName = 'Exam'
            Surname = 'Candidate'
            name = $username
            DisplayName = "$Givenname $Surname"
            Path = "OU=Exams,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL"
            HomeDirectory = "\\bhs-fs01\home`$\Exams\$username"
            HomeDrive = 'N:'
            UserPrincipalName = "$username@BHS.INTERNAL"
            AccountPassword = ConvertTo-SecureString -AsPlainText -Force $password
            Enabled = $true
        }

        CreateADUser -UserObject $user -Password:$password
    }
}

function Get-ExamUser {
    [cmdletbinding()]
    Param(
        # Get specific exam accounts
        [Parameter(ValueFromPipeline)]
        [ValidateRange(0, [int]::MaxValue)]
        [int[]]$Number
    )
    $list = Get-ADUser -Filter * -SearchBase 'OU=Exams,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL'
    if ($Number) {
        $list = $list | Where-Object {
            [int]$psitem.surname -in $Number
        }
    }
    $list | Sort-Object {
        [int]$psitem.surname
    }
}

function CreateADUser {
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        $userObject,
        $password
    )
    Process {
        if ($pscmdlet.ShouldProcess($user.name, "New AD User")){
            $result = New-ADUser @userObject
            $account = Get-SchoolUser $userObject.name

            if($password){
                Add-member -InputObject $account -NotePropertyName Password -NotePropertyValue $password -force
            }
        }
        Write-Output $account
    }
}

function CreateUsername([string]$Username,[int]$Count,[int]$Max = $MAX_RETRY_NEW_USER){
    Write-Verbose "Test #$Count for $Username name collision"
    if($Count -eq 0){
        $calcUsername = "$Username"
    } else {
        $calcUsername = "$Username$Count"
    }
    if($calcUsername -match "['\s]" ){ # Strip spaces and appostrophies from usernames
        $calcUsername = $calcUsername.replace("'", '').replace(" ", '')
    }
    if($calcUsername.length -gt 20){ # Max character limit in AD for SamAccountName property is 20
        Throw "$calcUsername is over 20 characters"
    }
    if($Max -le $Count){
        Throw "Maximum attempts to make $calcUsername without conflict reached ($Max)"
    }
    try {
        $u = Get-SchoolUser -SamAccountName $calcUsername -ErrorAction Stop
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Verbose "No record found user as $calcUsername, returning this name to use."
        return $calcUsername
    }
    Write-Warning "Changed username. Found existing user as $($u.samaccountname)"

    # Recursive call to this function to test an appended username
    CreateUsername $Username ($Count + 1)
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
        Microsoft.ActiveDirectory.Management.ADUser, String
    .OUTPUTS
        System.IO.DirectoryInfo
    .EXAMPLE
        Get-ADGroupMember 10c_im1 | New-CADirectory -SubjectName iMedia -intake 2014
        Will create in this case 26 folders of the usernames from the 10c_Im1 gorup membership at
        the path \\filesahre\Intake 2014\iMedia\%username% with fullControl folder permissions by each username.
    .NOTES
        TODO: Validate subject name against Get-ClassProperty for consistancy.
    #>
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        # Username to create directroy and assign permissions with
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Name")]
        [string[]]
        $SamAccountName

        , # Intake Year
        [Parameter(Mandatory=$true,
                   Position=1)]
        [ValidateScript({ValidateIntake $psitem})]
        [string]$intake

        , # Full subject name e.g. 'Computer Science'
        [Parameter(Mandatory=$true,
                   Position=2)]
        [string]$SubjectName
    )
    Begin {
        [string]$PathRoot = "\\bhs-fs01\CA\Intake $intake"
        [string]$PathSubject = join-path $PathRoot $SubjectName

        # Validate intake path exists or to be created
        if(-not (Test-Path $PathRoot)){
            Write-Error "Missing '$PathRoot' Path"
            Write-Warning "Ensure AccessCAShared has read/execute to access this folder only for later mapping"
            $invalidRoot = $true
        }
        if(-not (Test-Path $PathSubject)){
            Write-Error "Missing '$PathSubject' Path"
            Write-Warning "Ensure desired CA_Intake_Subject group has read/execute to access this folder only for later mapping"
            $invalidsubject = $true
        }
        if($invalidRoot -or -$invalidSubject){
            Throw "Please Fix path errors to continue."
        }

        $Propagation = [System.Security.AccessControl.PropagationFlags]::None
        $Type =[System.Security.AccessControl.AccessControlType]::Allow
    }
    Process {
        # Create user folder for each username, assigning onwership permission.
        foreach($user in $SamAccountName){
            # TODO: Handle an existing directory with a warning
            try {
                Write-Verbose "Create Path for $(Join-Path $PathSubject $user)"
                if ($pscmdlet.ShouldProcess($(Join-Path $PathSubject $user), "Create Directory")){
                    $Directory = new-item -ItemType Directory -Path (Join-Path $PathSubject $user) -ErrorAction stop
                } else {
                    # Exit loop as WhatIf doesn't create a folder to set ACL's on
                    return
                }
            } catch [System.IO.IOException] {
                Write-Warning $psitem.exception.message
                return
                # skip the loop for this user.
            } catch {
                throw $psitem
                # Break with the full error for troubleshooting.
            }
            $item = get-acl $Directory

            $Principal = New-Object System.Security.Principal.NTAccount($user)
            $Entry = New-Object System.Security.AccessControl.FileSystemAccessRule($Principal, 'Modify', 'ContainerInherit,ObjectInherit', $Propagation, $Type)
            $item.AddAccessRule($Entry)
            Write-Verbose ("Apply ACL: {0} {1} {2}" -f $entry.AccessControlType, $entry.IdentityReference, $entry.FileSystemRights)
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
        C:\PS> Reset-ADPassword -Identity test01
        Generate a new password for test01 account, enable the account, Require password changed at logon and warn if user will be unable to.

        Confirm
        Are you sure you want to perform this action?
        Performing the operation "Reset Account Password" on target "CN=Test01,OU=Guests,OU=...".
        [Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): y
        WARNING: 'PasswordNeverExpires' for Test01 is set to true. The account will not be required to change the password at next logon.

        EmployeeNumber :
        Forename       : Test01
        Surname        :
        Username       : Test01
        Password       : reset195
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

        , #
        $Prefix = 'birkdale'
    )
    Begin {
        $passwordNeverExpiresException = "'PasswordNeverExpires' for this account is set to true. The account will not be required to change the password at next logon."
    }
    Process{
        $resetList = $Identity | get-aduser -properties employeeNumber,EmailAddress
        foreach ($user in $resetlist) {
            $password = CreatePassword -prefix $Prefix
            if ($pscmdlet.ShouldProcess($user, "Reset Account Password")){
                Set-ADAccountPassword -Identity $user.samAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force)
                Enable-ADAccount -Identity $user.samAccountName
                try {
                    Set-aduser -Identity $user.samAccountName -ChangePasswordAtLogon $true -ErrorAction Stop
                } catch {
                    if($psitem.Exception.message -eq $passwordNeverExpiresException){
                        Write-Warning $passwordNeverExpiresException.replace('this account', $user.samAccountName)
                    } else {
                        throw
                    }
                }
            }
        }
        $resetList |
            Select-Object @(
                @{
                    name='AdmissionNumber';
                    expression={ $_.EmployeeNumber }
                }
                @{
                    name='Forename';
                    expression={ $_.Givenname }
                }
                'Surname'
                'EmailAddress'
                @{
                    name='Username';
                    expression={ $_.SamAccountName }
                }
            ) |
            Add-member -MemberType NoteProperty -Name Password -Value $password -PassThru |
            Write-Output
    }
}

Set-Alias -name CreatePassword -value New-EasyPassword
function New-EasyPassword {
    <#
    .SYNOPSIS
        Generate a new password
    .DESCRIPTION
        Create easy to read and type passwords for resetting accounts that exist for a short time.

        Randomly using and ascii table for a-Z, 1-9 with punctuation excluding ambiguous charaters like;
        O, 0, I, l, W, w, V v
    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    .INPUTS
        None
    .OUTPUTS
        String
    .EXAMPLE
        New-EasyPassword -Prefix welcome -MinLength 12
        welcomevDVRm$
    .EXAMPLE
        New-EasyPassword -MinLength 7
        ZzT:K.OG
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        # Minimum Password Length
        [Parameter(Position = 0)]
        [ValidateRange(1, [int]::MaxValue)]
        [Alias('Min')]
        [int]
        $MinLength = 10

        , # Maximum Password Length
        [Parameter(Position = 1)]
        [ValidateRange(2, [int]::MaxValue)]
        [Alias('Max')]
        [int]
        $MaxLength = $MinLength + 2

        , # Prefix to the generated password to meet length requirments but lower complexity for quick resets
        [Parameter(Position = 2)]
        [string]
        $Prefix = 'birkdale'
    )
    # Define the password length to be just the max length if a range is otherwise undefined.
    if ($PSBoundParameters.ContainsKey('MaxLength') -and -not $PSBoundParameters.ContainsKey('MinLength')) {
        $MinLength = $MaxLength - 1
    }
    if ($MinLength -gt $MaxLength) {
        Throw [System.Management.Automation.ParameterBindingException]::New("Max length($MaxLength) must be greater than the Minimum($MinLength)")
    }
    if ($Prefix.length -ge $MaxLength-1) {
        Throw [System.Management.Automation.ParameterBindingException]::New("Prefix($Prefix) must be not be longer than the Maximum($MAXLength) -1 to add random characters")
    }
    if ($Prefix.length -eq $MinLength) {
        Throw [System.Management.Automation.ParameterBindingException]::New("Prefix($Prefix) must not be the same as the minimum length($MinLength) to add random characters")
    }

    if ($Prefix) {
        $MinLength -= $Prefix.length
        $MaxLength -= $Prefix.length
    }

    if ($MinLength -eq $MaxLength) {
        $length = $MinLength
    }
    else {
        $length = Get-Random -Minimum $MinLength -Maximum $MaxLength
    }

    $letters = (33..122) |
    Where-Object {
        # Using an ASCII table, exclude character numbers found hard to say or type.
        # Consider removing O, 0, I, l, W, w, V v if you can't control the font the user is presented with.
        $psitem -notin 34, 38, 39, 42, 44, 47, 60, 62 + 91..96
    } |
    Get-Random -Count $length |
    ForEach-Object {
        [char]$psitem
    }

    Write-Output "$Prefix$(-join $letters)"
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
        $Identity
    )
    Process{
        $Identity |
            where-Object { (Test-HomeDirectory $psitem).result -eq $false } |
            foreach-Object {
                $location = New-Item -ItemType Directory -Path $psitem.homeDirectory

                $Propagation = [System.Security.AccessControl.PropagationFlags]::None
                $Type =[System.Security.AccessControl.AccessControlType]::Allow
                $Principal = New-Object System.Security.Principal.NTAccount($psitem.samAccountName)

                $Entry = New-Object System.Security.AccessControl.FileSystemAccessRule($Principal, 'Modify', 'ContainerInherit,ObjectInherit', $Propagation, $Type)

                $ACL = Get-ACL $location
                try{
                    $ACL.AddAccessRule($Entry)
                } catch {
                    # User somehow doesn't exist to actually set a permission when referenced
                    # Cleanup before end
                    Remove-Item $location
                    Write-Error "Could not create ACL for: $($Entry.IdentityReference)"
                    Throw $psitem
                }

                Set-ACL $psitem.homeDirectory $ACL

                $psitem.homeDirectory = $location
                Write-Output $psitem
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

Set-Alias Get-OrgUser Get-SchoolUser -Description "Alias to a name that is short to type for auto-completion"
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
    .EXAMPLE
        PS C:\> Get-SchoolUser -EmployeeNumber 001122
        Get the exact user account name from the number. The leading zeros are not required.
        You will get an error if there are multiple results found.

        GivenName         : Student
        Surname           : Orgname
        SamAccountName    : student
        DistinguishedName : CN=Student Orgname,OU=Test,OU=ORG,DC=ORG,DC=INTERNAL
        Enabled           : True
        HomeDirectory     : \\org-server01\files\students\Test\student
        EmployeeNumber    : 001122
        EmailAddress      : student@example.com
    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADUser
    .NOTES
        General notes
        TODO: Try change EmployeeNumber as Int to make just '<cmdlet> 0000' work as input. Also accepts '00000' pipes
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
        [Parameter(Position=0, Mandatory, ParameterSetName='Either', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string[]]
        $SamAccountName

        , # Admission/Employee Number
        [Parameter(Position=0, Mandatory, ParameterSetName='Get1', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [Parameter(Position=1, Mandatory, ParameterSetName='Either', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidateLength(1,6)]
        [ValidatePattern('^\d+$')]
        [Alias("AdmissionNumber","Adno")]
        [string[]]
        $EmployeeNumber

        , # MIS Record ID/Employee Number
        [Parameter(Position=0, Mandatory, ParameterSetName='GetID', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidateRange(0,6)]
        [Alias("physicalDeliveryOfficeName")]
        [int[]]
        $ID
    )
    Begin{
        $props = @(
            'HomeDirectory',
            'EmployeeID',
            'EmployeeNumber',
            'EmailAddress',
            'physicalDeliveryOfficeName'
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
                Write-Verbose "Specific powershell get-ADUser"
                $SamAccountName | Get-ADUser -properties $props |
                    Select-Object -Property $outputFields |
                    Write-Output
                return
            }
            'Search' {
                $queryString = "(&(objectClass=user)(sn=$Surname)(givenname=$givenname))"
                Write-Verbose "LDAP Search Query String: $queryString"
                Get-ADUser -LDAPfilter $queryString -properties $props |
                    Select-Object -Property $outputFields |
                    Write-Output
            }
            'Get1' {
                $queryString = "(&(objectClass=user)(employeenumber=$( $EmployeeNumber.padLeft(6,'0') )))"
                Write-Verbose "LDAP Get1 Query String: $queryString"
                $output = Get-ADUser -LDAPfilter $queryString -properties $props |
                    Select-Object -Property $outputFields
                if($output.length -eq 0){
                    throw [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]::new("No user found by employee number")
                }
                if($output.length -gt 1){
                    Write-Error "Multiple Users found with the same EmplyeeNumber field, please correct this."
                }
                Write-Verbose ("Found {0} User(s)" -f (Measure-object -InputObject $output).count)
                Write-Output $output
            }
            'GetID' {
                $queryString = "(&(physicalDeliveryOfficeName=$( $physicalDeliveryOfficeName )))"
                Write-Verbose "LDAP GetID Query String: $queryString"
                $output = Get-ADUser -LDAPfilter $queryString -properties $props |
                    Select-Object -Property $outputFields
                if($output.length -eq 0){
                    throw [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]::new("No user found by physicalDeliveryOfficeName")
                }
                if($output.length -gt 1){
                    Write-Error "Multiple Users found with the same physicalDeliveryOfficeName field, please correct this."
                }
                Write-Verbose ("Found {0} User(s)" -f (Measure-object -InputObject $output).count)
                Write-Output $output
            }
            'Either' {
                $queryString = "( &(objectClass=user) (|{0} {1} ) )" -f @(
                    ($EmployeeNumber.ForEach({"(employeenumber=$($_.padLeft(6,'0')))"}) -join ' '),
                    ($SamAccountName.ForEach({"(samaccountname=$_)"}) -join ' ')
                )
                Write-Verbose "LDAP Either Query String: $queryString"
                $output = Get-ADUser -LDAPfilter $queryString -properties $props |
                    Select-Object -Property $outputFields
                if($output.length -eq 0){
                    throw [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]::new("No user found by employee number")
                }
                if($output.count -gt 1){
                    Write-Warning "Multiple Users found with the same EmployeeNumber field, please correct this."
                }
                Write-Verbose ("Found {0} User(s)" -f (Measure-object -InputObject $output).count)
                Write-Output $output
            }
        }

    }
}

function Get-NewStudent {
    <#
    .SYNOPSIS
        Get users missing in AD from the MIS Source
    .DESCRIPTION
        Compares all ad studnets OU users against EmployeeID
    #>
    [CmdletBinding()]
    param (

    )
    process {
        $AD_LIST = Get-ADUser -Properties EmployeeID,EmployeeNumber,emailaddress -SearchBase 'OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL' -Filter *
        $MIS_LIST = Import-SimsUser
        compare-object $MIS_LIST $AD_LIST -Property EmployeeID -PassThru | Where-Object SideIndicator -eq '<='
    }
}

function Get-LeftStudent {
    <#
    .SYNOPSIS
        Get users missing in AD from the MIS Source
    .DESCRIPTION
        Compares all ad studnets OU users against EmployeeID
    #>
    [CmdletBinding()]
    param (

    )
    process {
        $AD_LIST = Get-ADUser -Properties EmployeeID,EmployeeNumber,emailaddress -SearchBase 'OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL' -Filter *
        $MIS_LIST = Import-SimsUser
        compare-object $MIS_LIST $AD_LIST -Property EmployeeID -PassThru | Where-Object SideIndicator -eq '<='
    }
}
