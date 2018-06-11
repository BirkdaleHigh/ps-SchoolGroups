class Class {
    [string]$Code
    [string]$ID
    [int]$Year
    [string]$Set
    [string]$FullName
    [int]$ClassNumber
}

function Get-Class{
    setupModule -ErrorAction Stop
    $ClassList | escapeName
}
function Get-ClassProperty{
<#
.Synopsis
    Decode the subject code into an object
.Description
    Split the subject code like 8E5_Fr into their meaning.

    <Year><Set>_<SubjectID><ClassNumber>
.EXAMPLE
    Get-ClassProperty 11A_Xl1 | format-table

    ID FullName               Code     Year ClassNumber Set
    -- --------               ----     ---- ----------- ---
    Xl Extra Literature       11A_Xl1  11   1           A
.EXAMPLE
    Get-Class | Get-ClassProperty | ft

    ID FullName               Code     Year ClassNumber Set
    -- --------               ----     ---- ----------- ---
    En English                8JM_En   8                JM
    Fr French                 8JM_Fr   8                JM
    Sp Spannish               8JM_Sp   8                JM
    Cs Computer Science       8M3_Cs   8                M3
    Ma Maths                  8M3_Ma   8                M3
    ...
.EXAMPLE
    Get-Class | Get-ClassProperty | where {($_.Year -eq 8) -and ($_.ID -eq 'Cs')} | format-table

    ID FullName         Code   Year ClassNumber Set
    -- --------         ----   ---- ----------- ---
    Cs Computer Science 8M3_Cs 8                M3
    Cs Computer Science 8M5_Cs 8                M5
    Cs Computer Science 8M1_Cs 8                M1
    Cs Computer Science 8M2_Cs 8                M2
    Cs Computer Science 8M6_Cs 8                M6
    Cs Computer Science 8M4_Cs 8                M4
.EXAMPLE
    Get-Class | Get-ClassProperty | Sort id | select id,fullname -Unique

    Get a list of all class codes that exist in use and their full name.

    ID  FullName
    --  --------
    Ar  Art
    Bi  Biology
    Bt  BTEC Sport
    Ch  Chemistry
    ...
#>
    [OutputType([class])]
    Param(
        # Class code from from sims, replace '/' replaced with '_'
        [parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern('^1?[01789][a-zA-Z\d]+_[a-zA-Z]+\d?$')]
        [Alias('Code')]
        [string[]]
        $Name
    )
    Begin{
        $fullName = @{
            'Ar' = 'Art'
            'Bi' = 'Biology'
            'Bt' = 'BTEC Sport'
            'Bu' = 'Business Studies'
            'Ch' = 'Chemistry'
            'Cs' = 'Computer Science'
            'Dr' = 'Drama'
            'Dt' = 'Design Technology'
            'En' = 'English'
            'Fo' = 'Food Technology'
            'Ft' = 'Food Technical'
            'Fr' = 'French'
            'Gg' = 'Geography'
            'Hi' = 'History'
            'Im' = 'I-Media'
            'It' = 'Information Technology'
            'Ma' = 'Maths'
            'Mu' = 'Music'
            'Pe' = 'Physical Education'
            'Ph' = 'Physics'
            'Re' = 'Religious Education'
            'Rm' = 'Resistant Materials'
            'St' = 'Study Plus'
            'Sc' = 'Science'
            'Sb' = 'BTEC Science'
            'Sp' = 'Spannish'
            'Te' = 'Technology'
            'Ts' = 'Triple Science'
            'Xl' = 'Extra Literature'
        }
    }
    Process{
        foreach($item in $Name){
            $Output = @{
                Code        = $item
                ID          = $ID = [regex]::match($item, '_([a-zA-Z]+)').Groups[1].Value
                Year        = [regex]::match($item, '^(1?[01789])').Groups[1].Value #also bounds check this to 7-11
                Set         = [regex]::match($item,  '1?[01789]([a-zA-Z\d]+)_.*').Groups[1].Value
                FullName    = $fullname[$ID]
                ClassNumber = [regex]::match($item, '(\d)?$').Groups[1].Value
            }
            New-Object Class -Property $Output
        }
    }
}

function Test-Class{
    Param(
        # Show values only from the chosen source, <= List, => AD
        [parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Both', 'List', 'AD')]
        $Filter = 'Both'
    )
    $ADList = Get-ADGroup -Filter * -SearchBase 'OU=Class Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL'

    if($ADList -eq $null){
        Write-Error "No Forms found from the AD" -ErrorAction Stop
    }
    switch ($Filter)
    {
        'List' {
            Compare-Object (Get-Class) $ADList.name  -IncludeEqual  -PassThru | where SideIndicator -eq '<='
        }
        'AD' {
            Compare-Object (Get-Class) $ADList.name  -IncludeEqual  -PassThru | where SideIndicator -eq '=>'
        }
        Default {
            Compare-Object (Get-Class) $ADList.name  -IncludeEqual
        }
    }
}

function New-Class{
    <#
    .SYNOPSIS
        Wrap New-ADGroup to create a class group in AD
    .DESCRIPTION
        Place the class groups in a specific OU path.
        Group needs to be universal in order to later get assigned an email address as a security group.
    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADGroup
    #>
    Param(
        [parameter(Mandatory=$true,
                   ValueFromPipeline=$true)]
        [string[]]
        $name
    )
    Process{
        foreach($class in $name){
            $group = @{
                'GroupScope' = 'Universal'
                'GroupCategory' = 'Security'
                'PassThru' = $True
                'Name' = $class
                'Path' = 'OU=Class Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL'
            }
            New-ADGroup @group
        }
    }
}

function Sync-Class{
    Test-Class -Filter List | New-Class
    Test-Class -Filter AD | Remove-ADGroup
}

function Get-ClassMember{
    <#
    .SYNOPSIS
        List AD accounts that are supposed to be members of a class.
    .DESCRIPTION
        Reference the MIS list of Id's to get AD Accounts for users that are supposed to be in the given class group.
    .INPUTS
        [string] Class Code
    .OUTPUTS
        AD user
    #>
    Param(
        [parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        $Class
    )
    Begin{
        setupModule -ErrorAction Stop
    }
    Process{
        $AdmissionNumber = $script:ClassMembers | where-object { (escapeName $_.Class) -eq $Class} | select-object -ExpandProperty Adno
        if([string]::IsNullOrEmpty($AdmissionNumber)){
            Throw "No members found in $Class from MIS dataset"
        }

        $filter = "(&(objectClass=user)(|(employeenumber={0})))" -f ($AdmissionNumber.padLeft(6,'0') -join ')(employeenumber=')
        Write-Verbose $filter
        get-aduser -Properties EmployeeNumber -LDAPFilter $filter
    }
}
function Get-ClassADGroupMember{
    <#
    .SYNOPSIS
        Get AD Accounts that are in the class
    .EXAMPLE
    #>
    Param(
        [Parameter(Mandatory,Position=0)]
        [Alias("class")]
        [string]
        $Name
    )
    get-aduser -Properties EmployeeNumber -LDAPFilter "(&(objectClass=user)(memberof=CN=$Name,OU=Class Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL))"
}

function Test-ClassMember{
    <#
    .SYNOPSIS
        Compares MIS to AD for present/missing account group memberships
    .DESCRIPTION
        ADGroup is true if user is found in the AD Class Security Group
        MIS is true if user if found in the MIS dataset

        Calls Get-ClassADGroupMember to find all users currently in the group.
        Calls Get-ClassMember to get all AD accounts for users from the MIS Dataset

        Compares these two sets to add resulting properties to use objects.
    .EXAMPLE
        Test-ClassMember 10e4_en
        Report group membership state of current and expected users.

        ADGroup   MIS DistinguishedName  EmployeeNumber Enabled GivenName Name      ObjectClass
        -------   --- -----------------  -------------- ------- --------- ----      -----------
           True  True CN=user,...        004841            True user      lastname  user
           True  True CN=user,...        004844            True user      lastname  user
           True  True CN=user,...        005152            True user      lastname  user
           True False CN=user,...        004949            True user      lastname  user
          False  True CN=user,...        004839            True user      lastname  user
          False  True CN=user,...        004876            True user      lastname  user
          False  True CN=user,...        004939            True user      lastname  user
    .INPUTS
        String, Class Group Name
    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADUser
    #>
    Param(
        # Form the user should be a member of
        [parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]
        $Class
    )
    $ADList = @(Get-ClassADGroupMember $Class)

    if([string]::IsNullOrEmpty($ADList)){
        Write-Warning "No members found in $Class from the AD"
    }

    $misList = @(Get-ClassMember $Class -ErrorAction SilentlyContinue)
    Compare-Object $misList $ADList -IncludeEqual -Property EmployeeNumber -PassThru |
        ForEach-Object {
            Add-Member -inputObject $PSItem -MemberType NoteProperty -Name "ADGroup" -Value ($PSItem.SideIndicator -in '=>','==') -Force
            Add-Member -inputObject $PSItem -MemberType NoteProperty -Name "MIS"     -Value ($PSItem.SideIndicator -in '<=','==') -Force
            $psitem.PSObject.properties.remove("SideIndicator")
            Write-Output $psitem
        }
}

function Sync-ClassMember{
    <#
    .Synopsis
        Make the AD group members match the provided MIS list.
    .DESCRIPTION
        For each class in the report add the members found only in this list
        For each class in the report remove any members only found in the AD

        Filters the output from Test-ClassMember to add/remove users.
    .EXAMPLE
        Sync-ClassMember 10e4_en -Verbose -WhatIf
        Test what is about to happen to the group when sync runs

        VERBOSE: (&(objectClass=user)(|(employeenumber=000001)(employeenumber=000007)...))
        What if: Performing the operation "Modify group members" on target "10e4_en".
        VERBOSE: Class: 10e4_en, New Total: 16, Add: 5 from MIS, Remove: 1 only in AD.
    #>
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        # Choose Classes to Syncronize
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Class = (Get-Class)
    )
    $Class | ForEach-Object {
        $users = Test-ClassMember $psitem
        $add = @($users | where-object { $psitem.MIS -and -not $psitem.ADGroup })
        $remove = @($users | where-object MIS -eq $false)

        if ($pscmdlet.ShouldProcess($psitem, "Modify group members")){
            if($add){
                Add-ADGroupMember -Identity $psitem -Members $add > $null
            }
            if($remove){
                Remove-ADGroupMember -Identity $psitem -Members $remove -confirm:$false
            }
        }

        Write-Verbose (
            "Class: {0}, New Total: {1}, Add: {2} from MIS, Remove: {3} only in AD." -f @(
                $psitem
                $users | where-object adgroup | Measure-Object | Select-Object -expandproperty count
                $add.length
                $remove.length
            )
        )
    }
}

function Split-ClassList{
    <#
    .SYNOPSIS
        Split the full user list into each class
    .DESCRIPTION
        Split full user list into separate lists to hand out for teachers class'
    .EXAMPLE
        C:\PS> <example usage>
        Explanation of what the example does
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        Output (if any)
    .NOTES
        General notes
    #>
    Param(
        # List of the whole Year Group
        $YearGroup

        , # List of the class members
        $Class
    )
    $YearGroup | where adno -in $class.adno | select givenname,surname,SamAccountName,password
}

<#
notes for testing

Check classMembers report has the same number of members as the AD group

#>