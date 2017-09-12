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
        $name
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
        $Output = @{
            Code        = $name[0]
            ID          = $ID = [regex]::match($name, '_([a-zA-Z]+)').Groups[1].Value
            Year        = [regex]::match($name, '^(1?[01789])').Groups[1].Value #also bounds check this to 7-11
            Set         = [regex]::match($name,  '1?[01789]([a-zA-Z\d]+)_.*').Groups[1].Value
            FullName    = $fullname[$ID]
            ClassNumber = [regex]::match($name, '(\d)?$').Groups[1].Value
        }
        New-Object Class -Property $Output
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
    Param(
        [parameter(Mandatory=$true,
                   ValueFromPipeline=$true)]
        [string]
        $name
    )
    Process{
        New-ADGroup -GroupScope Global -GroupCategory Security -Name $name -Path 'OU=Class Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL' -PassThru
    }
}

function Sync-Class{
    Test-Class -Filter List | New-Class
    Test-Class -Filter AD | Remove-ADGroup
}

function Get-ClassMember{
    Param(
        [parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        $Class
    )
    Begin{
        setupModule -ErrorAction Stop
    }
    Process{
        $AdmissionNumber = $ClassMembers | where { (escapeName $_.Class) -eq $Class} | select -ExpandProperty Adno

        $AdmissionNumber | foreach {
            get-aduser -Filter {EmployeeNumber -eq $psitem} -Properties EmployeeNumber
        }
    }
}
function Get-ClassADMember{
    <#
    .SYNOPSIS
        Show the counts of users found within each form group
    .DESCRIPTION
        To quickly check the state of the AD membership, use this command to find all the total users in each group.

        Check these numbers yourself against sims, use Test-FormMember to investigate specific forms further.

    .EXAMPLE
    #>
    Param(
        # Accepts a wildcard filter.
        [string]$Name = '*'
    )
    Get-ADGroup -SearchBase "OU=Class Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL" -Filter {Name -like $Name} |
        foreach {
            Get-ADGroupMember -Identity $psitem |
                add-member -PassThru -MemberType 'NoteProperty' -Name 'ClassName' -value $psitem -force
        } |
        Group-Object -Property 'ClassName'
}

function Test-ClassMember{
    Param(
        # Form the user should be a member of
        [parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]
        $Class

        , # Show values only from the chosen source, <= List, => AD
        [parameter(Position=1,
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Both', 'List', 'AD')]
        [string]
        $Filter = 'Both'
    )
    $ADList = Get-ADGroupMember -Identity $Class | get-aduser -Properties EmployeeNumber

    if($ADList -eq $null){
        Write-Warning "No members found in $Class from the AD"
        $Filter = 'List'
    }
    switch ($Filter)
    {
        'List' {
            Get-ClassMember $Class
        }
        'AD' {
            Compare-Object (Get-ClassMember $Class) $ADList  -IncludeEqual -Property EmployeeNumber -PassThru | where SideIndicator -eq '=>'
        }
        Default {
            Compare-Object (Get-ClassMember $Class) $ADList  -IncludeEqual -Property EmployeeNumber
        }
    }

}

function Sync-ClassMember{
<#
.Synopsis
    Make the AD group members match the provided list.
.DESCRIPTION
    For each class in the report add the members found only in this list
    For each class in the report remove any members only found in the AD
#>
    Get-Class | foreach {
        $add = $psitem | Test-ClassMember -Filter List
        if($add){
            Add-ADGroupMember -Identity $psitem -Members $add > $null
        }

        $remove = $psitem | Test-ClassMember -Filter AD
        if($remove){
            Remove-ADGroupMember -Identity $psitem -Members $remove -confirm:$false
        }
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