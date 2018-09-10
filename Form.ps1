function Get-Form{
    setupModule -ErrorAction Stop
    $FormList | escapeName
}
function Get-FormMember{
    Param(
        [parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Class')]
        $Form
    )
    Begin{
        setupModule -ErrorAction Stop
    }
    Process{
        $AdmissionNumber = $FormMembers | where { (escapeName $_.Class) -eq $form} | select -ExpandProperty Adno

        $AdmissionNumber | foreach {
            get-aduser -Filter {EmployeeNumber -eq $psitem} -Properties EmployeeNumber
        }
    }
}

function Test-Form{
    Param(
        # Show values only from the chosen source, <= List, => AD
        [parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Both', 'List', 'AD')]
        $Filter = 'Both'
    )
    $ADList = Get-ADGroup -Filter * -SearchBase 'OU=Form Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL'

    if($ADList -eq $null){
        Write-Error "No Forms found from the AD" -ErrorAction Stop
    }
    switch ($Filter)
    {
        'List' {
            Compare-Object (Get-Form) $ADList.name  -IncludeEqual  -PassThru | where SideIndicator -eq '<='
        }
        'AD' {
            Compare-Object (Get-Form) $ADList.name  -IncludeEqual  -PassThru | where SideIndicator -eq '=>'
        }
        Default {
            Compare-Object (Get-Form) $ADList.name  -IncludeEqual
        }
    }

}
function Test-FormMember{
    Param(
        # Form the user should be a member of
        [parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Class')]
        [string]
        $Form

        , # Show values only from the chosen source, <= List, => AD
        [parameter(Position=1,
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Both', 'List', 'AD')]
        [string]
        $Filter = 'Both'
    )
    $ADList = Get-ADGroupMember -Identity $Form | get-aduser -Properties EmployeeNumber

    if($ADList -eq $null){
        Write-Warning "No members found in $form from the AD"
        $Filter = 'List'
    }
    switch ($Filter)
    {
        'List' {
            Get-FormMember $form
        }
        'AD' {
            Compare-Object (Get-FormMember $form) $ADList  -IncludeEqual -Property EmployeeNumber -PassThru | where SideIndicator -eq '=>'
        }
        Default {
            Compare-Object (Get-FormMember $form) $ADList  -IncludeEqual -Property EmployeeNumber
        }
    }

}
function Get-FormADMember{
    <#
    .SYNOPSIS
        Show the counts of users found within each form group
    .DESCRIPTION
        To quickly check the state of the AD membership, use this command to find all the total users in each group.

        Check these numbers yourself against sims, use Test-FormMember to investigate specific forms further.
    .EXAMPLE
        Get-FormADMember

        Count Name                      Group
        ----- ----                      -----
            27 CN=7AS,OU=Form Groups,... {CN=17...
            26 CN=7GA,OU=Form Groups,... {CN=17...
            28 CN=7JM,OU=Form Groups,... {CN=17...
            28 CN=7HJJ,OU=Form Groups... {CN=17...
            28 CN=7LK,OU=Form Groups,... {CN=17...
            27 CN=7JW,OU=Form Groups,... {CN=17...
            24 CN=8HAD,OU=Form Groups... {CN=16...
            25 CN=8CMC,OU=Form Groups... {CN=16...
            24 CN=8SHW,OU=Form Groups... {CN=16...
            24 CN=8ZF,OU=Form Groups,... {CN=16...
            23 CN=8LM,OU=Form Groups,... {CN=16...
            24 CN=8SK,OU=Form Groups,... {CN=16...
            28 CN=9JCS,OU=Form Groups... {CN=15...
            28 CN=9JB,OU=Form Groups,... {CN=15...
            24 CN=9JQ,OU=Form Groups,... {CN=15...
            26 CN=9DAW,OU=Form Groups... {CN=15...
            24 CN=9EZM,OU=Form Groups... {CN=15...
            24 CN=10JSW,OU=Form Group... {CN=15...
            21 CN=10CW,OU=Form Groups... {CN=14...
            24 CN=10LH,OU=Form Groups... {CN=14...
            21 CN=10PZM,OU=Form Group... {CN=14...
            22 CN=10JC,OU=Form Groups... {CN=14...
            22 CN=10JG,OU=Form Groups... {CN=14...
            24 CN=11AM,OU=Form Groups... {CN=13...
            23 CN=11SZB,OU=Form Group... {CN=13...
            23 CN=11CS,OU=Form Groups... {CN=13...
            22 CN=11SEM,OU=Form Group... {CN=13...
            25 CN=11EJ,OU=Form Groups... {CN=13...
    .EXAMPLE
        Get-FormADMember 9jb | select -ExpandProperty group | sort | ft name

        Return the user accounts that are members of a specific form.
    #>
    Param(
        # Accepts a wildcard filter.
        [string]$Name = '*'
    )
    Get-ADGroup -SearchBase "OU=Form Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL" -Filter {Name -like $Name} |
        foreach {
            Get-ADGroupMember -Identity $psitem |
                add-member -PassThru -MemberType 'NoteProperty' -Name 'FormName' -value $psitem -force
        } |
        Group-Object -Property 'FormName'
}

function New-Form{
    Param(
        [parameter(Mandatory=$true,
                   ValueFromPipeline=$true)]
        [string]
        $name
    )
    Process{
        New-ADGroup -GroupScope Global -GroupCategory Security -Name $name -Path 'OU=Form Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL' -PassThru
    }
}

function Sync-Form{
    Test-Form -Filter List | New-Form
    Test-Form -Filter AD | Remove-ADGroup
}
function Sync-FormMember{
    Get-Form | foreach {
        Add-ADGroupMember -Identity $psitem -Members ($psitem | Test-FormMember -Filter List)
    }
}
