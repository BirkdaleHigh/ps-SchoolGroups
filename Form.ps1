function Get-Form {
    $script:FormList.foreach({
        [OrgForm]::New($psItem)
    })
}

function Get-FormMember {
    Param(
        [parameter(ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('Class')]
        $Form
    )
    Process {
        $AdmissionNumber = $FormMembers | where-Object { (escapeName $_.Class) -eq $form } | select -ExpandProperty Adno

        $AdmissionNumber | foreach-Object {
            get-aduser -Filter { EmployeeNumber -eq $psitem } -Properties EmployeeNumber
        }
    }
}

function Test-Form {
    Param(
        # Show values only from the chosen source, <= List, => AD
        [parameter(ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateSet('Both', 'List', 'AD')]
        $Filter = 'Both'
    )
    $ADList = Get-ADGroup -Filter * -SearchBase 'OU=Form Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL'

    switch ($Filter) {
        'List' {
            if ($null -eq $ADList) {
                Write-Warning "No Forms found, Were you expecting no forms in the OU?"
                return get-form
            }
            Compare-Object (Get-Form) $ADList.name  -IncludeEqual  -PassThru | Where-Object SideIndicator -eq '<='
        }
        'AD' {
            if ($null -eq $ADList) {
                Write-Warning "No Forms found, Were you expecting no forms in the OU?"
                return $null
            }
            Compare-Object (Get-Form) $ADList.name  -IncludeEqual  -PassThru | Where-Object SideIndicator -eq '=>'
        }
        Default {
            if ($null -eq $ADList) {
                Write-Warning "No Forms found, Were you expecting no forms in the OU?"
                return get-form
            }
            Compare-Object (Get-Form) $ADList.name  -IncludeEqual
        }
    }

}
function Test-FormMember {
    Param(
        # Form the user should be a member of
        [parameter(Mandatory,
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('Class')]
        [string]
        $Form

        , # Show values only from the chosen source, <= List, => AD
        [parameter(Position = 1,
            ValueFromPipelineByPropertyName)]
        [ValidateSet('Both', 'List', 'AD')]
        [string]
        $Filter = 'Both'
    )
    $ADList = Get-ADGroupMember -Identity $Form | get-aduser -Properties 'EmployeeNumber'

    if ($null -eq $ADList) {
        Write-Warning "No members found in $form from the AD"
        $Filter = 'List'
    }
    switch ($Filter) {
        'List' {
            Get-FormMember $form
        }
        'AD' {
            Compare-Object (Get-FormMember $form) $ADList  -IncludeEqual -Property 'EmployeeNumber' -PassThru | where SideIndicator -eq '=>'
        }
        Default {
            Compare-Object (Get-FormMember $form) $ADList  -IncludeEqual -Property 'EmployeeNumber'
        }
    }

}
function Get-FormADMember {
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
    Get-ADGroup -SearchBase "OU=Form Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL" -Filter { Name -like $Name } |
        Foreach-Object {
            Get-ADGroupMember -Identity $psitem |
                add-member -PassThru -MemberType 'NoteProperty' -Name 'FormName' -value $psitem -force
        } |
        Group-Object -Property 'FormName'
}

function New-Form {
    <#
    .SYNOPSIS
        Create a new form AD group in the correct OU
    .DESCRIPTION
        Creates an new AD group in the correct OU with an email address for the group.
    #>
    Param(
        [parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        [string]
        $Name
    )
    Process {
        $splat = @{
            GroupScope    = 'Global'
            GroupCategory = 'Security'
            Name          = $Name
            Path          = 'OU=Form Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL'
            PassThru      = $true
        }
        New-ADGroup @splat | Set-ADGroup -Replace @{"mail" = "$Name@birkdalehigh.co.uk" } -PassThru
    }
}

function Sync-FormMember {
    <#
        .NOTE
            TODO: Remove AD members no longer listed from MIS
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
        # Form name to synchronize
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Form')]
        [String[]]
        $Name = (Get-Form)
    )
    $Name | ForEach-Object {
        Add-ADGroupMember -Identity $psitem -Members ($psitem | Test-FormMember -Filter 'List')
    }
}
