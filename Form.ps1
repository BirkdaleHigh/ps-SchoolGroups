function Get-Form{
    $FormList | escapeName
}
function Get-FormMember{
    Param(
        [parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('Class')]
        $Form
    )
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
    Test-Form -Filter AD | Remove-ADGroup -WhatIf
}
function Sync-FormMember{
    Get-Form | foreach {
        Add-ADGroupMember -Identity $psitem -Members ($psitem | Test-FormMember -Filter List)
    }
}
