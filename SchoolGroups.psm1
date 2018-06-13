﻿function setupModule{
    $Datasource = Get-ChildItem -Filter "ClassMembers-*.csv" -Path $env:TEMP | Sort-Object -Property CreationTimeUtc | Select-Object -Last 1
    if($Datasource){
        $script:SimsReport = import-csv $Datasource.fullname

        $script:ClassMembers = $SimsReport | Where-Object Class -NotLike "CLS *" | Where-Object {-not [string]::IsNullOrEmpty($psitem.class)}
        $script:FormMembers  = $SimsReport | Where-Object Class    -Like "CLS *" | Where-Object {-not [string]::IsNullOrEmpty($psitem.class)}

        $script:ClassList = $ClassMembers | Select-Object -Unique -ExpandProperty class
        $script:FormList  = $FormMembers  | Select-Object -Unique -ExpandProperty class
    } else {
        Write-Warning "Run 'New-Report' for fresh MIS data to compare user accounts with"
    }
}

function escapeName{
    [OutputType([string])]
    Param(
        [parameter(Mandatory=$true,
                   ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $name
    )
    Process{
        if($name.StartsWith('CLS ')){
            return $name.replace('CLS ', '')
        }
        return $name.replace('/','_').replace('+','t')
    }
}

function ValidateIntake {
    [int]$year = (get-date).year
    [int]$test = $PSItem
    if( ($test -le $year) -and ($test -ge $year-5) ){
        return $true
    } else {
        Throw "$test is not an active intake year."
    }
}

# TODO: Function that replaces SideIndicator property with 2 booleans for AD and MIS

setupModule

. "$PSScriptRoot\Form.ps1"
. "$PSScriptRoot\Class.ps1"
. "$PSScriptRoot\Adno.ps1"
. "$PSScriptRoot\User.ps1"
. "$PSScriptRoot\Sims.ps1"
. "$PSScriptRoot\Task.ps1"
