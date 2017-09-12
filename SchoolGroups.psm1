function setupModule{
    $Datasource = Get-ChildItem -Filter "ClassMembers-*.csv" -Path $env:TEMP | Sort-Object -Property CreationTimeUtc | Select-Object -Last 1
    if($Datasource){
        $script:SimsReport = import-csv $Datasource.fullname

        $script:ClassMembers = $SimsReport | Where-Object Class -NotLike "CLS *"
        $script:FormMembers  = $SimsReport | Where-Object Class    -Like "CLS *"

        $script:ClassList = $ClassMembers | Select-Object -Unique -ExpandProperty class
        $script:FormList  = $FormMembers  | Select-Object -Unique -ExpandProperty class
    } else {
        Write-Warning "Run 'New-Report' for data to sync user accounts"
    }
}

function escapeName{
    [OutputType([string])]
    Param(
        [parameter(Mandatory=$true,
                   ValueFromPipeline=$true)]
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

setupModule

. "$PSScriptRoot\Form.ps1"
. "$PSScriptRoot\Class.ps1"
. "$PSScriptRoot\Adno.ps1"
. "$PSScriptRoot\User.ps1"
. "$PSScriptRoot\Sims.ps1"
