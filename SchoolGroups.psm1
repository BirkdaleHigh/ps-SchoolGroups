$SimsReport = import-csv N:\StudentClassMemberships.csv

$ClassMembers = $SimsReport | where Class -NotLike "CLS *"
$FormMembers  = $SimsReport | where Class    -Like "CLS *"

$ClassList = $ClassMembers | Select -Unique -ExpandProperty class
$FormList  = $FormMembers  | Select -Unique -ExpandProperty class

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
        return $name.replace('/','_')
    }
}

. "$PSScriptRoot\Form.ps1"
. "$PSScriptRoot\Class.ps1"
. "$PSScriptRoot\Adno.ps1"
. "$PSScriptRoot\User.ps1"
