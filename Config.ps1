function Get-Configuration{
    if(-not $Script:Config){
        Import-Configuration
    }
    Write-Output $Script:Config
}

function Set-Configuration{
    Param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    Process{
        $Script:Config | Add-Member -NotePropertyName $name -NotePropertyValue $Value
    }
}

function Import-Configuration {
    [CmdletBinding()]
    Param()
    # Defaults
    $Script:Config = Get-Content -Raw -Path (Join-Path $PSScriptRoot "Configuration.json")| convertfrom-json
    $Script:Config | Add-member -NotePropertyName Options -NotePropertyValue (@{
        Path = @($env:CommonProgramFiles, $env:APPDATA)
    })

    # Custom defined User settings
    ForEach($path in $Script:Config.options.path){
        try {
            $Script:Config += Get-Content -Raw -Path "$Path\SchoolGroups_Configuration.json" -ErrorAction Stop | convertfrom-json
        } catch {
            Write-Verbose "Failed to load custom user data in $Path"
        }
    }
    $Script:Config.Options | Add-member -NotePropertyName DefaultSavePath -NotePropertyValue ($Script:Config.Options.Path | Select-Object -last 1)
}
function Save-Configuration {
    $Script:Config | convertto-json | Out-File -Encoding utf8 -FilePath (Join-Path $Script:Config.Options.DefaultSavePath 'Powershell\SchoolGroups_Configuration.json')
}
