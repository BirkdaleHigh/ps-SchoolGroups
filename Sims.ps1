class SimsUser {
    [string]$Givenname
    [string]$Surname
    [string]$ADNO
}

function Import-SimsUser {
    param(
        # Sims report user list
        [Parameter(mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $user
    )
    $obj = [SimsUser]@{
        'givenname' = $user.Forename;
        'surname'   = $user."Legal Surname";
        'adno'      = $user.adno
        }
    Write-Output $obj
}