function Test-GroupMembership {
    <#
    .Synopsis
        Checks if users are in the correct groups as defined by their type
    #>
    Param(
        # User to check
        $Identity

        , # Expected kind of user
        [ValidateSet("Student", "Staff", "Exam")]
        [string]$Type = "Student"
    )
    Process {
        ForEach ($user in $Identity) {
            if (-not $user.PSobject.Properties.name -eq "MemberOf") {
                $user = $user | Get-Aduser -Properties MemberOf
            }

            @(
                'Access24 Students'
                'AccessStudentsShared'
                'AllPupils'
                "$Intake Students"
            ).ForEach( {
                    $user.memberof -like $psitem
                })
        }
    }
}

function Test-Group {
    <#
    .Synopsis
        Test that the groups to be enforced actually exist
    #>
    [CmdletBinding()]
    param (
        # Distinguished Name
        [Parameter(ParameterSetName = "DN", Mandatory)]
        [Alias('DistinguishedName')]
        [String]
        $Identity

        , # Group Name
        [Parameter(ParameterSetName = "simple", Mandatory)]
        [String]
        $Name

        , # Group OU Path
        [Parameter(ParameterSetName = "simple")]
        [String]
        $location
    )
    process {
        Get-ADGroup $Identity -ErrorAction Stop
    }
}

function Add-GroupStudent {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        $Identity
    )
    Begin {
        $groups = @(
            "Access24 Students" # Remote Desktop Access
            "AccessStudentsShared" # Shared students folder for reading lesson work
            "AllPupils" # Al students email address for bulk email becuase groups-in-groups doens't work
            "$Intake Students" # Per school year management. Group is a member of appropriate Year X group.
        )
    }
    process {
        $intake = [int]($Identity.DistinguishedName -split ',')[1].remove(0,3)

        if ($PSCmdlet.ShouldProcess($Identity.DistinguishedName, "Set group member of:$($groups -join ', ')")) {
            foreach($g in $groups){
                Add-ADGroupMember -Members $Identity -Identity $g
            }

            # Return the original user object
            Write-Output $Identity
        }

    }
}
