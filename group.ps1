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

    process {
        $intake = [int]($Identity.DistinguishedName -split ',')[1].remove(0,3)

        if ($PSCmdlet.ShouldProcess($Identity.DistinguishedName, "Set group member of:$Intake Students, Access24 Students, AccessStudentsShared, AllPupils")) {
            # Remote Desktop Access
            Add-ADGroupMember -Members $Identity -Identity "Access24 Students"
            # Shared students folder for reading lesson work
            Add-ADGroupMember -Members $Identity -Identity "AccessStudentsShared"
            # All students email address for bulk email
            Add-ADGroupMember -Members $Identity -Identity "AllPupils"
            # Per school year management. Group is a member of appropriate Year X group.
            Add-ADGroupMember -Members $Identity -Identity "$Intake Students"

            # Return the original user object
            $Identity
        }

    }
}
