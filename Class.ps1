function Get-Class{
    <#
    .SYNOPSIS
        Lists all the unique classes filtered from the MIS report.
    .DESCRIPTION
        References the module-level import of new-report and filters out the unique classes, used for input into other sync commands.
    .EXAMPLE
        PS C:\> get-class

        8TE_Ar
        8TE_Cs
        8TE_Dr
    #>
    $script:ClassList.foreach({
        [OrgClass]::new($psItem)
    })
}

function Test-Class {
    <#
    .SYNOPSIS
        Compare the MIS and AD list of classes to find which is present and on what side
    .DESCRIPTION
        Used to evaluate which side of 2 lists (being MIS and AD) to input for New-Class or Remove-Class inside Sync-Class
    .EXAMPLE
        PS C:\> test-class
        Check if all the results from Get-Class are present in the AD, Mis or both lists

        Name      Source
        ----      ------
        8TC_Fr    Both
        8TC_Gg    Both
        8TC_Hi    Both
        8TC_Mu    Both
        8TC_Pe    Both
        7SMB_Fr   Both
        OrgClass  AD
    .EXAMPLE
        PS C:\> test-class -Filter AD
        Show only the classes found in the AD but not from MIS. Results here should probably be deleted

        Name     Source
        ----     ------
        OrgClass AD
    .EXAMPLE
        PS C:\> test-class -Filter MIS
        No results means there's nothing out of sync i.e. Classes are both on the AD and MIS. Results here should probably be created
    #>
    Param(
        # Show values only from the chosen source, <= MIS, => AD
        [parameter(ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('Both', 'MIS', 'AD')]
        $Filter = 'Both'

        , # Class Name to test
        [String[]]
        $Name = (Get-Class)
    )
    Begin {
        $ADList = Get-ADGroup -Filter * -SearchBase 'OU=Class Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL'
        if ($null -eq $ADList) {
            Write-Error "No Classes found from the AD" -ErrorAction Stop
        }
    }
    Process {
        $result = Compare-Object $Name $ADList.name -IncludeEqual |
            Select-Object @{
                name       = 'Name';
                Expression = {
                    $_.InputObject
                }
            }, @{
                name       = 'Source';
                Expression = {
                    $_.SideIndicator.Replace('<=', 'MIS').Replace('=>', 'AD').Replace('==', 'Both')
                }
            }

        switch ($Filter) {
            'MIS' {
                $result | Where-Object Source -eq 'MIS' | Where-Object Name -in $Name
            }
            'AD' {
                $result | Where-Object Source -eq 'AD' | Where-Object Name -in $Name
            }
            Default {
                $result | Where-Object Name -in $Name
            }
        }
    }
}

function New-Class{
    <#
    .SYNOPSIS
        Wrap New-ADGroup to create a class group in AD
    .DESCRIPTION
        Place the class groups in a specific OU path.
        Group needs to be universal in order to later get assigned an email address as a security group.
    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADGroup
    #>
    Param(
        [parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $name
    )
    Process{
        foreach($class in $name){
            $group = @{
                'GroupScope' = 'Global'
                'GroupCategory' = 'Security'
                'PassThru' = $True
                'Name' = $class
                'Path' = 'OU=Class Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL'
            }
            New-ADGroup @group | Set-ADGroup -Replace @{"mail" = "$($group.name)@birkdalehigh.co.uk"} -PassThru
        }
    }
}

function Sync-Class{
    <#
    .SYNOPSIS
        Match AD Groups from the MIS source
    .DESCRIPTION
        Compare the MIS Sorce list of class groups and create AD groups or delete them.

        Contains import like Get-Class, uses Test-Class and then New-Class or Remove-Class
    .EXAMPLE
        Sync-Class -Verbose -WhatIf
        Shows you the progress as well as what it will do
    .INPUTS
        [string[]] Class name from Get-Class
    .OUTPUTS
        New class ad group objects
    #>
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        # Choose Classes to Syncronize
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Class = (Get-Class)
    )
    $classes = Test-Class -Name $Class
    $new = $classes | Where-Object Source -eq MIS | Select-Object -ExpandProperty Name
    $old = $classes | Where-Object Source -eq AD | Select-Object -ExpandProperty Name
    if($new.count -eq 0 -and $old.count -eq 0){
        Write-Verbose "No difference in AD class groups from MIS"
        return
    }
    Write-Verbose "Create $($new.count) groups"
    if ($pscmdlet.ShouldProcess($new, "Create New AD Group")){
        $new | New-Class
    }
    Write-Verbose "Remove $($old.count) groups"
    if ($pscmdlet.ShouldProcess($old, "Remove Existing AD Group")){
        $old | Remove-ADGroup
    }
}

function Get-ClassMember{
    <#
    .SYNOPSIS
        List AD accounts that are supposed to be members of a class.
    .DESCRIPTION
        Reference the MIS list of Id's to get AD Accounts for users that are supposed to be in the given class group.
    .INPUTS
        [string] Class Code
    .OUTPUTS
        AD user
    #>
    Param(
        [parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        $Class
    )
    Process{
        $AdmissionNumber = $script:ClassMembers | where-object { (escapeName $_.Class) -eq $Class} | select-object -ExpandProperty Adno
        if([string]::IsNullOrEmpty($AdmissionNumber)){
            Throw "No members found in $Class from MIS dataset"
        }

        $filter = "(&(objectClass=user)(|(employeenumber={0})))" -f ($AdmissionNumber.padLeft(6,'0') -join ')(employeenumber=')
        Write-Debug "LDAP Query for group members: $filter"
        get-aduser -Properties EmployeeNumber -LDAPFilter $filter
    }
}
function Get-ClassADGroupMember{
    <#
    .SYNOPSIS
        Get AD Accounts that are in the class
    .DESCRIPTION
        Effectively Wraps `Get-ADGroupMember <class> | Get-ADUser -properties EmployeeNumber`
    #>
    Param(
        [Parameter(Mandatory,Position=0)]
        [Alias("class")]
        [string]
        $Name
    )
    get-aduser -Properties EmployeeNumber -LDAPFilter "(&(objectClass=user)(memberof=CN=$Name,OU=Class Groups,OU=Student Groups,OU=Security Groups,OU=BHS,DC=BHS,DC=INTERNAL))"
}

function Test-ClassMember{
    <#
    .SYNOPSIS
        Compares MIS to AD for present/missing account group memberships
    .DESCRIPTION
        ADGroup is true if user is found in the AD Class Security Group
        MIS is true if user if found in the MIS dataset

        Calls Get-ClassADGroupMember to find all users currently in the group.
        Calls Get-ClassMember to get all AD accounts for users from the MIS Dataset

        Compares these two sets to add resulting properties to use objects.
    .EXAMPLE
        Test-ClassMember 10e4_en
        Report group membership state of current and expected users.

        ADGroup   MIS DistinguishedName  EmployeeNumber Enabled GivenName Name      ObjectClass
        -------   --- -----------------  -------------- ------- --------- ----      -----------
           True  True CN=user,...        004841            True user      lastname  user
           True  True CN=user,...        004844            True user      lastname  user
           True  True CN=user,...        005152            True user      lastname  user
           True False CN=user,...        004949            True user      lastname  user
          False  True CN=user,...        004839            True user      lastname  user
          False  True CN=user,...        004876            True user      lastname  user
          False  True CN=user,...        004939            True user      lastname  user
    .INPUTS
        String, Class Group Name
    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADUser
    #>
    Param(
        # Form the user should be a member of
        [parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [string]
        $Class
    )
    $ADList = @(Get-ClassADGroupMember $Class)

    if([string]::IsNullOrEmpty($ADList)){
        Write-Warning "No members found in $Class from the AD"
    }

    $misList = @(Get-ClassMember $Class -ErrorAction SilentlyContinue)
    Compare-Object $misList $ADList -IncludeEqual -Property EmployeeNumber -PassThru |
        ForEach-Object {
            Add-Member -inputObject $PSItem -MemberType NoteProperty -Name "ADGroup" -Value ($PSItem.SideIndicator -in '=>','==') -Force
            Add-Member -inputObject $PSItem -MemberType NoteProperty -Name "MIS"     -Value ($PSItem.SideIndicator -in '<=','==') -Force
            $psitem.PSObject.properties.remove("SideIndicator")
            Write-Output $psitem
        }
}

function Sync-ClassMember{
    <#
    .Synopsis
        Make the AD group members match the provided MIS list.
    .DESCRIPTION
        For each class add the members found only in the MIS
        For each class remove any members only found in the AD

        Internally calls Test-ClassMember to and add/removes users based on output with some extra logging.
    .EXAMPLE
        Sync-ClassMember 10e4_en -Verbose -Debug -WhatIf
        Test what is about to happen to the group when sync runs

        DEEBIG: LDAP Query for group members: (&(objectClass=user)(|(employeenumber=000001)(employeenumber=000007)...))
        What if: Performing the operation "Add 1 Member(s), Remove 0 Member(s)" on target "10e4_en".
        VERBOSE: Class: 10e4_en, New Total: 16, Add: 5 from MIS, Remove: 1 only in AD.
    .EXAMPLE
        Sync-ClassMember -WhatIf -Verbose
        Sample output from testing what synchronising everythign will do.

        VERBOSE: No change to Class: 8AB_Pe, Total: 27
        What if: Performing the operation "Add 1 Member(s), Remove 0 member(s)" on target "8E7_En".
        VERBOSE: Class: 8E7_En, New Total: 12, Add: 1 from MIS, Remove: 0 only in AD.
        ...
    .LINK
        Get-Help Get-Class
        Get-Help Test-ClassMember
    #>
    [cmdletbinding(SupportsShouldProcess=$true)]
    Param(
        # Choose Classes to Syncronize
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Class = (Get-Class)
    )
    $Class | ForEach-Object {
        $users = Test-ClassMember $psitem
        $add = @($users | where-object { $psitem.MIS -and -not $psitem.ADGroup })
        $remove = @($users | where-object MIS -eq $false)
        $total = [int]($users | where-object adgroup | Measure-Object).count

        if(($add.length -eq 0) -and ($remove.length -eq 0)){
            Write-Verbose "No change to members ($total) in target `"$psitem`""
            return
        }

        $logText = "New Total: {0}, Add: {1} from MIS, Remove: {2} only in AD." -f @(
            $total
            $add.length
            $remove.length
        )

        if ($pscmdlet.ShouldProcess($psitem, $logText)){
            if($add){
                Add-ADGroupMember -Identity $psitem -Members $add > $null
            }
            if($remove){
                Remove-ADGroupMember -Identity $psitem -Members $remove -confirm:$false
            }
        }
    }
}
