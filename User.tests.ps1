import-module "$PSScriptRoot\SchoolGroups.psm1" -force

Describe 'New-SchoolUser' {
    Mock -ModuleName SchoolGroups -CommandName New-ADUser -MockWith {
        write-host $psboundparameters
        return $script:newUser = $psboundparameters
    }
    Mock -CommandName New-HomeDirectory -MockWith {
        # Not testing this function here.
        return $true
    }
    Mock -ModuleName SchoolGroups -CommandName Get-ADUser -MockWith {
        if($script:newUser){
            return $script:newUser
        } else {
            return $null
        }
    }
    Context "Add 1 User, Ideal example"{
        It "Does not create a home directory for the user" {
            $t = New-SchoolUser -NoHome -intake (Get-Date).year -givenname "Alpha" -surname "Test" -EmployeeNumber "004321"

            $t.length | Should -be 1
            Assert-MockCalled -CommandName New-HomeDirectory -Times 0 -Exactly
            Assert-MockCalled -ModuleName SchoolGroups -CommandName New-ADUser -Times 1 -Exactly
        }

    }
}