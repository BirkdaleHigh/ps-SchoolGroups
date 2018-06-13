import-module "$PSScriptRoot\SchoolGroups.psm1" -force

# Example 1: https://hastebin.com/guhomecida.rb
# Example 2: https://hastebin.com/seresoseve.scala
# Example 3: https://hastebin.com/ixebepagik.php

Describe 'New-SchoolUser' {
    BeforeAll {
        $defaultParams = @{
            GivenName      = 'First'
            Surname        = 'Last'
            EmployeeNumber = '001234'
            Intake         = '2018'
        }
        Mock ValidateIntake -ModuleName SchoolGroups { $true }
        Mock New-HomeDirectory -ModuleName SchoolGroups
        Mock Get-ADUser -ModuleName SchoolGroups {
            if($script:NewADUser){
                return $script:NewADUser
            }
        }
        Mock New-ADUser -ModuleName SchoolGroups {
            $u = [Microsoft.ActiveDirectory.Management.ADUser]::new()
            $u.SamAccountName = $name
            $u.HomeDirectory = '\\example\path'
            $u.EmployeeNumber = $EmployeeNumber

            return $script:NewADUser = $u
        }
    }


    Context "Add 1 User, Ideal example"{
        It "Create 1 user"{
            $account = New-SchoolUser @defaultParams

            Assert-MockCalled New-ADUser -Times 1 -Exactly -ModuleName SchoolGroups
            Assert-MockCalled New-HomeDirectory -Times 1 -Exactly -ModuleName SchoolGroups
            $account.SamAccountName | Should -be "18LastF"
        }
    }
    context "Do not create Home Directroy"{
        It "nohome parameter does not call New-HomeDriectory"{
            $newParams = $defaultParams
            $newParams.noHome = $true
            $newParams.GivenName = 'Second'
            $newParams.EmployeeNumber = '001235'
            $account = New-SchoolUser @newParams

            Assert-MockCalled New-ADUser -Times 1 -Exactly -ModuleName SchoolGroups
            Assert-MockCalled New-HomeDirectory -Times 0 -Exactly -ModuleName SchoolGroups
            $account.SamAccountName | Should -be "18LastS"
        }
    }
}
