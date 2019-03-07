import-module "$PSScriptRoot\SchoolGroups.psm1" -force

# Example 1: https://hastebin.com/guhomecida.rb
# Example 2: https://hastebin.com/seresoseve.scala
# Example 3: https://hastebin.com/ixebepagik.php

InModuleScope SchoolGroups {
    Describe 'New-SchoolUser' {
        Mock ValidateIntake {return $true}
        Context "Creation"{
            Mock Get-SchoolUser {
                Throw [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]::new("User not found")
            }
            Mock Get-SchoolUser { # Existing employeeNumber
                New-Object -TypeName Microsoft.ActiveDirectory.Management.ADUser -Property @{
                    SamAccountName = $username
                    EmployeeNumber = $EmployeeNumber
                    HomeDirectory = 'Test Data'
                }
            } -ParameterFilter { $InputObject.EmployeeNumber -eq '002022' }
            Mock New-ADUser {
                New-Object -TypeName Microsoft.ActiveDirectory.Management.ADUser -Property @{
                SamAccountName = $username
                EmployeeNumber = $EmployeeNumber
                HomeDirectory = 'Test Data'
            }}
            Mock New-HomeDirectory {}
            Mock Get-ADUser {$script:NewUser}

            It "Create 1 user"{
                $account = New-SchoolUser -Givenname "Tester" -Surname "First" -EmployeeNumber '001011' -intake 1910

                Assert-MockCalled New-ADUser -Times 1 -Exactly -Scope 'It'
                Assert-MockCalled New-HomeDirectory -Times 1 -Exactly -Scope 'It'
                $account.SamAccountName | Should -be "10FirstT"
            }
            It "-NoHome parameter does not call New-HomeDriectory"{
                $account = New-SchoolUser -NoHome -Givenname "Tester" -Surname "First" -EmployeeNumber '001011' -intake 1910

                Assert-MockCalled New-ADUser -Times 1 -Exactly -Scope 'It'
                Assert-MockCalled New-HomeDirectory -Times 0 -Exactly -Scope 'It'
                $account.SamAccountName | Should -be "10SecondT"
            }
            It "Does not create a duplicate employeeNumber"{
                {New-SchoolUser -Givenname "Different" -Surname "User" -EmployeeNumber '002022' -intake 1910} | Should -Throw

                Assert-MockCalled Get-SchoolUser -Times 1 -Exactly -Scope 'It'
                Assert-MockCalled New-ADUser -Times 0 -Exactly -Scope 'It'
                Assert-MockCalled New-HomeDirectory -Times 0 -Exactly -Scope 'It'
            }
            It "Catch incorrect EmployeeID formats"{
                {New-SchoolUser -Givenname "Different" -Surname "User" -EmployeeNumber '00101' -intake 1910} | Should -Throw
                {New-SchoolUser -Givenname "Different" -Surname "User" -EmployeeNumber 'XY1101' -intake 1910} | Should -Throw

                Assert-MockCalled Get-SchoolUser -Times 0 -Exactly -Scope 'It'
                Assert-MockCalled New-ADUser -Times 0 -Exactly -Scope 'It'
                Assert-MockCalled New-HomeDirectory -Times 0 -Exactly -Scope 'It'
            }
            It "Increment the username number for duplicates"{
                Throw "TODO"
            }

        }
    }
}
