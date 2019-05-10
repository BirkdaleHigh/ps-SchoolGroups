remove-module SchoolGroups -force
import-module "$PSScriptRoot\SchoolGroups.psd1" -force

InModuleScope SchoolGroups {
    Describe 'Internal Function Testing' {
        Mock Get-SchoolUser {
            Throw [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]::New('Mock has no user to return')
        }
        Mock Get-SchoolUser {
            # Test existing user with different MIS ID
            return @{
                SamAccountName = '20DuplicateT'
                employeeNumber = '001112'
            }
        } -ParameterFilter { $SamAccountName -eq '20DuplicateT' }
        Mock Get-SchoolUser {
            # Test existing user with different MIS ID
            return @{
                SamAccountName = '20TripleT'
                employeeNumber = '001113'
            }
        } -ParameterFilter { $SamAccountName -eq '20TripleT' }
        Mock Get-SchoolUser {
            # Test existing user with different MIS ID
            return @{
                SamAccountName = '20TripleT1'
                employeeNumber = '001113'
            }
        } -ParameterFilter { $SamAccountName -eq '20TripleT1' }
        Mock Get-SchoolUser {
            # Test existing user with different MIS ID
            return @{
                SamAccountName = '1DuplicatenameLimitT'
                employeeNumber = '001112'
            }
        } -ParameterFilter { $SamAccountName -eq '1DuplicatenameLimitT' }

        Context 'Validate username uniquness algorithm'{
            It 'When no user already exists return the initial name' {
                $username = '20userT'
                CreateUsername -Username $username | should -eq $username
                
                Assert-MockCalled Get-SchoolUser -Exactly 1 -Scope 'It'            
            }
            It 'User already exists so append 1 to the username' {
                $username = '20DuplicateT'
                CreateUsername -Username $username | should -eq ($username + '1')
                
                Assert-MockCalled Get-SchoolUser -Exactly 2 -Scope 'It'            
                Assert-MockCalled Get-SchoolUser -Exactly 2 -Scope 'It'            
            }
            It 'Appended user already exists so increment the username' {
                $username = '20TripleT'
                CreateUsername -Username $username | should -eq '20TripleT2'
                
                Assert-MockCalled Get-SchoolUser -Exactly 3 -Scope 'It'            
                Assert-MockCalled Get-SchoolUser -Exactly 3 -Scope 'It'            
            }
            It 'Throw if the name is unique but the ID is not' {
                $username = '20DuplicateT'
                { CreateUsername -ID '001112' -Username $username } | should -Throw
                
                Assert-MockCalled Get-SchoolUser -Exactly 1 -Scope 'It'   
            }
            It 'Should not allow usernames over the 20 character SamAccountName limit' {
                $username = '120MaxusernameLimitT'
                CreateUsername -Username $username | should -eq $username

                Assert-MockCalled Get-SchoolUser -Exactly 1 -Scope 'It'
            }
            It 'Should not allow usernames over the 20 character SamAccountName limit when incrementing' {
                $username = '1DuplicatenameLimitT'
                { CreateUsername -Username $username } | should -Throw

                Assert-MockCalled Get-SchoolUser -Exactly 1 -Scope 'It'
            }
        }
    }

    Describe 'New-SchoolUser' {
        Mock ValidateIntake {return $true}
        Mock Get-SchoolUser {
            New-Object -TypeName Microsoft.ActiveDirectory.Management.ADUser -Property @{
                SamAccountName = $username
                EmployeeNumber = $EmployeeNumber
                HomeDirectory = 'Test Data'
            }
        }
        Mock New-ADUser {
            New-Object -TypeName Microsoft.ActiveDirectory.Management.ADUser -Property @{
                SamAccountName = $username
                EmployeeNumber = $EmployeeNumber
                HomeDirectory = 'Test Data'
            }
        }
        Mock CreateUsername {
            return '10FirstT'
        }
        Mock New-HomeDirectory {}
        Context "Creation"{
            It "Create 1 user"{
                $account = New-SchoolUser -Givenname "Tester" -Surname "First" -EmployeeNumber '001011' -intake 1910

                Assert-MockCalled New-ADUser -Exactly 1 -Scope 'It'
                Assert-MockCalled New-HomeDirectory -Exactly 1  -Scope 'It'
                $account.SamAccountName | Should -be "10FirstT"
            }
            It "-NoHome parameter does not call New-HomeDriectory"{
                $account = New-SchoolUser -NoHome -Givenname "Tester" -Surname "First" -EmployeeNumber '001011' -intake 1910

                Assert-MockCalled New-ADUser -Times 1 -Exactly -Scope 'It'
                Assert-MockCalled New-HomeDirectory -Times 0 -Exactly -Scope 'It'
                $account.SamAccountName | Should -be "10FirstT"
            }
            It "Catch incorrect EmployeeID formats"{
                {New-SchoolUser -Givenname "Different" -Surname "User" -EmployeeNumber '00101' -intake 1910} | Should -Throw
                {New-SchoolUser -Givenname "Different" -Surname "User" -EmployeeNumber 'XY1101' -intake 1910} | Should -Throw

                Assert-MockCalled Get-SchoolUser -Times 0 -Exactly -Scope 'It'
                Assert-MockCalled New-ADUser -Times 0 -Exactly -Scope 'It'
                Assert-MockCalled New-HomeDirectory -Times 0 -Exactly -Scope 'It'
            }
        }
    }
}
