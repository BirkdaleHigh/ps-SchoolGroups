import-module "$PSScriptRoot\SchoolGroups.psm1" -force

InModuleScope SchoolGroups {
    Describe 'Update-EmployeeNumber' {
        Set-StrictMode -Version latest
        Mock Set-ADUser { return  }
        Context 'Pipe 1 user' {
            It 'Should pipe one ad user as input'{
                $user = New-Object Microsoft.ActiveDirectory.Management.ADUser -Property @{
                    DistinguishedName = "CN=16LastF,OU=2016"
                    EmployeeNumber    = "000001"
                }

                $user | Update-EmployeeNumber

                Assert-MockCalled Set-ADUser -Times 1 -Exactly
            }
        }
        Context 'Pipe multiple users'{
            It 'Should pipe three ad users as input'{
                $user1 = New-Object Microsoft.ActiveDirectory.Management.ADUser -Property @{
                    DistinguishedName = "CN=16LastF,OU=2016"
                    EmployeeNumber    = "000001"
                }
                $user2 = New-Object Microsoft.ActiveDirectory.Management.ADUser -Property @{
                    DistinguishedName = "CN=16LastS,OU=2016"
                    EmployeeNumber    = "000002"
                }
                $user3 = New-Object Microsoft.ActiveDirectory.Management.ADUser -Property @{
                    DistinguishedName = "CN=16LastT,OU=2016"
                    EmployeeNumber    = "000003"
                }

                $user1,$user2,$user3 | Update-EmployeeNumber

                Assert-MockCalled Set-ADUser -Times 3 -Exactly
            }
        }
        Context 'Output Handling' {
            It 'Should return the AD user objects that has been set'{
                $user1 = New-Object Microsoft.ActiveDirectory.Management.ADUser -Property @{
                    DistinguishedName = "CN=16LastF,OU=2016"
                    Enabled           = "True"
                    GivenName         = "First"
                    ObjectClass       = "user"
                    SamAccountName    = "16LastF"
                    Surname           = "Last"
                    UserPrincipalName = '16LastF@ORG'
                    EmployeeNumber    = "000001"
                }

                $output = $user1 | Update-EmployeeNumber
                $output | should -Be $user1

            }
        }
    }
}