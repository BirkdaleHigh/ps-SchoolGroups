remove-module SchoolGroups -force
import-module "$PSScriptRoot\SchoolGroups.psd1" -force

InModuleScope SchoolGroups {
    Describe 'Add-GroupStudent' {
        Mock ValidateIntake {return $true}
        Mock Get-SchoolUser {
            New-Object -TypeName Microsoft.ActiveDirectory.Management.ADUser -Property @{
                DistinguishedName = "CN=$username,OU=2018,OU=Students,OU=Users,OU=BHS,DC=BHS,DC=INTERNAL"
                SamAccountName = $username
            }
        }
        Mock Add-ADGroupMember { }
        Context "Creation"{
            It "Pipe 1 user"{
                $result = Get-SchoolUser "20UserT" -OutVariable user | Add-GroupStudent

                Assert-MockCalled Add-ADGroupMember -Exactly 4 -Scope 'It'
                $result | Should -BeExactly $user
            }
        }
    }
}
