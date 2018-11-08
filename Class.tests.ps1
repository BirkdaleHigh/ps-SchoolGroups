import-module "$psScriptRoot\SchoolGroups.psd1"

InModuleScope SchoolGroups{
    Describe 'New-Class' {
        Mock New-ADGroup {
            return @{ Name = $name }
        }
        Context "Add 1 group"{
            It "Create 1 new AD group for 1 name supplied" {
                New-Class -Name Experiment

                Assert-MockCalled New-ADGroup -Times 1 -Exactly
            }
        }
        Context "Add 5 groups"{
            It "Create 5 new AD groups for 5 supplied names" {
                New-Class -Name "ClassA","ClassB","ClassC","ClassD","ClassE"

                Assert-MockCalled New-ADGroup -Times 5 -Exactly
            }
        }
        Context "Add 5 groups by piped value"{
            It "Create 5 new AD groups for 5 supplied names" {
                "ClassA","ClassB","ClassC","ClassD","ClassE" | New-Class

                Assert-MockCalled New-ADGroup -Times 5 -Exactly
            }
        }
    }
}
InModuleScope SchoolGroups{
    Describe 'Sync-ClassMember'{
        Mock Test-ClassMember {
            return @(
                New-Object psobject -Property @{
                    name = "Mock User 1"
                    MIS = $true
                    ADGroup = $false
                }
                New-Object psobject -Property @{
                    name = "Mock User 2"
                    MIS = $false
                    ADGroup = $true
                }
            )
        }
        Mock Add-ADGroupMember {}
        Mock Remove-ADGroupMember {}
        Context 'Run safety'{
            it 'Does not make changes with -whatif'{
                Sync-ClassMember -Class 'ABC' -WhatIf

                Assert-MockCalled -CommandName Add-ADGroupMember -Times 0 -Exactly
                Assert-MockCalled -CommandName Remove-ADGroupMember -Times 0 -Exactly
            }
        }
    }
}
