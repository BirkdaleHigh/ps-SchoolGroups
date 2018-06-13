. "$PSScriptRoot\Class.ps1"

Describe 'New-Class' {
    Mock -CommandName New-ADGroup -MockWith {
        return @{ Name = $name }
    }
    Context "Add 1 group"{
        It "Create 1 new AD group for 1 name supplied" {
            New-Class -Name Experiment

            Assert-MockCalled -CommandName New-ADGroup -Times 1 -Exactly
        }
    }
    Context "Add 5 groups"{
        It "Create 5 new AD groups for 5 supplied names" {
            New-Class -Name "ClassA","ClassB","ClassC","ClassD","ClassE"

            Assert-MockCalled -CommandName New-ADGroup -Times 5 -Exactly
        }
    }
    Context "Add 5 groups by piped value"{
        It "Create 5 new AD groups for 5 supplied names" {
            "ClassA","ClassB","ClassC","ClassD","ClassE" | New-Class

            Assert-MockCalled -CommandName New-ADGroup -Times 5 -Exactly
        }
    }
}
