class Group {
    [string]$Code
    [int]$Year
    [alias("Code")]$Name

    Group (){
        
    }

    Group([string]$Name){
        $regex = '^(?:CLS )?(1?[01789])'
        $match = [regex]::Match(
            $Name,
            $regex
        )
        if($match.success){
            $this.Code = $Name
            $allMatches, $this.Year = $match.groups.value
            return
        }
        throw "Could not decode group pattern (e.g. 8M3_MA1 or CLS 9CK): $regex"
    }
}

class OrgForm : Group {
    [string]$ID
    [string]$Tutor

    OrgForm([string]$Name) : base ($Name) {
        $regex = '([a-zA-Z]+)$'
        $match = [regex]::Match(
            $Name,
            $regex
        )
        if($match.success){
            $allMatches, $this.ID = $match.groups.value
            $this.Tutor = $script:FormMembers.where({$_.initials -eq $this.ID}, 'First').Teacher
            return
        }
        Throw "Could not decode group pattern (e.g. CLS 10JB): $regex"
    }
}

class OrgClass : Group {
    [string]$Set
    [string]$ID
    [string]$FullName
    $Number
    hidden static [hashtable]$SubjectList = @{
        'Ar' = 'Art'
        'Bi' = 'Biology'
        'Bt' = 'BTEC Sport'
        'Bu' = 'Business Studies'
        'Ch' = 'Chemistry'
        'Cs' = 'Computer Science'
        'Dr' = 'Drama'
        'Dt' = 'Design Technology'
        'En' = 'English'
        'Fo' = 'Food Technology'
        'Ft' = 'Food Technical'
        'Fr' = 'French'
        'Gg' = 'Geography'
        'Hi' = 'History'
        'Im' = 'I-Media'
        'It' = 'Information Technology'
        'Ma' = 'Maths'
        'Mu' = 'Music'
        'Pe' = 'Physical Education'
        'Ph' = 'Physics'
        'Re' = 'Religious Education'
        'Rm' = 'Resistant Materials'
        'St' = 'Study Plus'
        'Sc' = 'Science'
        'Sb' = 'BTEC Science'
        'Sp' = 'Spannish'
        'Te' = 'Technology'
        'Ts' = 'Triple Science'
        'Xl' = 'Extra Literature'
    }

    OrgClass([string]$Name) : base ($Name) {
        $regex = '^1?[01789]([a-zA-Z]+\d?)+_([a-zA-Z]+)(\d?)$'
        $match = [regex]::Match(
            $Name.replace('/','_').replace('+','t'),
            $regex
        )
        if($match.success){
            $this.Code, $this.Set, $this.ID, $this.Number = $match.groups.value
            $this.FullName = $this::SubjectList[$this.ID]
            return
        }
        throw "Could not decode class pattern (e.g. 8M3_MA1): $regex"
    }
}
