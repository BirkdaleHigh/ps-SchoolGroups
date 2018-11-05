# School Groups
Manage school group and user life cycle (creation, find, update, removal) actions common in the school. The "EmployeeNumber" field from Active Directory to reference the school "Admission Number" from the MIS as a unique ID.

## Features
- Sync your users active directory field `EmployeeNumber` with MIS `AdmissionNumber` record per student
- Sync all active class names from the school MIS into AD Groups
- With the admission number linked to employee number as a unique ID, Sync class group memberships in AD from MIS
- Create new AD users with a prescribed set of actions
- Create new subject specific user accounts from AD accounts to manage Controlled Assessment activities.
- Split a created user list into sub lists suitable for distribution to class representatives
- Find un-reset passwords in the AD which can represent unused or dormant accounts

## School Specific Features
- Decode our class code into a useful object whose properties represent the expanded information

## Planned Additions
- Configure a scheduled job to generate a new school report for class group membership
- Create associated email accounts
- Tidy the cmdlet interfaces to present exported functions from a module data file.
- Set ManagedBy on class groups to the teacher.
    - Cannot be achieved until a unique field can by used between MIS and AD for staff, like Adno->EmployeeNumber for students.
- Set group associations for users from specified template.
- Enforce compliance of data rules like group membership, name formats, unique employee numbers etc.
- Provision new users where employeenumber is not found in AD from MIS source.
- Log changes made.

# Install

1. Download the folder and place it in your own module folder. `$env:PSModulePath.split(';')` will show you these locations.
1. Ensure that folder is named `SchoolGroups`
1. When needed, import the module with `Import-Module SchoolGroups`

# How To Use

* `Get-Command -module SchoolGroups` will show you the commands from this module
* `Get-Help <command name>` will print the help of a command you are interested in.
* `Get-Help <command name> -examples` will display how you can use a command
* `Get-Help <command name> -full` you will find everything there is to know.

# Information

## Property Mapping
Active Directory | Sims.Net | Description
---------------- | -------- | -----------
EmployeeNumber | adno | Admission Number unique from sims used as the key to link student details between MIS and AD.
GivenName | Legal Forename
Surname | Legal Surname
DisplayName | Preferred Forename Preferred Surname | Concatenation of names for pronunciation, Email signatures and sign in display.
Intake | Year of Entry | Entry year the pupil is within the school used to find OU Path

## Rules
* Names with characters; ` ' <space> ` will have those characters stripped out for compatibility purposes on other systems.
* Usernames must be =<20 characters and will be truncated or changed at use request when starting.
* duplicate usernames will get a number appended, starting from 1.

# Contributing

Use `git update-index --skip-worktree .\configuration.json` to have git ignore your own changes to the module.

Any contributions are welcome, the areas that need work to accept PR's would be;

1. Migrate settings from hard-coded values to using the `configuration.json`.
1. More Unit Tests.
1. Introduce Poshcode/ModuleBuilder to align the module with how the community expects modules.
1. Auto-publishing workflow.

These points aren't the only things to be accepted, I feel they would be the major roadblocks before others may use this module.

## Update "functions to export" list
1. `Import-Module -Force .\SchoolGroups.psm1` Force import the module to bypass the psd curated exports list.
1. `get-command -Module SchoolGroups | select -ExpandProperty name | sort` View the list to remove functions that should be exported
1. Replace the list in .psd1 with the updated version in alphabetical order
