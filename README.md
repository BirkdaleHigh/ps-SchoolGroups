# School Groups
Manage school group and user lifecycle (creation, membership, removal) actions common in the school. Uses the "EmployeeNumber" field from Active Directory to reference the school "Admission Number" from the MIS as a unique ID.

## Features
- Sync your users active directory field `EmployeeNumber` with MIS `AdmissionNumber` record per student
- Sync all active class names from the school MIS into AD Groups
- With the admission number linked to employee number as a unique ID, Sync class group memberships in AD from MIS
- Create new AD users with a prescribed set of actions
- Create new subject specific user accounts from AD accounts to manage Controlled Assessment activities.
- Split a created user list into sub lists suitable for distribution to class representatives
- Find un-reset passwords in the AD which can represent unsused or dormant accounts

## School Specific Features
- Decode our class code into a useful object whose properties represent the expanded information

## Planned Additions
- Configure a scheduled job to generate a new school report for class group membership
- Create associated email accounts
- Tidy the cmdlet interfaces to present exported functions from a module data file.

# Install

1. Download the folder and place it in your own module folder. `$env:PSModulePath.split(';')` will show you these locations.
1. Ensure that folder is named `SchoolGroups`
1. When needed, import the module with `Import-Module SchoolGroups`

# How To Use

* `Get-Command -module SchoolGroups` will show you the commands from this module
* `Get-Help <command name>` will print the help of a command you are interested in.
* `Get-Help <command name> -examples` will display how you can use a command
* `Get-Help <command name> -full` you will find everything there is to know.