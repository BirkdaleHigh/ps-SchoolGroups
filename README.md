# School Groups
Manage school group and user lifecycle (creation, membership, removal) actions common in the school. Uses the "EmployeeNumber" field from Active Directory to reference the school "Admission Number" from the MIS as a unique ID.

## Features
- Sync your users active directory field `EmployeeNumber` with MIS `AdmissionNumber` record per student
- Sync all active class names from the school MIS into AD Groups
- With the admission number linked to employee number as a unique ID, Sync class group memberships in AD from MIS
- Create new AD users with a prescribed set of actions
- Create new subject specific user accounts from AD accounts to manage Controlled Assessment activities.
- Split a created user list into sub lists suitable for distribution to class representatives
- Find any un-reset passwords in the AD which can represent unsused or dormant accounts

## School Specific Features
- Decode our class code into a useful object whose properties represent the expanded information

## Planned Additions
- Configure a scheduled job to generate a new school report for class group membership
- Create associated email accounts