function Test-CAInvPermanentAssignment {
    <#
    .SYNOPSIS
        Is this a genuinely permanent role assignment?
    .DESCRIPTION
        One definition of "permanent" for the whole module: assignmentType = 'Assigned' AND no
        endDateTime. So a standing assignment, not an active PIM activation ('Activated'), not an
        eligible assignment, and not an assignment that expires on an end date.

        This definition was previously written out separately in Get-CAInvPrivilegedAccess
        (Identity-09), Get-CAInvEmergencyAccess (Emergency-01), and Get-CAInvDailyAdmin
        (Identity-19). Three copies of the same concept is exactly how two definitions of
        "permanent Global Admin" end up disagreeing within a single run; that happened before,
        which is why it's now reduced to one place.

        Reads via Get-CAInvProp rather than direct property access: the PrivilegedPrincipals
        collection contains objects from two sources (active assignments and PIM-eligible
        assignments), and a source that doesn't supply a field must never make this helper trip
        under StrictMode.
    .EXAMPLE
        $permanent = @($principals | Where-Object { Test-CAInvPermanentAssignment $_ })
    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowNull()]
        $Assignment
    )

    if ($null -eq $Assignment) { return $false }

    if ((Get-CAInvProp $Assignment 'assignmentType' '') -ne 'Assigned') { return $false }
    return [string]::IsNullOrEmpty((Get-CAInvProp $Assignment 'endDateTime' ''))
}
