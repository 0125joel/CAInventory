function Get-CAInvPolicyUserScope {
    <#
    .SYNOPSIS
        Determines who a CA policy targets: all users, or a bounded audience.
    .DESCRIPTION
        One definition for everyone who asks "does this policy hit everyone or a selection?".
        Before this helper, the check `includeUsers -contains 'All'` was baked in separately in
        Foundation-07, Foundation-09, Identity-03/Identity-04, and the workbook export; four places
        that could silently drift apart. Same motive as Get-CAInvPolicyManagedOrigin: the report
        and the workbook must never give a different answer to the same question.

        The distinction between 'allUsers' and a targeted scope isn't just cosmetic. The
        recommendation for Condition-05 (resilience defaults) hinges on it: Microsoft writes that
        disabling it on a policy targeted at a group or role lowers resilience for ALL users in the
        tenant, not just for that audience. That's exactly the warning you don't need to give for
        an all-users policy.

        Kind is deliberately modeled as descriptive, not exhaustive: a policy can target groups and
        roles at the same time. That's 'mixed'. 'none' means no include targeting was found at
        all; that's not an error but is something the consumer needs to weigh themselves, because a
        policy without an include scope hits no one in practice.
    .PARAMETER Policy
        A CA policy object from Graph.
    .OUTPUTS
        PSCustomObject with TargetsAllUsers (bool), Kind ('allUsers' | 'groups' | 'roles' |
        'users' | 'mixed' | 'none'), and Summary (short English description).
    .EXAMPLE
        $scope = Get-CAInvPolicyUserScope -Policy $p
        if (-not $scope.TargetsAllUsers) { # include the tenant-wide warning in the recommendation
        }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][AllowNull()][object] $Policy
    )

    $includeUsers  = @(Get-CAInvProp $Policy 'conditions.users.includeUsers' @())
    $includeGroups = @(Get-CAInvProp $Policy 'conditions.users.includeGroups' @())
    $includeRoles  = @(Get-CAInvProp $Policy 'conditions.users.includeRoles' @())

    if ($includeUsers -contains 'All') {
        return [PSCustomObject]@{
            TargetsAllUsers = $true
            Kind            = 'allUsers'
            Summary         = 'All users'
        }
    }

    $namedUsers = @($includeUsers | Where-Object { $_ -notin @('All', 'None') })

    $kinds = @()
    if ($includeGroups.Count -gt 0) { $kinds += 'groups' }
    if ($includeRoles.Count -gt 0)  { $kinds += 'roles' }
    if ($namedUsers.Count -gt 0)    { $kinds += 'users' }

    $kind = switch ($kinds.Count) {
        0       { 'none' }
        1       { $kinds[0] }
        default { 'mixed' }
    }

    $parts = @()
    if ($includeGroups.Count -gt 0) { $parts += "$($includeGroups.Count) group(s)" }
    if ($includeRoles.Count -gt 0)  { $parts += "$($includeRoles.Count) role(s)" }
    if ($namedUsers.Count -gt 0)    { $parts += "$($namedUsers.Count) user(s)" }
    $summary = if ($parts.Count -gt 0) { $parts -join ', ' } else { 'No include targeting' }

    return [PSCustomObject]@{
        TargetsAllUsers = $false
        Kind            = $kind
        Summary         = $summary
    }
}
