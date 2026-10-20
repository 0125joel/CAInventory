function Get-CAInvTransitiveMember {
    <#
    .SYNOPSIS
        Returns the transitive (nested) members of a group as a list of objects.
    .DESCRIPTION
        Shared helper for scope and integrity checks. Uses /groups/{id}/transitiveMembers and
        caches per run via Invoke-CAInvGraph.
        Fails soft: on an error, an empty list is returned along with Failed = $true.
    .OUTPUTS
        PSCustomObject: @{ Members (array); Failed; ErrorMessage }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string] $GroupId
    )

    $resp = Invoke-CAInvGraph -Uri "groups/$GroupId/transitiveMembers?`$select=id,displayName,userPrincipalName,userType" -ApiVersion 'v1.0'
    if ($resp.Failed) {
        return [PSCustomObject]@{ Members = @(); Failed = $true; ErrorMessage = $resp.ErrorMessage }
    }
    return [PSCustomObject]@{ Members = @($resp.Value); Failed = $false; ErrorMessage = $null }
}

function Get-CAInvDirectMember {
    <#
    .SYNOPSIS
        Returns the DIRECT (non-nested) members of a group as a list of objects.
    .DESCRIPTION
        Counterpart to Get-CAInvTransitiveMember. Uses /groups/{id}/members, which returns only
        the directly assigned members (nested group members are NOT expanded; a nested group
        itself appears as a member object). This is exactly the semantics the authentication
        methods registration campaign uses: the campaign targets only direct members of a
        targeted group. Fails soft.
    .OUTPUTS
        PSCustomObject: @{ Members (array); Failed; ErrorMessage }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string] $GroupId
    )

    $resp = Invoke-CAInvGraph -Uri "groups/$GroupId/members?`$select=id,displayName,userPrincipalName,userType" -ApiVersion 'v1.0'
    if ($resp.Failed) {
        return [PSCustomObject]@{ Members = @(); Failed = $true; ErrorMessage = $resp.ErrorMessage }
    }
    return [PSCustomObject]@{ Members = @($resp.Value); Failed = $false; ErrorMessage = $null }
}

function Resolve-CAInvGroupReference {
    <#
    .SYNOPSIS
        Authoritative resolution of a referenced group ID.
    .DESCRIPTION
        Checks a group ID against active and deleted objects. First uses the already-loaded
        group set as a fast cache; if the ID isn't there, the function resolves directly via
        Graph (GET /groups/{id}) and then against /directory/deletedItems. This way the check
        works correctly regardless of whether layer 1 (Groups) ran in this run — crucial to
        avoid false positives when only layer 0 runs.
    .OUTPUTS
        PSCustomObject: @{ Exists (bool); State ('active'|'deleted'|'missing'|'unknown') }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string] $GroupId,
        [string[]] $KnownActiveIds = @()
    )

    if ($KnownActiveIds -contains $GroupId) {
        return [PSCustomObject]@{ Exists = $true; State = 'active' }
    }

    $active = Invoke-CAInvGraph -Uri "groups/$GroupId`?`$select=id" -ApiVersion 'v1.0'
    if (-not $active.Failed -and $active.Value) {
        return [PSCustomObject]@{ Exists = $true; State = 'active' }
    }

    if ($active.Failed -and $active.StatusCode -ne 404) {

        return [PSCustomObject]@{ Exists = $true; State = 'unknown' }
    }

    $deleted = Invoke-CAInvGraph -Uri "directory/deletedItems/microsoft.graph.group/$GroupId`?`$select=id" -ApiVersion 'v1.0'
    if (-not $deleted.Failed -and $deleted.Value) {
        return [PSCustomObject]@{ Exists = $true; State = 'deleted' }
    }

    return [PSCustomObject]@{ Exists = $false; State = 'missing' }
}

function Test-CAInvUserExcludedFromPolicy {
    <#
    .SYNOPSIS
        Determines whether a user is explicitly excluded from a CA policy.
    .DESCRIPTION
        Computes the effective exclude scope of a policy for a specific user: a direct user
        exclude, or (transitive) membership of an excluded group. Role-based excludes are
        flagged as 'uncertain' so the reliability can be factored into the finding.
    .OUTPUTS
        PSCustomObject: @{ Excluded (bool); Reason (string); Certainty ('high'|'medium') }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string] $UserId
    )

    $certainty = 'high'
    $users = Get-CAInvProp $Policy 'conditions.users'
    if (-not $users) {
        return [PSCustomObject]@{ Excluded = $false; Reason = ('No users condition on policy.'); Certainty = 'high' }
    }

    $excludeUsers  = @(Get-CAInvProp $users 'excludeUsers' @())
    $excludeGroups = @(Get-CAInvProp $users 'excludeGroups' @())
    $excludeRoles  = @(Get-CAInvProp $users 'excludeRoles' @())

    if ($excludeUsers -contains $UserId) {
        return [PSCustomObject]@{ Excluded = $true; Reason = ('Directly excluded as a user.'); Certainty = 'high' }
    }

    foreach ($gid in $excludeGroups) {
        if ([string]::IsNullOrWhiteSpace($gid)) { continue }
        $tm = Get-CAInvTransitiveMember -GroupId $gid
        if ($tm.Failed) {
            $certainty = 'medium'
            continue
        }
        if ($tm.Members | Where-Object { $_.id -eq $UserId }) {
            return [PSCustomObject]@{ Excluded = $true; Reason = ('Excluded via group {0}.' -f @($gid)); Certainty = 'high' }
        }
    }

    if ($excludeRoles.Count -gt 0) {
        $certainty = 'medium'
    }

    return [PSCustomObject]@{ Excluded = $false; Reason = ('No explicit exclusion found.'); Certainty = $certainty }
}
