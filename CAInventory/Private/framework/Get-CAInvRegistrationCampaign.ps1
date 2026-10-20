function Get-CAInvRegistrationCampaign {
    <#
    .SYNOPSIS
        Fetches and normalizes the authentication methods registration campaign (proof-up nudge).
    .DESCRIPTION
        Reads GET /policies/authenticationMethodsPolicy and extracts
        registrationEnforcement.authenticationMethodsRegistrationCampaign. Normalizes state,
        targeting, and the include/exclude targets into a stable object and caches the result on
        the run context object (RegistrationCampaign), so both the emergency access check (layer
        1, Emergency-04) and the authentication layer (layer 2) use the same measurement without
        reading twice.

        Important semantic difference from Conditional Access: the campaign resolves group
        membership on DIRECT members. Nested group members fall outside the resolution. This
        object therefore explicitly separates include/exclude groups and leaves the direct-member
        check to Test-CAInvUserInCampaignScope.

        State semantics (v1.0 enum enabled|disabled|default):
          - enabled: explicitly on; targeting follows include/exclude targets.
          - default: Microsoft-managed. Microsoft determines the targeting and in practice targets
            all MFA-capable users. We treat this as "effectively on with all users included";
            exclude targets still apply.
          - disabled: off.
    .OUTPUTS
        PSCustomObject: @{ Failed; ErrorMessage; State; EffectivelyOn; AllUsersIncluded;
            TargetedMethod; SnoozeDurationInDays; EnforceAfterSnoozes;
            IncludeUserIds; IncludeGroupIds; ExcludeUserIds; ExcludeGroupIds;
            IncludeTargets; ExcludeTargets; RawPath }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $ctx = $script:CAInvContext

    if ($ctx -and $ctx.PSObject.Properties['RegistrationCampaign'] -and $ctx.RegistrationCampaign) {
        return $ctx.RegistrationCampaign
    }

    $resp = Invoke-CAInvGraph -Uri 'policies/authenticationMethodsPolicy' -ApiVersion 'v1.0'
    if ($resp.Failed) {
        $result = [PSCustomObject]@{
            Failed = $true; ErrorMessage = $resp.ErrorMessage; State = $null
            EffectivelyOn = $false; AllUsersIncluded = $false; TargetedMethod = $null
            SnoozeDurationInDays = $null; EnforceAfterSnoozes = $null
            IncludeUserIds = @(); IncludeGroupIds = @(); ExcludeUserIds = @(); ExcludeGroupIds = @()
            IncludeTargets = @(); ExcludeTargets = @(); RawPath = $null
        }
        if ($ctx) { Add-CAInvContextData -Context $ctx -Name 'RegistrationCampaign' -Value $result -AllowOverwrite }
        return $result
    }

    $policyValues = @($resp.Value)
    $policy   = if ($policyValues.Count -gt 0) { $policyValues[0] } else { $null }
    $campaign = Get-CAInvProp $policy 'registrationEnforcement.authenticationMethodsRegistrationCampaign'
    $raw = Write-CAInvRaw -Domain '6.7' -Endpoint 'authenticationMethodsRegistrationCampaign' -Data $campaign

    $state = Get-CAInvProp $campaign 'state' 'disabled'
    $include = @(Get-CAInvProp $campaign 'includeTargets' @())
    $exclude = @(Get-CAInvProp $campaign 'excludeTargets' @())

    $allUsersIncluded = [bool](@($include | Where-Object { $_.id -eq 'all_users' }).Count)

    $incUserIds  = @($include | Where-Object { $_.targetType -eq 'user' } | ForEach-Object { $_.id })
    $incGroupIds = @($include | Where-Object { $_.targetType -eq 'group' -and $_.id -ne 'all_users' } | ForEach-Object { $_.id })
    $excUserIds  = @($exclude | Where-Object { $_.targetType -eq 'user' } | ForEach-Object { $_.id })
    $excGroupIds = @($exclude | Where-Object { $_.targetType -eq 'group' } | ForEach-Object { $_.id })

    $method = @($include | ForEach-Object { Get-CAInvProp $_ 'targetedAuthenticationMethod' } | Where-Object { $_ } | Select-Object -Unique) -join ', '
    if ([string]::IsNullOrWhiteSpace($method)) { $method = if ($state -eq 'default') { 'Microsoft-managed (method not explicit)' } else { 'unknown' } }

    $effectivelyOn = ($state -eq 'enabled' -or $state -eq 'default')

    if ($state -eq 'default') { $allUsersIncluded = $true }

    $result = [PSCustomObject]@{
        Failed               = $false
        ErrorMessage         = $null
        State                = $state
        EffectivelyOn        = $effectivelyOn
        AllUsersIncluded     = $allUsersIncluded
        TargetedMethod       = $method
        SnoozeDurationInDays = Get-CAInvProp $campaign 'snoozeDurationInDays'
        EnforceAfterSnoozes  = Get-CAInvProp $campaign 'enforceRegistrationAfterAllowedSnoozes'
        IncludeUserIds       = $incUserIds
        IncludeGroupIds      = $incGroupIds
        ExcludeUserIds       = $excUserIds
        ExcludeGroupIds      = $excGroupIds
        IncludeTargets       = $include
        ExcludeTargets       = $exclude
        RawPath              = $raw
    }

    if ($ctx) { Add-CAInvContextData -Context $ctx -Name 'RegistrationCampaign' -Value $result -AllowOverwrite }
    return $result
}

function Test-CAInvUserInCampaignScope {
    <#
    .SYNOPSIS
        Determines whether a user falls within the registration campaign's targeting, using the
        campaign's direct-members semantics.
    .DESCRIPTION
        A user is in scope when they are INCLUDED and not directly EXCLUDED. Crucially: for group
        targeting, the campaign only honors DIRECT members. A user who is excluded only via a
        nested (transitive, non-direct) group is therefore NOT excluded by the campaign and still
        falls in scope. We explicitly return that distinction (ExcludedNestedOnly) so the caller
        can build a targeted judgment on it.

        Group membership is fetched both directly (Get-CAInvDirectMember) and transitively
        (Get-CAInvTransitiveMember) to be able to detect the nested-only case. On a membership read
        error, Certainty becomes 'medium' so the caller can choose 'Review required' instead of a
        falsely hard verdict.
    .OUTPUTS
        PSCustomObject: @{ EffectivelyOn; Included; ExcludedDirect; ExcludedNestedOnly;
            InScope; Certainty; Reason }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string] $UserId,
        [Parameter(Mandatory)] $Campaign
    )

    if (-not $Campaign.EffectivelyOn) {
        return [PSCustomObject]@{
            EffectivelyOn = $false; Included = $false; ExcludedDirect = $false
            ExcludedNestedOnly = $false; InScope = $false; Certainty = 'high'
            Reason = 'Campaign is not effectively on (state={0}).' -f @($Campaign.State)
        }
    }

    $certainty = 'high'

    $included = $false
    if ($Campaign.AllUsersIncluded) {
        $included = $true
    }
    elseif ($Campaign.IncludeUserIds -contains $UserId) {
        $included = $true
    }
    else {
        foreach ($gid in $Campaign.IncludeGroupIds) {
            if ([string]::IsNullOrWhiteSpace($gid)) { continue }
            $dm = Get-CAInvDirectMember -GroupId $gid
            if ($dm.Failed) { $certainty = 'medium'; continue }
            if ($dm.Members | Where-Object { $_.id -eq $UserId }) { $included = $true; break }
        }
    }

    $excludedDirect = $false
    $excludedNestedOnly = $false
    if ($Campaign.ExcludeUserIds -contains $UserId) {
        $excludedDirect = $true
    }
    else {
        foreach ($gid in $Campaign.ExcludeGroupIds) {
            if ([string]::IsNullOrWhiteSpace($gid)) { continue }
            $dm = Get-CAInvDirectMember -GroupId $gid
            if ($dm.Failed) { $certainty = 'medium'; continue }
            if ($dm.Members | Where-Object { $_.id -eq $UserId }) { $excludedDirect = $true; break }

            $tm = Get-CAInvTransitiveMember -GroupId $gid
            if ($tm.Failed) { $certainty = 'medium'; continue }
            if ($tm.Members | Where-Object { $_.id -eq $UserId }) { $excludedNestedOnly = $true }
        }
    }

    $inScope = ($included -and -not $excludedDirect)

    $reason =
        if (-not $included) { 'Falls outside the campaign''s include targeting.' }
        elseif ($excludedDirect) { 'Included but directly excluded (user, or direct member of the exclusion group).' }
        elseif ($excludedNestedOnly) { 'Included and only excluded via a NESTED group; the campaign only honors direct members, so effectively in scope.' }
        else { 'Included and not excluded; falls within the campaign targeting.' }

    return [PSCustomObject]@{
        EffectivelyOn = $true; Included = $included; ExcludedDirect = $excludedDirect
        ExcludedNestedOnly = $excludedNestedOnly; InScope = $inScope
        Certainty = $certainty; Reason = $reason
    }
}
