function Get-CAInvPolicyLimit {
    <#
    .SYNOPSIS
        Domain 6.2 — Number of CA policies against the tenant limit.
    .DESCRIPTION
        Layer 0 collector. Counts the already-fetched CA policies against the hard tenant limit of
        240 and warns before it comes into view. Makes no Graph call of its own.

        Microsoft: "A maximum of 240 policies can be created in a single Microsoft Entra
        organization (tenant)" (service limits and restrictions, checked 25-08-2026).

        The pitfall is in what counts: report-only and disabled policies count just as much as
        enabled ones. It's exactly a migration project that stacks temporary report-only policies
        next to the existing set, so that's precisely the scenario where a tenant runs into the
        limit without anyone seeing it coming. That's why the observation breaks the count down by
        state.

        The 80 percent threshold is our own judgment call, not a Microsoft statement. The limit
        itself is, and that distinction is also stated in the check text.

        The Terms of Use limit (40 per tenant) is deliberately out of scope for this check: that
        belongs to domain 6.30 and thus to Foundation-15, not to a CA prefix.

        Gates on CAPoliciesFetchFailed, not on an empty policy set: a tenant with a confirmed zero
        CA policies is trivially Ready (0 is nowhere near 240), which the normal count logic below
        already produces without a special case. Only a failed fetch is Not assessed.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.2'
    $src    = 'GET /identity/conditionalAccess/policies'

    $policyLimit = 240
    $warnRatio = 0.8

    $caPolicies = @(Get-CAInvCaPolicy)

    if ($caPolicies.Count -eq 0 -and [bool](Get-CAInvProp $script:CAInvContext 'CAPoliciesFetchFailed' $true)) {
        New-CAInvRecord -Domain $domain -CheckId 'Foundation-11' -ObjectType 'Tenant' `
            -Property 'policies.count' -Status 'Not assessed' `
            -NotAssessedReason ('CA policies not available (layer 0 not run, or not readable).') `
            -GraphSource $src | Out-Null
        return
    }

    $total = $caPolicies.Count
    $byState = @{ enabled = 0; enabledForReportingButNotEnforced = 0; disabled = 0; other = 0 }
    foreach ($p in $caPolicies) {
        $state = [string](Get-CAInvProp $p 'state' '')
        if ($byState.ContainsKey($state)) { $byState[$state]++ } else { $byState['other']++ }
    }

    $breakdown = "$($byState['enabled']) on, $($byState['enabledForReportingButNotEnforced']) report-only, $($byState['disabled']) off"
    if ($byState['other'] -gt 0) { $breakdown += ", $($byState['other']) with an unknown state" }

    $warnAt = [int][math]::Ceiling($policyLimit * $warnRatio)
    $observed = "$total of a maximum of $policyLimit policies ($breakdown). Every state counts toward the limit."

    if ($total -ge $policyLimit) {
        New-CAInvRecord -Domain $domain -CheckId 'Foundation-11' -ObjectType 'Tenant' `
            -Property 'policies.count' -ObservedValue $observed `
            -Status 'Gap' -GraphSource $src `
            -Recommendation ('The tenant is at the hard limit of {0} Conditional Access policies. No more policies can be added, not even a temporary report-only policy for a rollout. Clean up disabled and expired report-only policies before the rollout starts, or consolidate policies.' -f @($policyLimit)) | Out-Null
    }
    elseif ($total -ge $warnAt) {
        New-CAInvRecord -Domain $domain -CheckId 'Foundation-11' -ObjectType 'Tenant' `
            -Property 'policies.count' -ObservedValue $observed `
            -Status 'Review required' -GraphSource $src `
            -Recommendation ('The tenant is at or above {0} policies, our own warning threshold of {1} percent of the {2} limit. Assess whether enough room remains for the planned rollout: it typically adds temporary report-only policies, and those count too. Clean up disabled and expired report-only policies if needed.' -f @($warnAt, [int]($warnRatio * 100), $policyLimit)) | Out-Null
    }
    else {
        New-CAInvRecord -Domain $domain -CheckId 'Foundation-11' -ObjectType 'Tenant' `
            -Property 'policies.count' -ObservedValue $observed `
            -Status 'Ready' -GraphSource $src | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$total of maximum $policyLimit CA policies ($breakdown)."
}
