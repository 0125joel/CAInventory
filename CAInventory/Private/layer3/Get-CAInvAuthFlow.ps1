function Get-CAInvAuthFlow {
    <#
    .SYNOPSIS
        Domain 6.27 — Authentication flows (device code, authentication transfer).
    .DESCRIPTION
        Layer 3 collector. Checks whether Conditional Access uses the authenticationFlows
        condition (device code flow and authentication transfer). These flows are a known
        phishing vector and belong explicitly blocked or restricted in a modern CA baseline. Reads the already-fetched CAPolicies (layer 0) when
        available, and falls back gracefully otherwise.

        Gates on CAPoliciesFetchFailed, not on an empty policy set: a confirmed zero CA policies
        falls through to the existing "no policy uses this condition" branches, which already give
        the right answer (Condition-07 Review required, Condition-08 Ready). Only a failed fetch is
        Not assessed for both CheckIds.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.27'
    $src    = 'CA conditions.authenticationFlows'

    $caPolicies = @(Get-CAInvCaPolicy)

    if ($caPolicies.Count -eq 0 -and [bool](Get-CAInvProp $script:CAInvContext 'CAPoliciesFetchFailed' $true)) {
        $notAssessedReason = 'CA policies not available (layer 0 not run, or not readable).'
        New-CAInvRecord -Domain $domain -CheckId 'Condition-07' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'authenticationFlows' -Status 'Not assessed' `
            -NotAssessedReason $notAssessedReason -GraphSource $src | Out-Null
        New-CAInvRecord -Domain $domain -CheckId 'Condition-08' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'deprecatedApprovedClientApp' -Status 'Not assessed' `
            -NotAssessedReason $notAssessedReason -GraphSource $src | Out-Null
        return
    }

    $withFlows = @($caPolicies | Where-Object {
        $tt = Get-CAInvProp $_ 'conditions.authenticationFlows.transferMethods'
        $tt -and "$tt" -ne ''
    })

    if ($withFlows.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-07' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'authenticationFlows' -ObservedValue 'No CA policy at all uses the authenticationFlows condition.' `
            -Status 'Review required' -ManualReview -GraphSource $src `
            -Recommendation ('Device code flow and authentication transfer are not restricted anywhere by CA. Consider a policy that blocks device code flow, unless there''s a deliberate use case.') | Out-Null
    }
    else {
        foreach ($p in $withFlows) {
            $tm = Get-CAInvProp $p 'conditions.authenticationFlows.transferMethods'
            New-CAInvRecord -Domain $domain -CheckId 'Condition-07' -ObjectType 'ConditionalAccessPolicy' `
                -ObjectId (Get-CAInvProp $p 'id') -ObjectName (Get-CAInvProp $p 'displayName') -Property 'authenticationFlows.transferMethods' `
                -ObservedValue "transferMethods=$tm; state=$(Get-CAInvProp $p 'state')" `
                -Status 'Ready' -GraphSource $src `
                -Recommendation ('Confirm that the flow restriction has the intended scope (device code flow is the main phishing vector).') | Out-Null
        }
    }

    $approvedAppPolicies = @($caPolicies | Where-Object {
        $_.state -ne 'disabled' -and (@(Get-CAInvProp $_ 'grantControls.builtInControls' @()) -contains 'approvedApplication')
    })
    if ($approvedAppPolicies.Count -gt 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-08' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'deprecatedApprovedClientApp' `
            -ObservedValue "$($approvedAppPolicies.Count) policy(s) use the deprecated grant control 'approved client app'" `
            -Status 'Review required' -ManualReview -GraphSource $src `
            -Recommendation ('From June 30, 2026, ''Require approved client app'' becomes read-only: it can no longer be created or changed, only disabled or deleted. Existing, enabled policies keep enforcing as long as they stay enabled; there''s no silent loss of enforcement. Migrate to ''Require app protection policy'' in time, because after the freeze you can no longer adjust these policies.') | Out-Null
    }
    else {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-08' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'deprecatedApprovedClientApp' -ObservedValue "No policy uses the deprecated grant control 'approved client app'." `
            -Status 'Ready' -GraphSource $src | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($withFlows.Count) CA policies with an authenticationFlows condition."
}
