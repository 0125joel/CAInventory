function Get-CAInvConditionalAccessPolicy {
    <#
    .SYNOPSIS
        Domain 6.2 — Existing Conditional Access configuration.
    .DESCRIPTION
        Exports all CA policies plus named locations. The raw response is kept UNCHANGED. Produces normalized records on state, 'All users' scope
        without exclusions, and references to groups that are resolved later by the integrity
        check. The policies are kept in the context object so layer 1 (emergency access), the
        integrity checks, and New-CAInvApiDriftReport (unknown top-level properties, formerly
        Foundation-08) can reuse them.

        Also sets CAPoliciesFetchFailed (bool) alongside CAPolicies: a consumer that reads
        Get-CAInvCaPolicy and finds it empty cannot otherwise tell a failed fetch (layer 0 didn't
        run, or the call errored) apart from a tenant that genuinely has zero CA policies — the
        first is Not assessed, the second can be a confirmed Gap (Evidence-09).

        Besides the v1.0 set, the policy collection is fetched a second time via beta. That's not
        duplicate work: some session controls exist exclusively in beta (secureSignInSession for
        Token Protection, continuousAccessEvaluation, globalSecureAccessFilteringProfile), while
        v1.0 knows exactly five. A check that looked at secureSignInSession on v1.0 could therefore
        never become Ready and structurally reported a Gap that didn't exist (backlog item B1). The
        beta call is deliberately SOFT: if it fails, $ctx.CAPoliciesBeta stays empty and the
        consuming checks set themselves to Not assessed with the real failure reason. All other
        checks keep running on the v1.0 set, so an unstable beta endpoint can never drag down the
        rest of layer 0.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.2'
    $src    = 'GET /identity/conditionalAccess/policies'

    $resp = Invoke-CAInvGraphOrNotAssessed -Uri 'identity/conditionalAccess/policies' -ApiVersion 'v1.0' `
        -Domain $domain -CheckId 'Foundation-06' -ObjectType 'ConditionalAccessPolicy' -Property 'policies' `
        -GraphSource $src -NotAssessedReasonPrefix ('Could not read CA policies')
    if ($resp.Failed) {
        Add-CAInvContextData -Context $script:CAInvContext -Name 'CAPoliciesFetchFailed' -Value $true
        return
    }

    $policies = @($resp.Value)
    $rawPath = Write-CAInvRaw -Domain $domain -Endpoint 'conditionalAccessPolicies' -Data $policies

    Add-CAInvContextData -Context $script:CAInvContext -Name 'CAPolicies' -Value $policies
    Add-CAInvContextData -Context $script:CAInvContext -Name 'CAPoliciesFetchFailed' -Value $false

    $betaResp = Invoke-CAInvGraph -Uri 'identity/conditionalAccess/policies' -ApiVersion 'beta' `
        -Headers @{ 'Prefer' = 'include-unknown-enum-members' }
    if ($betaResp.Failed) {

        Add-CAInvContextData -Context $script:CAInvContext -Name 'CAPoliciesBeta' -Value @()
        Add-CAInvContextData -Context $script:CAInvContext -Name 'CAPoliciesBetaError' -Value ([string]$betaResp.ErrorMessage)
        Write-CAInvLog -Level 'WARN' -Domain $domain -Message "Beta policy set unavailable; session controls that only exist in beta remain Not assessed: $($betaResp.ErrorMessage)"
    }
    else {
        $betaPolicies = @($betaResp.Value)
        Write-CAInvRaw -Domain $domain -Endpoint 'conditionalAccessPoliciesBeta' -Data $betaPolicies | Out-Null
        Add-CAInvContextData -Context $script:CAInvContext -Name 'CAPoliciesBeta' -Value $betaPolicies
        Add-CAInvContextData -Context $script:CAInvContext -Name 'CAPoliciesBetaError' -Value $null
        Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($betaPolicies.Count) CA policies additionally fetched via beta (session controls that don't exist in v1.0)."
    }

    $nlResp = Invoke-CAInvGraph -Uri 'identity/conditionalAccess/namedLocations' -ApiVersion 'v1.0'
    if (-not $nlResp.Failed) {
        Write-CAInvRaw -Domain '6.20' -Endpoint 'namedLocations' -Data $nlResp.Value | Out-Null
        Add-CAInvContextData -Context $script:CAInvContext -Name 'NamedLocations' -Value @($nlResp.Value)
    }

    foreach ($p in $policies) {

        New-CAInvRecord -Domain $domain -CheckId 'Foundation-06' -ObjectType 'ConditionalAccessPolicy' `
            -ObjectId $p.id -ObjectName $p.displayName -Property 'state' -ObservedValue $p.state `
            -Status 'Ready' -GraphSource $src -RawPath $rawPath | Out-Null

        $users = Get-CAInvProp $p 'conditions.users'
        if ($users -and (Get-CAInvPolicyUserScope -Policy $p).TargetsAllUsers -and (Test-CAInvPolicyRestrictsSignIn -Policy $p)) {
            $hasExcl = ((@(Get-CAInvProp $users 'excludeUsers' @()).Count -gt 0) -or (@(Get-CAInvProp $users 'excludeGroups' @()).Count -gt 0) -or (@(Get-CAInvProp $users 'excludeRoles' @()).Count -gt 0))
            if (-not $hasExcl) {

                $bgKnown = (
                    @(Get-CAInvProp $script:CAInvContext 'EmergencyAccountUpn' @()).Count -gt 0 -or
                    @(Get-CAInvProp $script:CAInvContext 'EmergencyAccountId' @()).Count -gt 0
                )

                if ($bgKnown) {
                    New-CAInvRecord -Domain $domain -CheckId 'Foundation-07' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $p.id -ObjectName $p.displayName -Property 'includeUsers=All; exclusions' `
                        -ObservedValue 'All users with no exclusion at all, while the break-glass set is explicitly provided; those accounts therefore fall within this policy.' `
                        -Status 'Gap' `
                        -GraphSource $src `
                        -Recommendation ('Explicitly exclude the break-glass accounts from this policy. Without an exception, this policy can block your emergency accounts right when you need them.') `
                        -RawPath $rawPath | Out-Null
                }
                else {
                    New-CAInvRecord -Domain $domain -CheckId 'Foundation-07' -ObjectType 'ConditionalAccessPolicy' `
                        -ObjectId $p.id -ObjectName $p.displayName -Property 'includeUsers=All; exclusions' `
                        -ObservedValue 'All users with no exclusion at all' -Status 'Review required' `
                        -GraphSource $src -ManualReview `
                        -Recommendation ('Confirm that break-glass accounts are excluded from this policy. Provide the emergency accounts with -EmergencyAccountUpn for a definitive verdict instead of this confirmation prompt.') `
                        -RawPath $rawPath | Out-Null
                }
            }
        }
    }

    $baselineMfa = @($policies | Where-Object {
        $gc = Get-CAInvProp $_ 'grantControls'
        $builtIn = @(Get-CAInvProp $gc 'builtInControls' @())
        $hasStrength = [bool](Get-CAInvProp $gc 'authenticationStrength.id')
        $totalControls = $builtIn.Count + $(if ($hasStrength) { 1 } else { 0 })
        $operator = [string](Get-CAInvProp $gc 'operator' 'AND')

        $_.state -eq 'enabled' -and
        (Get-CAInvPolicyUserScope -Policy $_).TargetsAllUsers -and
        ($builtIn -contains 'mfa' -or $hasStrength) -and
        ($operator -ne 'OR' -or $totalControls -le 1)
    })
    if ($baselineMfa.Count -gt 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Foundation-09' -ObjectType 'ConditionalAccessPolicy' `
            -ObjectName ($baselineMfa[0].displayName) -Property 'baselineMfaPolicy' `
            -ObservedValue "$($baselineMfa.Count) enabled policy(s) enforce MFA/strength for all users" `
            -Status 'Ready' -GraphSource $src -RawPath $rawPath | Out-Null
    }
    else {
        New-CAInvRecord -Domain $domain -CheckId 'Foundation-09' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'baselineMfaPolicy' -ObservedValue 'No enabled policy enforces MFA for all users' `
            -Status 'Gap' -GraphSource $src -RawPath $rawPath `
            -Recommendation ('Set up a baseline policy that enforces MFA (or an authentication strength) for all users, with only break-glass excluded. This is the most fundamental CA/Secure Score recommendation.') | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($policies.Count) CA policies inventoried."
}
