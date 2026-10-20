function Get-CAInvWorkloadIdentity {
    <#
    .SYNOPSIS
        Domain 6.15 — Workload identities.
    .DESCRIPTION
        Layer 3 collector. Distinguishes the non-human identities (managed identities and
        application service principals with credentials) and flags, where the license allows
        it, risky service principals. Workload identities fall outside user CA but within
        Conditional Access for workload identities; they're a blind spot in CA standardization.

        Reuses the already-fetched ServicePrincipals (6.14) when available.

        WLI-002 (federated identity credentials per app) was removed because its security value is debatable. Investigated: federated identity credentials are
        Microsoft's own recommended best practice (secretless CI/CD auth, e.g. GitHub Actions/Azure
        DevOps/Kubernetes workloads) — having a FIC is not a risk signal, unlike how the check
        treated it ('Review required' for every app with a FIC, 52% of apps in the live-tenant run
        wentzo). The risk Microsoft actually documents is specifically a FIC with a *mutable*
        subject claim (e.g. a GitHub repo that can be deleted/renamed/transferred, after which
        another party claims the same identifier — "dangling federated identity credential") —
        that cannot be reliably detected from Graph/Entra alone (requires knowledge of the
        external issuer per type, and for 'dangling' even a call to that external system). Same
        removal pattern as APP-003/APP-005/APP-006/DEV-002 earlier in this project: a check that
        triggers broadly without distinguishing well- from poorly-configured, so noise without a
        CA-relevant action.

        Identity-18 (2026-08-20, verification round): 'riskyServicePrincipals' is GA in v1.0 (was
        beta) and requires a 'Workload Identities Premium' license, NOT Entra ID P2 (confirmed via
        Microsoft Learn). That license cannot be reliably derived from subscribedSkus (the exact
        servicePlanName is nowhere documented; adding a guess for it to
        config/sku-license-map.json would violate the project rule "never guess"). The earlier
        hard P2 precheck was therefore wrong on both endpoint version and license signal. Now:
        just call it (like Identity-17 for servicePrincipals), Invoke-CAInvGraphOrNotAssessed
        automatically catches a missing license as Not assessed.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.15'

    $ctx = $script:CAInvContext
    $sps = @(if ($ctx.PSObject.Properties.Name -contains 'ServicePrincipals') { @($ctx.ServicePrincipals) } else { @() })

    if ($sps.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-17' -ObjectType 'ServicePrincipal' `
            -Property 'workloadIdentities' -Status 'Not assessed' `
            -NotAssessedReason ('Service principals not available (6.14 not run, or not readable).') `
            -GraphSource 'GET /servicePrincipals' | Out-Null
        return
    }

    $managedIdentities = @($sps | Where-Object { (Get-CAInvProp $_ 'servicePrincipalType' '') -eq 'ManagedIdentity' })
    $appPrincipals     = @($sps | Where-Object { (Get-CAInvProp $_ 'servicePrincipalType' '') -eq 'Application' })

    New-CAInvRecord -Domain $domain -CheckId 'Identity-17' -ObjectType 'ServicePrincipal' `
        -Property 'workloadIdentityPopulation' `
        -ObservedValue "managed identities=$($managedIdentities.Count); application SPs=$($appPrincipals.Count)" `
        -Status 'Ready' -GraphSource 'GET /servicePrincipals' | Out-Null

    $riskResp = Invoke-CAInvGraphOrNotAssessed -Uri 'identityProtection/riskyServicePrincipals' -ApiVersion 'v1.0' `
        -Domain $domain -CheckId 'Identity-18' -ObjectType 'ServicePrincipal' -Property 'riskyServicePrincipals' `
        -GraphSource 'GET /identityProtection/riskyServicePrincipals' `
        -NotAssessedReasonPrefix ('Could not read riskyServicePrincipals (possibly no Workload Identities Premium license)')
    if (-not $riskResp.Failed) {

        $riskRawPath = Write-CAInvRaw -Domain $domain -Endpoint 'riskyServicePrincipals' -Data $riskResp.Value
        $risky = @($riskResp.Value | Where-Object { (Get-CAInvProp $_ 'riskState' 'none') -notin @('none', 'dismissed', 'remediated') })
        New-CAInvRecord -Domain $domain -CheckId 'Identity-18' -ObjectType 'ServicePrincipal' `
            -Property 'riskyServicePrincipals' -ObservedValue "$($risky.Count) service principal(s) with active risk" `
            -Status ($(if ($risky.Count -gt 0) { 'Review required' } else { 'Ready' })) `
            -ManualReview:($risky.Count -gt 0) `
            -ApiVersion 'v1.0' -GraphSource 'GET /identityProtection/riskyServicePrincipals' -RawPath $riskRawPath `
            -Recommendation ($(if ($risky.Count -gt 0) { 'Investigate the risky workload identities; consider CA for workload identities to block or restrict them.' } else { $null })) | Out-Null
    }
}
