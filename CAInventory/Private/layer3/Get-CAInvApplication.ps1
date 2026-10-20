function Get-CAInvApplication {
    <#
    .SYNOPSIS
        Domain 6.14 — Enterprise apps and app registrations.
    .DESCRIPTION
        Layer 3 collector. Reads /servicePrincipals and /applications and records the population:
        counts of service principals and app registrations.

        Ownership is deliberately NOT checked tenant-wide here (formerly APP-003, removed
        v0.15.0, breaking): flagging every app registration without an owner is app hygiene, not
        a CA implementation precondition — most apps in a tenant never have anything to do with
        CA. The CA-relevant variant (an app that's actually excluded from a CA policy and has no
        owner) runs via Foundation-12 (flagging) and Foundation-14 (full cross-check in the
        integrity check), both scoped to CA exclusions.

        The service principals are kept on the context object (ServicePrincipals) so the workload
        identity collector (6.15) can reuse them.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.14'
    $src    = 'GET /servicePrincipals; GET /applications'

    $spResp = Invoke-CAInvGraphOrNotAssessed -Uri 'servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId' -ApiVersion 'v1.0' -MaxPages 100 `
        -Domain $domain -CheckId 'Foundation-13' -ObjectType 'ServicePrincipal' -Property 'servicePrincipals' `
        -GraphSource $src -NotAssessedReasonPrefix ('Could not read /servicePrincipals')
    if ($spResp.Failed) { return }

    $sps = @($spResp.Value)
    Write-CAInvRaw -Domain $domain -Endpoint 'servicePrincipals' -Data $sps | Out-Null
    Add-CAInvContextData -Context $script:CAInvContext -Name 'ServicePrincipals' -Value $sps

    $spCappedNote = if ($spResp.Capped) { ' (page limit reached; possibly incomplete)' } else { '' }
    New-CAInvRecord -Domain $domain -CheckId 'Foundation-13' -ObjectType 'ServicePrincipal' `
        -Property 'count' -ObservedValue "$($sps.Count) service principals$spCappedNote" -Status 'Ready' `
        -GraphSource 'GET /servicePrincipals' | Out-Null

    $appResp = Invoke-CAInvGraphOrNotAssessed -Uri 'applications?$select=id,appId,displayName,signInAudience,passwordCredentials,keyCredentials' -ApiVersion 'v1.0' -MaxPages 100 `
        -Domain $domain -CheckId 'Foundation-13' -ObjectType 'Application' -Property 'applications' `
        -GraphSource 'GET /applications' -NotAssessedReasonPrefix ('Could not read /applications')
    if ($appResp.Failed) { return }

    $apps = @($appResp.Value)
    Write-CAInvRaw -Domain $domain -Endpoint 'applications' -Data $apps | Out-Null

    $appCappedNote = if ($appResp.Capped) { ' (page limit reached; possibly incomplete)' } else { '' }
    New-CAInvRecord -Domain $domain -CheckId 'Foundation-13' -ObjectType 'Application' `
        -Property 'applicationCount' -ObservedValue "$($apps.Count) app registrations$appCappedNote" `
        -Status 'Ready' -GraphSource 'GET /applications' | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($sps.Count) service principals, $($apps.Count) applications."
}
