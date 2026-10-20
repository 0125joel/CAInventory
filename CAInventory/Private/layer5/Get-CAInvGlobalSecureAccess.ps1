function Get-CAInvGlobalSecureAccess {
    <#
    .SYNOPSIS
        Domain 6.28 — Global Secure Access and compliant network.
    .DESCRIPTION
        Layer 5 collector, and the function most likely to return Not assessed. Parts of Global
        Secure Access (GSA) are preview or only available via the portal, and it's an open
        research question which GSA and compliant network APIs are officially supported in the
        target cloud. This function therefore NEVER
        fails hard: if the endpoint is unavailable, it records that as a finding instead of
        breaking the run.

        Precheck: `networkAccess/settings` itself has no
        properties of its own (Microsoft Learn: only redirects to sub-resources) and so says
        little about whether the tenant actually uses compliant-network CA. The reliable, specific
        signal is `compliantNetworkNamedLocation`: a named location with displayName "All
        Compliant Network Locations" that Microsoft creates EXCLUSIVELY automatically as soon as
        an admin enables "Enable Conditional Access Signaling for Microsoft Entra ID" (Global
        Secure Access > Settings > Session management > Adaptive access). No Create API, no
        manual creation route via the regular named-location flow, so its existence is direct
        evidence, not a proxy. Reused from `$ctx.NamedLocations` (already fetched in layer 0 /
        Condition-01), no extra Graph call or scope needed. If the named location is missing, the
        compliant-network condition isn't enabled and this check doesn't apply (Ready/Info instead
        of a forced Review required).
    #>
    [CmdletBinding()]
    param()

    $domain = '6.28'
    $src    = 'GET /networkAccess/settings (beta)'

    $ctx = $script:CAInvContext
    $namedLocationsKnown = ($ctx.PSObject.Properties.Name -contains 'NamedLocations')
    $hasCompliantNetworkLocation = $namedLocationsKnown -and (@(@($ctx.NamedLocations) | Where-Object {
        (Get-CAInvProp $_ '@odata.type' '') -match 'compliantNetworkNamedLocation'
    })).Count -gt 0

    if ($namedLocationsKnown -and -not $hasCompliantNetworkLocation) {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-12' -ObjectType 'NetworkAccess' `
            -Property 'globalSecureAccess' `
            -ObservedValue 'No "All Compliant Network Locations" named location found (via Condition-01); the compliant network condition is not enabled.' `
            -Status 'Ready' -GraphSource 'GET /identity/conditionalAccess/namedLocations' | Out-Null
        Write-CAInvLog -Level 'INFO' -Domain $domain -Message 'GSA compliant-network condition not enabled (precheck via named locations); not applicable.'
        return
    }

    $resp = Invoke-CAInvGraph -Uri 'networkAccess/settings' -ApiVersion 'beta'
    if ($resp.Failed) {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-12' -ObjectType 'NetworkAccess' `
            -Property 'globalSecureAccess' -Status 'Not assessed' `
            -NotAssessedReason ('GSA endpoint not available or not supported in this cloud/license: {0}' -f @($resp.ErrorMessage)) `
            -ApiVersion 'beta' -GraphSource $src `
            -Recommendation ('Verify per target cloud which Global Secure Access and compliant network APIs are officially supported; some are preview or portal-only.') | Out-Null
        Write-CAInvLog -Level 'INFO' -Domain $domain -Message 'GSA not assessable via API; recorded as a finding.'
        return
    }

    $settings = @($resp.Value) | Select-Object -First 1
    Write-CAInvRaw -Domain $domain -Endpoint 'networkAccessSettings' -Data $settings | Out-Null

    New-CAInvRecord -Domain $domain -CheckId 'Condition-12' -ObjectType 'NetworkAccess' `
        -Property 'globalSecureAccess' -ObservedValue 'Global Secure Access settings present; check compliant network usage in CA.' `
        -Status 'Review required' -ManualReview -ApiVersion 'beta' -GraphSource $src `
        -Recommendation ('GSA is present. Confirm whether CA policies use the "compliant network" condition and whether it has the intended scope.') | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message 'GSA settings read.'
}
