function Get-CAInvDefenderDependency {
    <#
    .SYNOPSIS
        Domain 6.29 — Defender dependencies.
    .DESCRIPTION
        Layer 4 collector. CA controls can rely on device risk from Microsoft Defender for
        Endpoint (via the Intune connector) and on signals from Defender for Cloud Apps. This
        collector checks whether that link is present; if the endpoint or license is missing, the
        status is explicitly Not assessed and the collector never fails hard. The Defender APIs themselves require permissions that can fall outside
        this script's standard Graph scope.

        Precheck: a missing connector is only relevant if the
        compliance policy actually relies on device threat protection. Reuses
        `CompliancePolicyUsesDefender` from Device-02 (layer 4, runs before this); no extra Graph
        call. If that signal is unknown (Device-02 not run/failed), behavior stays unchanged.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.29'
    $src    = 'GET /deviceManagement/mobileThreatDefenseConnectors'

    $ctx = $script:CAInvContext
    $defenderRelevanceKnown = ($ctx.PSObject.Properties.Name -contains 'CompliancePolicyUsesDefender')
    $usesDefender = $defenderRelevanceKnown -and [bool]$ctx.CompliancePolicyUsesDefender

    if (-not (Test-CAInvLicensePrecondition -CheckId 'Device-10' -Domain $domain `
            -ObjectType 'Connector' -Property 'mobileThreatDefenseConnectors' -GraphSource $src `
            -Consequence ('Without Intune, there can be no mobile threat defense connector.'))) {
        return
    }

    $resp = Invoke-CAInvGraph -Uri 'deviceManagement/mobileThreatDefenseConnectors' -ApiVersion 'v1.0'
    if ($resp.Failed) {
        New-CAInvRecord -Domain $domain -CheckId 'Device-10' -ObjectType 'Connector' `
            -Property 'mobileThreatDefenseConnectors' -Status 'Not assessed' `
            -NotAssessedReason ('Could not read mobileThreatDefenseConnectors: {0}. Possibly no Intune license/permissions.' -f @($resp.ErrorMessage)) `
            -GraphSource $src | Out-Null
        return
    }

    $connectors = @($resp.Value)
    Write-CAInvRaw -Domain $domain -Endpoint 'mtdConnectors' -Data $connectors | Out-Null

    $active = @($connectors | Where-Object { (Get-CAInvProp $_ 'partnerState' '') -eq 'available' })

    if ($connectors.Count -eq 0 -and $defenderRelevanceKnown -and -not $usesDefender) {
        New-CAInvRecord -Domain $domain -CheckId 'Device-10' -ObjectType 'Connector' `
            -Property 'defenderConnector' -ObservedValue 'No mobile threat defense connector configured; no compliance policy uses device threat protection, so not applicable.' `
            -Status 'Ready' -GraphSource $src | Out-Null
    }
    elseif ($connectors.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Device-10' -ObjectType 'Connector' `
            -Property 'defenderConnector' -ObservedValue 'No mobile threat defense connector configured.' `
            -Status 'Review required' -ManualReview -GraphSource $src `
            -Recommendation ('No Defender connector found. CA controls that rely on device risk (e.g. via Defender for Endpoint) won''t work. Confirm whether device-risk signaling is part of the CA design.') | Out-Null
    }
    else {
        New-CAInvRecord -Domain $domain -CheckId 'Device-10' -ObjectType 'Connector' `
            -Property 'defenderConnector' -ObservedValue "$($active.Count) active of $($connectors.Count) connector(s)" `
            -Status 'Ready' -GraphSource $src | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($connectors.Count) MTD connector(s), $($active.Count) active."
}
