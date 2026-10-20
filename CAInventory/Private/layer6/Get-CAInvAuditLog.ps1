function Get-CAInvAuditLog {
    <#
    .SYNOPSIS
        Domain 6.24 — Audit logs and change history.
    .DESCRIPTION
        Layer 6 collector. Reads /auditLogs/directoryAudits within the effective window and
        extracts the changes to Conditional Access policies: who changed what, and when. During a
        migration, CA's change history is the evidence that the baseline came about under control
        and doesn't drift unnoticed. Fails soft.

        The window is deliberately NOT EffectiveLookbackDays: that window applies to sign-in logs
        (extends up to the Log Analytics workspace retention, up to 90+ days).
        /auditLogs/directoryAudits is a separate Graph endpoint with its own hard retention limit
        that doesn't factor in an external workspace: 30 days with Entra ID P1/P2, 7 days without
        (confirmed via a live-tenant run: a `ge` filter before that limit returns a 400 "Minimum
        allowed time for activityDateTime is ..." — not a soft degradation to fewer results, a hard
        error).
    #>
    [CmdletBinding()]
    param()

    $domain = '6.24'
    $src    = 'GET /auditLogs/directoryAudits'

    $ctx = $script:CAInvContext
    $desiredWindow = Get-CAInvEffectiveLookbackWindow

    if (-not [bool](Get-CAInvProp $ctx 'Preflight.LicensesKnown' $false)) {
        New-CAInvRecord -Domain $domain -CheckId 'Evidence-03' -ObjectType 'AuditLog' `
            -Property 'caPolicyChanges' -Status 'Not assessed' `
            -NotAssessedReason ('License context unknown (preflight failed or not yet run); the Graph retention limit for audit logs (7 d Free, 30 d P1/P2) cannot be established, so the window cannot be determined.') `
            -GraphSource $src | Out-Null
        return
    }

    $hasPremium = [bool](Get-CAInvProp $ctx 'Preflight.Licenses.EntraIdP1' $false) -or [bool](Get-CAInvProp $ctx 'Preflight.Licenses.EntraIdP2' $false)
    $graphAuditRetentionCap = if ($hasPremium) { 30 } else { 7 }
    $window = [Math]::Min($desiredWindow, $graphAuditRetentionCap)
    if ($window -lt $desiredWindow) {
        Write-CAInvLog -Level 'DEBUG' -Domain $domain -Message "Audit log window limited to $window d (Graph retention limit for directoryAudits), desired was $desiredWindow d."
    }
    $since = ([DateTimeOffset]::UtcNow.AddDays(-$window)).ToString('yyyy-MM-ddTHH:mm:ssZ')

    $maxPages = 20
    $uri = "auditLogs/directoryAudits?`$filter=activityDateTime ge $since and category eq 'Policy'&`$top=1000"
    $resp = Invoke-CAInvGraphOrNotAssessed -Uri $uri -ApiVersion 'v1.0' -MaxPages $maxPages `
        -Domain $domain -CheckId 'Evidence-03' -ObjectType 'AuditLog' -Property 'directoryAudits' `
        -GraphSource $src -NotAssessedReasonPrefix ('Could not read /auditLogs/directoryAudits')
    if ($resp.Failed) { return }

    $audits = @($resp.Value)
    Write-CAInvRaw -Domain $domain -Endpoint 'directoryAudits' -Data $audits | Out-Null

    $caChanges = @($audits | Where-Object {
        $target = @(Get-CAInvProp $_ 'targetResources' @())
        ("$(Get-CAInvProp $_ 'activityDisplayName')" -match '(?i)conditional access') -or
        (@($target | Where-Object { "$(Get-CAInvProp $_ 'type')" -match '(?i)conditionalAccess|policy' }).Count -gt 0 -and "$(Get-CAInvProp $_ 'activityDisplayName')" -match '(?i)policy')
    })
    $cappedNote = if ($audits.Count -ge ($maxPages * 1000)) { " (page limit reached; possibly incomplete within the window)" } else { '' }

    New-CAInvRecord -Domain $domain -CheckId 'Evidence-03' -ObjectType 'AuditLog' `
        -Property 'caPolicyChanges' `
        -ObservedValue "$($caChanges.Count) CA-related policy change(s) in $window d (of $($audits.Count) policy audit rows)$cappedNote" `
        -Status 'Ready' -GraphSource $src `
        -Recommendation ('Check the CA change history against the change process; undocumented changes to the baseline are a governance risk.') | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($caChanges.Count) CA changes in audit log (window $window d)."
}
