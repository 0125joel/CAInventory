function Get-CAInvInsightsReadiness {
    <#
    .SYNOPSIS
        Domain 6.25 — Insights and reporting readiness.
    .DESCRIPTION
        Layer 6 collector that runs BEFORE the two log functions and determines whether their
        result is meaningful. The diagnostic settings and the
        effective log window are already determined early in the run by Resolve-CAInvLogWindow
        (Evidence-04/Evidence-05); this collector doesn't duplicate that, it summarizes usability
        into the Evidence-06 record.

        Important: the Graph endpoints /auditLogs/signIns and /auditLogs/directoryAudits deliver
        ~30 days even without diagnostic settings. So a shorter-than-requested window doesn't make
        log checks unusable, just less far-reaching; this collector conveys that distinction.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.25'
    $src    = 'Derived: diagnostic settings + effective log window (Evidence-04/Evidence-05)'

    $ctx = $script:CAInvContext
    $desired = [int](Get-CAInvProp $ctx 'LookbackDays' 30)
    $effective = [int](Get-CAInvProp $ctx 'EffectiveLookbackDays' $desired)
    $azure = [bool](Get-CAInvProp $ctx 'Connections.Azure' $false)

    $usable = ($effective -ge $desired)

    $note = if (-not $azure) {
        "No Azure context: usage analysis relies on Graph retention (~$effective d). A longer window needs an Azure context (run without -SkipAzure, with Log Analytics Reader on the workspace)."
    } elseif ($effective -lt $desired) {
        "Effective window ($effective d) is shorter than desired ($desired d); log conclusions only apply within that window."
    } else {
        "Effective window $effective d; diagnostic settings support usage analysis over the desired range."
    }

    New-CAInvRecord -Domain $domain -CheckId 'Evidence-06' -ObjectType 'LogWindow' `
        -Property 'evidenceReadiness' -ObservedValue "effectiveWindow=$effective d; desired=$desired d; azureContext=$azure" `
        -Status ($(if ($effective -lt $desired) { 'Review required' } else { 'Ready' })) `
        -ManualReview:($effective -lt $desired) -ApiVersion 'n/a' -GraphSource $src -Recommendation $note | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Evidence readiness: window $effective d (usable for desired range=$usable)."
}
