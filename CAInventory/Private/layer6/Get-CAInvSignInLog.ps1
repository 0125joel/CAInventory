function Get-CAInvSignInLog {
    <#
    .SYNOPSIS
        Domain 6.23 — Sign-in logs.
    .DESCRIPTION
        Layer 6 collector. Reads /auditLogs/signIns within the effective log window and summarizes
        the observations: total, failed sign-ins, and sign-ins with a CA policy applied. The raw
        sign-ins are kept on the context object (SignIns) so the method matrix (6.23 axis) and the
        legacy auth usage check (6.16) can reuse them without reading again.

        To keep the run manageable on large tenants, the window is passed as a $filter and the page
        count is capped; when capped, that's stated explicitly in the record.

        For reference: `/auditLogs/signIns` returns ONLY interactive sign-ins by default (Microsoft
        Learn: "Only interactive sign-ins are returned... unless you set an explicit filter on the
        signInEventType property"). So what this collector measures here is by definition the
        interactive traffic, and that's exactly the intent.

        This collector measures only the INTERACTIVE sign-ins. The separate summary of
        non-interactive sign-ins (SIL-002) was removed on 21-08-2026; see the note by the code.
        Non-interactive traffic remains available via Log Analytics for the checks that do build a
        verdict on it (legacy auth drilldown 6.16, method matrix usage axis).
    #>
    [CmdletBinding()]
    param()

    $domain = '6.23'
    $src    = 'GET /auditLogs/signIns'

    $data = Get-CAInvSignInData
    $window = $data.Window
    if ($data.Failed) {
        New-CAInvRecord -Domain $domain -CheckId 'Evidence-01' -ObjectType 'SignIn' `
            -Property 'signIns' -Status 'Not assessed' `
            -NotAssessedReason ('Could not read /auditLogs/signIns: {0}' -f @($data.ErrorMessage)) `
            -GraphSource $src | Out-Null
        return
    }

    $signIns = @($data.SignIns)

    $ciStatuses = @('success', 'failure')
    $swSummary = [System.Diagnostics.Stopwatch]::StartNew()
    $failed = 0
    $caApplied = 0
    foreach ($si in $signIns) {
        if ((Get-CAInvProp $si 'status.errorCode' 0) -ne 0) { $failed++ }
        foreach ($p in @(Get-CAInvProp $si 'appliedConditionalAccessPolicies' @())) {
            if ((Get-CAInvProp $p 'result' '') -in $ciStatuses) { $caApplied++; break }
        }
    }
    $swSummary.Stop()
    Write-CAInvLog -Level 'DEBUG' -Domain $domain -Message "Sign-in summary computed: $($signIns.Count) items, $([Math]::Round($swSummary.Elapsed.TotalSeconds, 1))s."
    if ($swSummary.Elapsed.TotalSeconds -ge 5) {
        Write-CAInvLog -Level 'WARN' -Domain $domain -Message "Sign-in summary took $([Math]::Round($swSummary.Elapsed.TotalSeconds, 1))s for $($signIns.Count) items — possibly a large payload."
    }
    $cappedNote = if ($data.Capped) { " (page limit reached; possibly incomplete within the window)" } else { '' }

    New-CAInvRecord -Domain $domain -CheckId 'Evidence-01' -ObjectType 'SignIn' `
        -Property 'signInSummary' `
        -ObservedValue "$($signIns.Count) sign-ins in $window d; failed=$failed; withCaApplied=$caApplied$cappedNote" `
        -Status 'Ready' -GraphSource $src -RawPath $data.RawPath `
        -Recommendation ('Sign-in data available for usage analysis (method matrix, legacy auth). Not measured within the window is not evidence of non-use.') | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($signIns.Count) sign-ins read (window $window d)."

}
