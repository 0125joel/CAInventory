function Get-CAInvSignInData {
    <#
    .SYNOPSIS
        Fetches the sign-in logs ONCE within the effective window and caches them for the run.
    .DESCRIPTION
        Shared source for every function that needs sign-ins: the legacy auth usage check (layer
        3, 6.16), the sign-in log summary (layer 6, 6.23), and the method matrix (6.23 axis).
        Without this centralization, every consumer would query /auditLogs/signIns separately; on
        large tenants that's an expensive, slow call and duplicated work.

        Performance and robustness measures (learned from real runs):
          1. A lean $select. Without $select, /auditLogs/signIns returns the full sign-in object
             (location, device, network, per-CA detail): dozens of fields per row, which pushes a
             single page past the 300s HttpClient timeout on a busy tenant.
          2. Only universally selectable fields. signIn's 'detail' properties
             (authenticationDetails, networkLocationDetails, authenticationProcessingDetails) are
             NOT supported in $select by /auditLogs/signIns and produce a 400 BadRequest. They are
             therefore deliberately NOT in the core select. Consequence: clientAppUsed, status, and
             appliedConditionalAccessPolicies (legacy auth + summary) are measured quickly and
             reliably; the matrix's per-method usage axis requires authenticationDetails and can't
             be reliably obtained via this source. HasAuthDetails explicitly indicates that, so the
              matrix sets the usage columns to Not assessed instead of a misleading zero.
          3. Caching on the context object (SignInData): the first call measures, every subsequent
             call reuses the result — even on a failure, so a slow/failed query is never attempted
             twice.

        The evidence (Write-CAInvRaw) is written HERE, at the point of the actual
        fetch, not by a consumer. Only Get-CAInvSignInLog.ps1 (Evidence-01,
        layer 6) did that — with the result that a run that skipped layer 6 (e.g. -Layer
        Application, which already supplies Condition-09 with this data via
        Get-CAInvLegacyAuthUsage) left a verdict on sign-in data without ever writing evidence for
        it. Now the evidence is created unconditionally at the fetch itself, regardless of which
        layer asks for the data first, and the RawPath is included in the result so every consumer
        (Evidence-01, Condition-09, the method matrix) can point its own record to it without
        writing the data again — at tens of thousands of sign-ins, that's a real cost (see the
        batching-behavior note on Write-CAInvRaw).

        Reliably measuring per-method usage requires Entra diagnostic settings to Log Analytics and
        a KQL query over SignInLogs; that's a documented follow-up point, not something achievable via the Graph sign-in API.

        Fetched in 7-day slices, not as one $filter spanning the whole window (live-tenant
        incident 10-09-2026: a single 90-day query against a busy tenant hung for the full 300s
        HttpClient timeout with no server response at all — not a 429/503, so the existing
        throttle-retry in Invoke-CAInvGraph never got a chance to run — and took Condition-09,
        Evidence-01 and Evidence-02 down with it, since all three read this same cached result.
        Seven days keeps a single slice's own volume small enough that a busy tenant's week is
        unlikely to itself take 5 minutes, without multiplying the call count unreasonably (a
        90-day window is at most 13 calls, not 90).

        Slices are walked newest-first (now backward to the requested window start), not
        oldest-first, and stop after two consecutive empty slices: that run's diagnostic settings had only existed
        since the preceding Saturday, so /auditLogs/signIns came back empty for the oldest ~11 of
        13 weekly slices and only had real (and, near the present, heavy) volume in the last two —
        11 round-trips that confirmed nothing, spent walking oldest-first before ever reaching the
        data that mattered. Walking backward means the two slices needed to detect "nothing here"
        are the CHEAPEST to confirm (empty responses return fast) and sit next to whatever recent
        activity exists, so the scan naturally reaches the busy, recent end first and skips the
        historical tail once two slices in a row confirm it's quiet. The returned Window field
        reflects what was actually walked, not the originally requested number of days: if the
        scan stops early, Window is the distance back to the oldest slice actually queried (which
        still includes its own two empty confirmations), so every consumer's "window of N days"
        text stays honest about what was measured versus inferred-quiet. A single busy slice can
        still take the full 300s if it doesn't happen to be adjacent to two empty ones. That is
        acceptable as long as the wait is visible; the very first slice hit the timeout with nothing
        to skip ahead of it. That's why every call here passes -Heartbeat to Invoke-CAInvGraph: a
        DEBUG progress line every 10s instead of up to 5 minutes of silence. See
        Invoke-CAInvWithHeartbeat for why that's an opt-in switch and not Invoke-CAInvGraph's
        default (a Start-ThreadJob boundary that Pester mocks don't cross).

        All-or-nothing on an actual FAILURE, same as before chunking: the first slice that fails
        aborts the whole fetch immediately (no point spending more calls on data that a
        partial-window contract would need Not assessed anyway), so a consumer's Failed check
        keeps meaning exactly what it always meant. Smaller slices lower the ODDS of hitting that
        failure; they don't change what a failure means, and the empty-slice early-stop is
        unrelated to it (an empty slice is a successful, zero-result response, not a failure).
        Each slice logs its own progress line, so a long fetch is visibly incremental instead of
        silent.
    .OUTPUTS
        PSCustomObject: @{ Attempted; Failed; ErrorMessage; SignIns (array); Window (int, actually
        queried days — see .DESCRIPTION); Capped (bool); HasAuthDetails (bool); RawPath (string) }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $ctx = $script:CAInvContext

    if ($ctx -and $ctx.PSObject.Properties['SignInData'] -and $ctx.SignInData) {
        return $ctx.SignInData
    }

    $window = Get-CAInvEffectiveLookbackWindow
    $now = [DateTimeOffset]::UtcNow
    $windowStart = $now.AddDays(-$window)

    $maxPages = 100
    $chunkDays = 7

    $select = 'id,createdDateTime,userPrincipalName,userId,appId,appDisplayName,clientAppUsed,conditionalAccessStatus,status,appliedConditionalAccessPolicies'

    $chunks = [System.Collections.Generic.List[object]]::new()
    $cursor = $now
    while ($cursor -gt $windowStart) {
        $chunkStart = $cursor.AddDays(-$chunkDays)
        if ($chunkStart -lt $windowStart) { $chunkStart = $windowStart }
        [void]$chunks.Add([PSCustomObject]@{ Start = $chunkStart; End = $cursor })
        $cursor = $chunkStart
    }

    $allSignIns = [System.Collections.Generic.List[object]]::new()
    $failed = $false
    $failureMessage = $null
    $cappedAny = $false
    $consecutiveEmpty = 0
    $oldestQueriedStart = $now

    for ($i = 0; $i -lt $chunks.Count; $i++) {
        $chunk = $chunks[$i]
        $startStr = $chunk.Start.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $endStr = $chunk.End.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $uri = "auditLogs/signIns?`$filter=createdDateTime ge $startStr and createdDateTime lt $endStr&`$select=$select&`$top=1000"

        $resp = Invoke-CAInvGraph -Uri $uri -ApiVersion 'v1.0' -MaxPages $maxPages -Heartbeat `
            -Headers @{ 'Prefer' = 'include-unknown-enum-members' }

        if ($resp.Failed) {
            $failed = $true
            $failureMessage = "Window slice $startStr to $endStr failed: $($resp.ErrorMessage)"
            break
        }

        $oldestQueriedStart = $chunk.Start
        foreach ($item in $resp.Value) { [void]$allSignIns.Add($item) }
        if ($resp.Capped) { $cappedAny = $true }
        Write-CAInvLog -Level 'INFO' -Domain '6.23' -Message "Sign-in window slice $($i + 1)/$($chunks.Count) ($startStr to $endStr): $($resp.Value.Count) sign-in(s)."

        if ($resp.Value.Count -eq 0) {
            $consecutiveEmpty++
            if ($consecutiveEmpty -ge 2) {
                $remaining = $chunks.Count - $i - 1
                if ($remaining -gt 0) {
                    Write-CAInvLog -Level 'INFO' -Domain '6.23' -Message "Two consecutive empty slices; treating the remaining $remaining older slice(s) (older than $startStr) as quiet without querying them."
                }
                break
            }
        }
        else {
            $consecutiveEmpty = 0
        }
    }

    if ($failed) {
        $result = [PSCustomObject]@{
            Attempted = $true; Failed = $true; ErrorMessage = $failureMessage
            SignIns = @(); Window = $window; Capped = $false; HasAuthDetails = $false; RawPath = $null
        }
    }
    else {
        $signIns = @($allSignIns)
        $actualWindowDays = [Math]::Max(1, [int][Math]::Ceiling(($now - $oldestQueriedStart).TotalDays))

        $rawPath = Write-CAInvRaw -Domain '6.23' -Endpoint 'signIns' -Data $signIns
        $result = [PSCustomObject]@{
            Attempted = $true; Failed = $false; ErrorMessage = $null
            SignIns = $signIns; Window = $actualWindowDays
            Capped = $cappedAny; HasAuthDetails = $false; RawPath = $rawPath
        }
    }

    if ($ctx) {
        Add-CAInvContextData -Context $ctx -Name 'SignInData' -Value $result -AllowOverwrite

        if (-not $result.Failed) { Add-CAInvContextData -Context $ctx -Name 'SignIns' -Value $result.SignIns -AllowOverwrite }
    }

    return $result
}
