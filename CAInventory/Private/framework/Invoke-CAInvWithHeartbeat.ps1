function Invoke-CAInvWithHeartbeat {
    <#
    .SYNOPSIS
        Runs a scriptblock in a background thread job and logs a DEBUG heartbeat while it's
        running, so a slow-but-not-yet-failed call never reads as a silent hang (CLAUDE.md:
        "Every network call gets its own client-side timeout + heartbeat + fallback").
    .DESCRIPTION
        Invoke-CAInvHttpWithTimeout already does this for a raw HttpClient.SendAsync Task, which
        PowerShell can .Wait() on with a bounded timeout. Invoke-MgGraphRequest (the SDK cmdlet
        every Invoke-CAInvGraph call goes through) is synchronous — no Task to poll — so the only
        way to get a heartbeat around it is to run it somewhere else and poll THAT: a
        Start-ThreadJob (same process, separate thread), polled with Wait-Job -Timeout.

        Start-ThreadJob, not Start-Job: Start-Job spins up a whole separate PowerShell.exe process,
        which would NOT share the connected Microsoft.Graph session (its auth state lives in a
        process-wide static, not on disk) — the job would need to reconnect itself, which can
        trigger an interactive prompt on a background thread for -AuthMode Delegated, exactly the
        outcome this exists to avoid. Start-ThreadJob runs on a different thread of the SAME
        process, so it sees the same static state. Verified live 10-09-2026: Get-MgContext inside a
        Start-ThreadJob returned the full connected context (TenantId, Account, Scopes) even though
        -ContextScope was CurrentUser, not Process — Microsoft.Graph's auth state turned out to be
        visible process-wide regardless of that setting, at least on the SDK version tested
        (Microsoft.Graph.Authentication 2.38.0). -ArgumentList passes live object references
        (hashtables, etc.) directly, no remoting-style serialization, because the job shares the
        same memory space.

        No separate client-side timeout here: the SDK's own HttpClient.Timeout (5 minutes by
        default, session-wide via Connect-MgGraph -ClientTimeout) remains the actual ceiling. This
        function only adds visibility into the wait, it doesn't shorten it. A slow but visible call is fine, a silent one isn't.
    .PARAMETER ScriptBlock
        The call to run in the background thread job.
    .PARAMETER ArgumentList
        Arguments passed to ScriptBlock, same convention as Start-ThreadJob -ArgumentList.
    .PARAMETER HeartbeatSeconds
        Interval at which a DEBUG heartbeat is logged while waiting. Same default as
        Invoke-CAInvHttpWithTimeout's callers (Invoke-CAInvArmRequest, Invoke-CAInvLogAnalyticsQuery).
    .PARAMETER Domain
        For the heartbeat log line. Optional: Invoke-CAInvGraph is domain-agnostic (used by every
        collector), so most callers have nothing meaningful to pass here.
    .OUTPUTS
        Whatever ScriptBlock returns. An exception raised inside ScriptBlock is re-thrown here,
        exactly as if the call had been made synchronously in the caller's own scope — an
        enclosing try/catch (like Invoke-CAInvGraph's own retry loop) needs no changes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [scriptblock] $ScriptBlock,
        [object[]] $ArgumentList = @(),
        [int] $HeartbeatSeconds = 10,
        [string] $Domain
    )

    $job = Start-ThreadJob -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    try {
        $elapsed = 0
        while (-not (Wait-Job -Job $job -Timeout $HeartbeatSeconds)) {
            $elapsed += $HeartbeatSeconds
            Write-CAInvLog -Level 'DEBUG' -Domain $Domain -Message "Call still running... (${elapsed}s)."
        }
        return Receive-Job -Job $job -ErrorAction Stop
    }
    finally {
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}
