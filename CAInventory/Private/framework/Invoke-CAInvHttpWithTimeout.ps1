function Invoke-CAInvHttpWithTimeout {
    <#
    .SYNOPSIS
        Shared resilience core: sends a ready-made HTTP request with a client-side timeout and
        progress heartbeat (CLAUDE.md: "Every network call gets its own client-side timeout +
        heartbeat + fallback").
    .DESCRIPTION
        Extracted from Invoke-CAInvLogAnalyticsQuery: that function was written,
        tested, and elevated to a rule after a live-tenant incident (a bare
        Invoke-RestMethod to Log Analytics hung for 11+ minutes with no signal whatsoever) — but
        until this round had zero callers, while three ARM GETs in Resolve-CAInvLogWindow.ps1
        carried exactly the same risk with no ceiling. Those ARM calls are GETs with no body, the
        KQL call is a POST with a JSON body and a Prefer header; the only thing they share is the
        resilience core itself (timeout, heartbeat, AggregateException handling). This function is
        that core, made method- and body-independent by accepting a ready-made
        HttpRequestMessage instead of building one itself. Invoke-CAInvLogAnalyticsQuery and
        Invoke-CAInvArmRequest are the two thin wrappers around it; the internal logic below is
        deliberately carried over unchanged (same catch structure, same error text) so
        Invoke-CAInvLogAnalyticsQuery's behavior stays identical for its existing callers and
        tests.
    .PARAMETER Request
        Ready-made HttpRequestMessage (method, URI, headers, and body already set by the caller).
        This function takes ownership and disposes it.
    .PARAMETER TimeoutSeconds
        Client-side hard ceiling: the only real safety net if a server-side timeout, for whatever
        reason, doesn't arrive cleanly (e.g. a network interruption rather than a slow query).
    .PARAMETER HeartbeatSeconds
        Interval at which a DEBUG heartbeat is logged while waiting, so silence never again needs
        to be distinguished from a hang.
    .PARAMETER Domain
        For the heartbeat and (on a timeout) error log line.
    .OUTPUTS
        PSCustomObject @{ Success; Response (parsed JSON, or $null); ErrorMessage; TimedOut }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [System.Net.Http.HttpRequestMessage] $Request,
        [Parameter(Mandatory)] [int] $TimeoutSeconds,
        [Parameter(Mandatory)] [int] $HeartbeatSeconds,
        [Parameter(Mandatory)] [string] $Domain
    )

    $client = $null
    try {
        $client = [System.Net.Http.HttpClient]::new()
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)

        $task = $client.SendAsync($Request)
        $elapsed = 0
        while (-not $task.Wait([TimeSpan]::FromSeconds($HeartbeatSeconds))) {
            $elapsed += $HeartbeatSeconds
            Write-CAInvLog -Level 'DEBUG' -Domain $Domain -Message "HTTP call still running... (${elapsed}s, ceiling ${TimeoutSeconds}s)."
            if ($elapsed -ge $TimeoutSeconds) {
                return [PSCustomObject]@{ Success = $false; Response = $null; ErrorMessage = "Client-side timeout after ${TimeoutSeconds}s with no response."; TimedOut = $true }
            }
        }

        $httpResponse = $task.Result
        $responseBody = $httpResponse.Content.ReadAsStringAsync().Result

        if (-not $httpResponse.IsSuccessStatusCode) {
            return [PSCustomObject]@{
                Success = $false; Response = $null
                ErrorMessage = "HTTP $([int]$httpResponse.StatusCode) ($($httpResponse.StatusCode)): $responseBody"
                TimedOut = ($httpResponse.StatusCode -eq [System.Net.HttpStatusCode]::GatewayTimeout)
            }
        }

        $parsed = $responseBody | ConvertFrom-Json
        return [PSCustomObject]@{ Success = $true; Response = $parsed; ErrorMessage = $null; TimedOut = $false }
    }
    catch {

        $isTimeout = $false
        $ex = $_.Exception
        while ($ex) {
            if ($ex -is [System.Threading.Tasks.TaskCanceledException] -or $ex -is [System.OperationCanceledException]) {
                $isTimeout = $true
                break
            }
            if ($ex -is [System.AggregateException] -and $ex.InnerExceptions.Count -gt 0) {
                $ex = $ex.InnerExceptions[0]
                continue
            }
            $ex = $ex.InnerException
        }
        if ($isTimeout) {
            return [PSCustomObject]@{ Success = $false; Response = $null; ErrorMessage = "Timeout after ${TimeoutSeconds}s (client-side): $($_.Exception.Message)"; TimedOut = $true }
        }
        return [PSCustomObject]@{ Success = $false; Response = $null; ErrorMessage = $_.Exception.Message; TimedOut = $false }
    }
    finally {
        if ($Request) { $Request.Dispose() }
        if ($client) { $client.Dispose() }
    }
}
