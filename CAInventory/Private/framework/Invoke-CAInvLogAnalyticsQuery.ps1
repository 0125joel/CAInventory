function Invoke-CAInvLogAnalyticsQuery {
    <#
    .SYNOPSIS
        Bounded, asynchronous Log Analytics KQL query with a progress heartbeat.
    .DESCRIPTION
        Live-tenant analysis (2026-08-20, wentzo) showed that a bare `Invoke-RestMethod` call to
        the Log Analytics query API can hang for 11+ minutes with no response, error, or any
        intermediate signal — the call had no client-side timeout of its own and no
        `Prefer: wait=` header, so no safety net regardless of the cause (a heavy query, or a
        local network hiccup as had already happened once that same day). Microsoft's own
        documentation confirms a server-side default timeout of 3 minutes, extendable up to 10
        minutes via `Prefer: wait=`; a 504 should come back when that's exceeded.

        This function wraps the call in .NET's async HttpClient (built in, no new module
        dependency — `Start-ThreadJob` is only built in from PS 7.4 onward, this project requires
        PS 7.2) with an explicit `Prefer: wait=` header AND a client-side `HttpClient.Timeout` as
        a hard ceiling. While waiting, a DEBUG line is logged every `HeartbeatSeconds`
        ("still running...") so silence never again needs to be distinguished from a hang.
        Microsoft's Log Analytics query API offers no progress percentage for a single ad-hoc
        query (that only exists for asynchronous export jobs) — so this is a liveness heartbeat,
        not a "% done".

        On timeout or failure: returns Success=$false, does NOT itself call Write-CAInvLog WARN
        (the caller knows the context — which query, which purpose — better and logs its own
        specific WARN), so this generic helper stays reusable for every KQL caller in this module.

        Thin wrapper: builds the POST KQL request (URI, body, Prefer header,
        Bearer auth) and delegates the timeout/heartbeat/fallback handling itself to the shared
        core Invoke-CAInvHttpWithTimeout — see that function for the ARM-GET counterpart
        (Invoke-CAInvArmRequest) and the reason those are two thin wrappers around one core rather
        than one more-generic function: the name "LogAnalyticsQuery" would mischaracterize an ARM
        metadata GET.
    .OUTPUTS
        PSCustomObject @{ Success; Response; ErrorMessage; TimedOut }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string] $CustomerId,
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $Kql,
        [Parameter(Mandatory)] [string] $Domain,

        [int] $PreferWaitSeconds = 120,

        [int] $TimeoutSeconds = 150,

        [int] $HeartbeatSeconds = 10,

        [string] $BaseUri = 'https://api.loganalytics.io/v1/workspaces'
    )

    $uri = "$BaseUri/$CustomerId/query"
    $body = @{ query = $Kql } | ConvertTo-Json -Depth 3

    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $uri)
    $request.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Token)
    $request.Headers.TryAddWithoutValidation('Prefer', "wait=$PreferWaitSeconds") | Out-Null
    $request.Content = [System.Net.Http.StringContent]::new($body, [System.Text.Encoding]::UTF8, 'application/json')

    return Invoke-CAInvHttpWithTimeout -Request $request -TimeoutSeconds $TimeoutSeconds -HeartbeatSeconds $HeartbeatSeconds -Domain $Domain
}
