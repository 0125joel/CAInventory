function Invoke-CAInvArmRequest {
    <#
    .SYNOPSIS
        Bounded GET to Azure Resource Manager, with client-side timeout and progress heartbeat.
    .DESCRIPTION
        ARM counterpart to Invoke-CAInvLogAnalyticsQuery: the same
        timeout+heartbeat+fallback guarantee (CLAUDE.md: "Every network call gets its own
        client-side timeout + heartbeat + fallback"), but for the GET-shaped ARM metadata calls in
        Resolve-CAInvLogWindow.ps1 (workspace properties, diagnostic settings) instead of a POST
        KQL query. Before this round those three calls had no client-side ceiling and no
        heartbeat — exactly the risk Invoke-CAInvLogAnalyticsQuery already covered on the KQL side,
        just without the corresponding fix here.

        Builds the GET request itself (Bearer auth, no body, no Prefer header — ARM metadata reads
        aren't asynchronous long-running queries) and then delegates to the same core as
        Invoke-CAInvLogAnalyticsQuery, Invoke-CAInvHttpWithTimeout. Two thin wrappers around one
        core instead of one more-generic function: "LogAnalyticsQuery" would mischaracterize an ARM
        GET, and a GET-only ARM call has no need for Prefer-wait semantics.

        On timeout or failure: returns Success=$false, does not itself call Write-CAInvLog WARN
        (the caller knows the context better), same pattern as Invoke-CAInvLogAnalyticsQuery.
    .PARAMETER Uri
        Full ARM URI including the api-version query string.
    .PARAMETER Token
        ARM access token (Bearer), already obtained by the caller.
    .PARAMETER Domain
        For the heartbeat/error log line.
    .PARAMETER TimeoutSeconds
        Client-side hard ceiling. ARM metadata reads are typically sub-second; the default is a
        generous, bounded ceiling for the case of a network interruption or throttling, not tuned
        to an expected long response time like the KQL side.
    .PARAMETER HeartbeatSeconds
        Interval at which a DEBUG heartbeat is logged while waiting.
    .OUTPUTS
        PSCustomObject @{ Success; Response (parsed JSON); ErrorMessage; TimedOut }
    .EXAMPLE
        $r = Invoke-CAInvArmRequest -Uri "https://management.azure.com/$wsId?api-version=2023-09-01" `
            -Token $token -Domain '6.25'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $Domain,

        [int] $TimeoutSeconds = 60,
        [int] $HeartbeatSeconds = 10
    )

    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Uri)
    $request.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Token)

    return Invoke-CAInvHttpWithTimeout -Request $request -TimeoutSeconds $TimeoutSeconds -HeartbeatSeconds $HeartbeatSeconds -Domain $Domain
}
