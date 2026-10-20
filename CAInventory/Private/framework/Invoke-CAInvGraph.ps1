function Invoke-CAInvGraph {
    <#
    .SYNOPSIS
        Mandatory wrapper for every Microsoft Graph read operation in CAInventory.
    .DESCRIPTION
        Delivers the non-negotiable requirements:
          - Paging: follows @odata.nextLink to exhaustion.
          - Throttling: 429/503 retry honoring the Retry-After header and exponential backoff.
          - Caching: identical GET requests within a run are cached.
          - ApiVersion: v1.0 or beta is recorded and returned, so beta provenance stays visible
            in the output.
          - Fails soft: on a permission/endpoint error, the run isn't aborted — instead a result
            with .Failed = $true is returned so the collector can set 'Not assessed'.
          - API drift log: every NEW call (not a cache hit) is recorded in $ctx.GraphCallLog
            (Uri, ApiVersion, Failed, StatusCode, ErrorMessage). This feeds New-CAInvApiDriftReport
            (architecture proposal Phase A): surfacing WHICH endpoints are beta and WHICH calls
            failed, before that becomes a deprecation in production. Cache hits don't log again;
            the first (real) attempt is representative.
          - Page progress: logs INFO at page 1 and every 10th page after, so a long but
            legitimately ongoing paging run (up to -MaxPages pages) stays distinguishable in
            collector.log from an actual hang — previously a normal paging run was completely
            silent (only throttling/MaxPages being exceeded logged anything).
          - Capped: the result now carries its own Capped boolean (true when -MaxPages is
            reached), so callers no longer need to recompute this themselves from Value.Count.
          - POST only for /$batch: N GET subrequests in a single HTTP call, needed for per-object
            endpoints with no collection query (such as
            /users/{id}/authentication/requirements). Any other POST target is hard-rejected, so
            the module's read-only guarantee doesn't depend on caller discipline. See
            Invoke-CAInvGraphBatch for the usable wrapper around this.
          - Heartbeat (-Heartbeat, opt-in, off by default): routes the actual Invoke-MgGraphRequest
            call through Invoke-CAInvWithHeartbeat (10-09-2026, live-tenant incident) instead of
            calling it directly, so a slow single page logs DEBUG progress every 10s instead of
            sitting silent for up to the SDK's own 5-minute HttpClient.Timeout. Deliberately NOT the
            default for the other 79+ callers: Invoke-CAInvWithHeartbeat runs the actual call in a
            Start-ThreadJob, and while the connected Graph session survives that boundary fine (see
            Invoke-CAInvWithHeartbeat), a Pester mock of Invoke-MgGraphRequest does NOT — it's
            defined in the parent runspace/module scope, which a freshly spawned thread job doesn't
            inherit. Turning heartbeat on unconditionally broke 12 of this function's own 14 tests
            (the real, unmocked cmdlet ran inside the job and failed with "Authentication needed"),
            and would have broken the same pattern across most of the test suite. Pass -Heartbeat
            only from a caller that has already identified its own call as genuinely at risk (see
            Get-CAInvSignInData) — callers that don't pass it keep the original direct,
            fully-mockable code path, unchanged.
        Uses Invoke-MgGraphRequest (Microsoft.Graph) under the hood.
    .PARAMETER Heartbeat
        Opt-in: logs DEBUG progress every 10s while this call is in flight (see .DESCRIPTION).
        Off by default; existing callers and their tests are unaffected.
    .OUTPUTS
        PSCustomObject: @{ Value; ApiVersion; Uri; Failed; ErrorMessage; StatusCode; FromCache; Capped }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string] $Uri,

        [ValidateSet('v1.0', 'beta')]
        [string] $ApiVersion = 'v1.0',

        [ValidateSet('GET', 'POST')]
        [string] $Method = 'GET',

        [hashtable] $Body,

        [hashtable] $Headers,

        [switch] $NoCache,

        [int] $MaxRetries = 8,

        [int] $MaxPages = 0,

        [switch] $Heartbeat
    )

    $ctx = $script:CAInvContext

    if ($Method -eq 'POST' -and $Uri.TrimStart('/') -ne '$batch') {
        throw "Invoke-CAInvGraph: POST is only allowed for `$batch (requested: '$Uri'). CAInventory is read-only."
    }

    if ($Uri -match '^https?://') {
        $fullUri = $Uri
    }
    else {
        $graphHost = if ($ctx -and $ctx.GraphBaseUri) { $ctx.GraphBaseUri } else { 'https://graph.microsoft.com' }
        $fullUri = "$graphHost/$ApiVersion/" + $Uri.TrimStart('/')
    }

    $cacheable = (-not $NoCache -and $Method -eq 'GET')
    $cacheKey = "$Method|$fullUri"
    if ($cacheable -and $ctx -and $ctx.GraphCache -and $ctx.GraphCache.ContainsKey($cacheKey)) {

        $cached = $ctx.GraphCache[$cacheKey]
        $cachedCapped = if ($cached.PSObject.Properties['Capped']) { $cached.Capped } else { $false }
        return [PSCustomObject]@{
            Value = $cached.Value; ApiVersion = $cached.ApiVersion; Uri = $cached.Uri
            Failed = $cached.Failed; ErrorMessage = $cached.ErrorMessage; StatusCode = $cached.StatusCode; FromCache = $true; Capped = $cachedCapped
        }
    }

    $all = [System.Collections.Generic.List[object]]::new()
    $next = $fullUri
    $page = 0

    while ($next) {
        $page++
        if ($MaxPages -gt 0 -and $page -gt $MaxPages) {
            Write-CAInvLog -Level 'WARN' -Message "Page limit ($MaxPages) reached for $fullUri; result may be incomplete."
            break
        }

        $attempt = 0
        $response = $null

        while ($true) {
            $attempt++
            try {
                if ($Heartbeat) {
                    if ($Method -eq 'POST') {
                        $json = $Body | ConvertTo-Json -Depth 10 -Compress
                        $response = Invoke-CAInvWithHeartbeat -ArgumentList @($Method, $next, $json, $Headers) -ScriptBlock {
                            param($Method, $Uri, $Body, $Headers)
                            Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $Body -ContentType 'application/json' -Headers $Headers -OutputType PSObject -ErrorAction Stop
                        }
                    }
                    else {
                        $response = Invoke-CAInvWithHeartbeat -ArgumentList @($Method, $next, $Headers) -ScriptBlock {
                            param($Method, $Uri, $Headers)
                            Invoke-MgGraphRequest -Method $Method -Uri $Uri -Headers $Headers -OutputType PSObject -ErrorAction Stop
                        }
                    }
                }
                elseif ($Method -eq 'POST') {
                    $json = $Body | ConvertTo-Json -Depth 10 -Compress
                    $response = Invoke-MgGraphRequest -Method $Method -Uri $next -Body $json -ContentType 'application/json' -Headers $Headers -OutputType PSObject -ErrorAction Stop
                }
                else {
                    $response = Invoke-MgGraphRequest -Method $Method -Uri $next -Headers $Headers -OutputType PSObject -ErrorAction Stop
                }
                break
            }
            catch {
                $status = $null
                try { $status = [int]$_.Exception.Response.StatusCode } catch { $status = $null }

                $isThrottle = ($status -eq 429 -or $status -eq 503 -or $status -eq 504)
                if (-not $isThrottle -and -not $status) {
                    $msgText = "$($_.Exception.Message)"
                    $isThrottle = ($msgText -match '(?i)too many retries|TooManyRequests|\b429\b|\b503\b|\b504\b')
                }
                if ($isThrottle -and $attempt -le $MaxRetries) {
                    $retryAfter = 0
                    try {
                        $ra = $_.Exception.Response.Headers.RetryAfter
                        if ($ra -and $ra.Delta) { $retryAfter = [int]$ra.Delta.Value.TotalSeconds }
                    } catch { $retryAfter = 0 }
                    if ($retryAfter -le 0) {

                        $base = [Math]::Min([Math]::Pow(2, $attempt), 60)
                        $retryAfter = [Math]::Max(5, [Math]::Min([Math]::Round($base * (0.8 + (Get-Random -Minimum 0 -Maximum 40) / 100)), 60))
                    }

                    Write-CAInvLog -Level 'WARN' -Message "Throttled ($(if ($status) { $status } else { 'SDK retry exhausted' })) on $next; retry $attempt/$MaxRetries after ${retryAfter}s."
                    Start-Sleep -Seconds $retryAfter
                    continue
                }

                $msg = $_.Exception.Message

                $graphErrorBody = $null
                try {
                    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $graphErrorBody = $_.ErrorDetails.Message }
                } catch { $graphErrorBody = $null }
                $logMsg = "Graph call failed ($status) for $next : $msg"
                if ($graphErrorBody -and $graphErrorBody -ne $msg) { $logMsg += " | Graph error detail: $graphErrorBody" }
                Write-CAInvLog -Level 'WARN' -Message $logMsg
                $failResult = [PSCustomObject]@{
                    Value = $null; ApiVersion = $ApiVersion; Uri = $fullUri
                    Failed = $true; ErrorMessage = $msg; StatusCode = $status; FromCache = $false; Capped = $false
                }

                $isDeterministic = ($null -ne $status -and $status -ge 400 -and $status -lt 500 -and $status -ne 429)
                if ($cacheable -and $isDeterministic -and $ctx -and $ctx.GraphCache) {
                    $ctx.GraphCache[$cacheKey] = $failResult
                }
                Add-CAInvGraphCallLog -Uri $fullUri -ApiVersion $ApiVersion -Failed $true -StatusCode $status -ErrorMessage $msg
                return $failResult
            }
        }

        if ($null -ne $response -and ($response.PSObject.Properties.Name -contains 'value')) {
            foreach ($item in $response.value) { [void]$all.Add($item) }
            $next = $null
            if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
                $next = $response.'@odata.nextLink'
            }
        }
        else {
            [void]$all.Add($response)
            $next = $null
        }

        if ($next -and ($page -eq 1 -or $page % 10 -eq 0)) {
            Write-CAInvLog -Level 'INFO' -Message "Page $page fetched for $fullUri (total so far: $($all.Count) items)."
        }
    }

    $capped = ($MaxPages -gt 0 -and $page -gt $MaxPages)

    if (-not $capped -and $page -gt 1) {
        Write-CAInvLog -Level 'DEBUG' -Message "Paging completed for ${fullUri}: ${page} page(s), $($all.Count) items total."
    }

    $okResult = [PSCustomObject]@{
        Value = $all.ToArray(); ApiVersion = $ApiVersion; Uri = $fullUri
        Failed = $false; ErrorMessage = $null; StatusCode = 200; FromCache = $false; Capped = $capped
    }

    if ($cacheable -and $ctx -and $ctx.GraphCache) {
        $ctx.GraphCache[$cacheKey] = $okResult
    }

    Add-CAInvGraphCallLog -Uri $fullUri -ApiVersion $ApiVersion -Failed $false -StatusCode 200 -ErrorMessage $null
    return $okResult
}

function Add-CAInvGraphCallLog {
    <#
    .SYNOPSIS
        Records one Graph call in $ctx.GraphCallLog for the API drift report.
    .DESCRIPTION
        Internal helper for Invoke-CAInvGraph. Always fails soft itself (no context, no list): a
        logging problem here must never affect the collection.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $ApiVersion,
        [Parameter(Mandatory)] [bool] $Failed,
        [AllowNull()] $StatusCode,
        [AllowNull()] [string] $ErrorMessage
    )

    $ctx = $script:CAInvContext
    if (-not $ctx) { return }

    $logProp = $ctx.PSObject.Properties['GraphCallLog']
    if (-not $logProp -or $null -eq $logProp.Value) {
        Add-CAInvContextData -Context $ctx -Name 'GraphCallLog' -Value ([System.Collections.Generic.List[object]]::new()) -AllowOverwrite
        $logProp = $ctx.PSObject.Properties['GraphCallLog']
    }

    [void]$logProp.Value.Add([PSCustomObject]@{
        Uri          = $Uri
        ApiVersion   = $ApiVersion
        Failed       = $Failed
        StatusCode   = $StatusCode
        ErrorMessage = $ErrorMessage
        Timestamp    = [DateTimeOffset]::UtcNow.ToString('o')
    })
}
