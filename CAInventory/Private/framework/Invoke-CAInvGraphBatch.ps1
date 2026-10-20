function Invoke-CAInvGraphBatch {
    <#
    .SYNOPSIS
        Executes N GET requests via Microsoft Graph's /$batch endpoint.
    .DESCRIPTION
        Some Graph data exists only per object, with no collection query available. The clearest
        example is the legacy per-user MFA status
        (/beta/users/{id}/authentication/requirements): there is no
        /users?$select=perUserMfaState, so a tenant with 471 users requires 471 separate calls.
        Sequentially that's minutes of work; via /$batch (20 subrequests per call) it's 24.

        What this wrapper adds on top of a plain batch POST:

          1. **Per-subrequest throttling.** A batch call can succeed (HTTP 200) while individual
             subrequests return 429 or 503. Invoke-CAInvGraph's retry doesn't see those: it looks
             at the outer HTTP status. Without handling here, a truncated response would silently
             pass as "measured." Only the failed subrequests are retried, honoring the
             Retry-After per sub-response.
          2. **No silent zeros.** Every id comes back in the result hashtable, even when the call
             failed: Ok=$false with Status and Error. This lets the caller set 'Not assessed' per
             object instead of reading a missing measurement as absence (status model: a missing
             measurement is never the value 0).
          3. **Progress.** Every 10th batch gets an INFO line, so a long but legitimate sequence
             stays distinguishable in collector.log from a hang. Same pattern as the paging in
             Invoke-CAInvGraph.

        Graph's batch limit is 20 subrequests per call; -BatchSize is capped accordingly.
    .PARAMETER Request
        Objects with an Id property (a free-form key, returned in the result) and a Url property
        (the path relative to the API version, e.g.
        'users/<guid>/authentication/requirements').
    .PARAMETER ApiVersion
        v1.0 or beta. Applies to the batch call and therefore to all subrequests within it.
    .PARAMETER BatchSize
        Subrequests per batch call. Maximum 20 (Graph limit).
    .PARAMETER MaxRetries
        Number of extra rounds for subrequests that came back throttled.
    .OUTPUTS
        Hashtable: Id -> PSCustomObject @{ Ok; Status; Body; Error }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Request,
        [ValidateSet('v1.0', 'beta')][string] $ApiVersion = 'v1.0',
        [ValidateRange(1, 20)][int] $BatchSize = 20,
        [int] $MaxRetries = 5
    )

    $result = @{}
    $items = @($Request)
    if ($items.Count -eq 0) { return $result }

    $pending = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $items) { [void]$pending.Add($r) }

    $round = 0
    $batchNumber = 0

    while ($pending.Count -gt 0 -and $round -le $MaxRetries) {
        $round++
        $retryNext = [System.Collections.Generic.List[object]]::new()
        $retryAfterSeconds = 0

        for ($offset = 0; $offset -lt $pending.Count; $offset += $BatchSize) {
            $take = [Math]::Min($BatchSize, $pending.Count - $offset)
            $slice = $pending.GetRange($offset, $take)
            $batchNumber++

            $indexToItem = @{}
            $requests = @()
            for ($i = 0; $i -lt $slice.Count; $i++) {
                $key = [string]$i
                $indexToItem[$key] = $slice[$i]
                $requests += @{ id = $key; method = 'GET'; url = '/' + ([string]$slice[$i].Url).TrimStart('/') }
            }

            if ($batchNumber -eq 1 -or $batchNumber % 10 -eq 0) {
                Write-CAInvLog -Level 'INFO' -Message "Graph batch $batchNumber ($($slice.Count) subrequests, round $round) executed."
            }

            $resp = Invoke-CAInvGraph -Uri '$batch' -ApiVersion $ApiVersion -Method 'POST' -Body @{ requests = $requests }

            if ($resp.Failed) {
                foreach ($key in $indexToItem.Keys) {
                    $result[$indexToItem[$key].Id] = [PSCustomObject]@{
                        Ok = $false; Status = $resp.StatusCode; Body = $null
                        Error = "Batch-call faalde: $($resp.ErrorMessage)"
                    }
                }
                continue
            }

            $envelope = @($resp.Value) | Select-Object -First 1
            $responses = @(Get-CAInvProp $envelope 'responses' @())

            if ($responses.Count -eq 0) {
                foreach ($key in $indexToItem.Keys) {
                    $result[$indexToItem[$key].Id] = [PSCustomObject]@{
                        Ok = $false; Status = $null; Body = $null
                        Error = 'Batch response contained no responses array.'
                    }
                }
                continue
            }

            foreach ($sub in $responses) {
                $key = [string](Get-CAInvProp $sub 'id' '')
                if (-not $indexToItem.ContainsKey($key)) { continue }
                $item = $indexToItem[$key]
                $status = [int](Get-CAInvProp $sub 'status' 0)

                if ($status -ge 200 -and $status -lt 300) {
                    $result[$item.Id] = [PSCustomObject]@{
                        Ok = $true; Status = $status; Body = (Get-CAInvProp $sub 'body'); Error = $null
                    }
                    continue
                }

                if ($status -eq 429 -or $status -eq 503 -or $status -eq 504) {
                    [void]$retryNext.Add($item)
                    $ra = [int](Get-CAInvProp $sub 'headers.Retry-After' 0)
                    if ($ra -gt $retryAfterSeconds) { $retryAfterSeconds = $ra }
                    continue
                }

                $errText = [string](Get-CAInvProp $sub 'body.error.message' '')
                if ([string]::IsNullOrWhiteSpace($errText)) { $errText = "HTTP $status" }
                $result[$item.Id] = [PSCustomObject]@{
                    Ok = $false; Status = $status; Body = $null; Error = $errText
                }
            }

            foreach ($key in $indexToItem.Keys) {
                $item = $indexToItem[$key]
                if (-not $result.ContainsKey($item.Id) -and -not $retryNext.Contains($item)) {
                    $result[$item.Id] = [PSCustomObject]@{
                        Ok = $false; Status = $null; Body = $null
                        Error = 'No sub-response received for this request.'
                    }
                }
            }
        }

        $pending = $retryNext
        if ($pending.Count -gt 0) {
            if ($round -gt $MaxRetries) { break }
            $wait = if ($retryAfterSeconds -gt 0) { [Math]::Min($retryAfterSeconds, 60) } else { [Math]::Min([Math]::Pow(2, $round), 30) }
            Write-CAInvLog -Level 'WARN' -Message "Graph batch: $($pending.Count) subrequest(s) throttled; round $($round + 1) after ${wait}s."
            Start-Sleep -Seconds $wait
        }
    }

    foreach ($item in $pending) {
        if (-not $result.ContainsKey($item.Id)) {
            $result[$item.Id] = [PSCustomObject]@{
                Ok = $false; Status = 429; Body = $null
                Error = "Still throttled after $MaxRetries retry rounds."
            }
        }
    }

    return $result
}
