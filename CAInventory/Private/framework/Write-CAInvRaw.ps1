function Write-CAInvRaw {
    <#
    .SYNOPSIS
        Preserves the raw Graph response as evidence under /raw/{domain}/{endpoint}.json.
    .DESCRIPTION
        Stores the unprocessed data unchanged (including unknown properties/@odata.type),
        computes a SHA256 hash for reference/comparison, and returns the relative path so the
        normalized record can reference it via RawPath.
        Large arrays (e.g. tens of thousands of sign-ins) are serialized in batches of
        $BatchSize and written directly to a StreamWriter instead of a single ConvertTo-Json
        call that first builds the whole array into one string in memory — the latter turned out
        to be unnecessarily memory- and time-intensive on a busy tenant (live-tenant run wentzo,
        2026-08-20, 28,232 sign-ins -> 256 MB). -Depth 10 is well above the empirically measured
        nesting depth of sign-in objects (4, measured over a sample of that same run) versus the
        original -Depth 30. A singular (non-array) $Data is still written unwrapped, exactly as
        before.

        $BatchSize stays at 500. Investigated on 26-08-2026 whether larger is faster: on
        SYNTHETIC objects, 500 -> 2000 seemed to make a factor-3 difference, but on the real
        42,456 sign-ins from run 20260826-075950 that difference disappears entirely into the
        noise (four measurements per value, median 4.2s at 500 versus 4.3s at 2000). The output
        is byte-identical for every batch size, so there's nothing to gain and nothing to lose:
        don't investigate again without a new reason.
    .OUTPUTS
        String: the path to the raw file written (or $null if there is no context).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Domain,

        [Parameter(Mandatory)]
        [string] $Endpoint,

        [Parameter(Mandatory)]
        [AllowNull()]
        $Data,

        [int] $BatchSize = 500,

        [int] $JsonDepth = 10,

        [double] $SlowThresholdSeconds = 5
    )

    $ctx = $script:CAInvContext
    $rawDir = $null
    if ($ctx) {
        $pathsProp = $ctx.PSObject.Properties['Paths']
        if ($pathsProp -and $pathsProp.Value -is [System.Collections.IDictionary] -and $pathsProp.Value.Contains('Raw')) {
            $rawDir = $pathsProp.Value['Raw']
        }
    }
    if (-not $rawDir) {
        return $null
    }

    $safeEndpoint = ($Endpoint -replace '[^\w\.\-]', '_').Trim('_')
    if ([string]::IsNullOrWhiteSpace($safeEndpoint)) { $safeEndpoint = 'endpoint' }

    $domainDir = Join-Path $rawDir ($Domain -replace '[^\w\.\-]', '_')
    if (-not (Test-Path -LiteralPath $domainDir)) {
        New-Item -ItemType Directory -Path $domainDir -Force | Out-Null
    }

    $filePath = Join-Path $domainDir "$safeEndpoint.json"

    $resolvedFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($filePath)

    $isCollection = ($null -ne $Data) -and ($Data -is [System.Array] -or ($Data -is [System.Collections.IEnumerable] -and $Data -isnot [string] -and $Data -isnot [System.Collections.IDictionary]))

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $itemCount = 0
    $writer = $null

    try {

        $noBomUtf8 = [System.Text.UTF8Encoding]::new($false)
        $writer = [System.IO.StreamWriter]::new($resolvedFilePath, $false, $noBomUtf8)

        if (-not $isCollection) {
            $itemCount = if ($null -eq $Data) { 0 } else { 1 }
            $writer.Write(($Data | ConvertTo-Json -Depth $JsonDepth -Compress -WarningAction SilentlyContinue))
        }
        else {
            $items = @($Data)
            $itemCount = $items.Count

            if ($itemCount -eq 0) {
                $writer.Write('[]')
            }
            else {
                $writer.Write('[')
                $first = $true
                for ($i = 0; $i -lt $itemCount; $i += $BatchSize) {
                    $end = [Math]::Min($i + $BatchSize - 1, $itemCount - 1)
                    $batch = $items[$i..$end]
                    $batchJson = $batch | ConvertTo-Json -Depth $JsonDepth -Compress -AsArray -WarningAction SilentlyContinue

                    $inner = $batchJson.Substring(1, $batchJson.Length - 2)
                    if (-not $first) { $writer.Write(',') }
                    $writer.Write($inner)
                    $first = $false
                }
                $writer.Write(']')
            }
        }

        $writer.Flush()
        $writer.Dispose()
        $writer = $null
    }
    catch {
        if ($writer) {
            try { $writer.Dispose() } catch { Write-CAInvLog -Level 'DEBUG' -Domain $Domain -Message "Writer dispose after error failed for $filePath." }
            $writer = $null
        }
        $errObj = [PSCustomObject]@{ _error = "ConvertTo-Json faalde: $($_.Exception.Message)" }
        Set-Content -LiteralPath $filePath -Value ($errObj | ConvertTo-Json -Depth 3) -Encoding utf8
    }
    finally {
        if ($writer) {
            try { $writer.Dispose() } catch { Write-CAInvLog -Level 'DEBUG' -Domain $Domain -Message "Writer dispose failed for $filePath." }
        }
    }

    $sw.Stop()
    $elapsedSeconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    Write-CAInvLog -Level 'INFO' -Domain $Domain -Message "Raw evidence written: $Domain/$safeEndpoint.json ($itemCount items, ${elapsedSeconds}s)."
    if ($sw.Elapsed.TotalSeconds -ge $SlowThresholdSeconds) {
        Write-CAInvLog -Level 'WARN' -Domain $Domain -Message "Raw evidence write for $safeEndpoint took ${elapsedSeconds}s ($itemCount items) — possibly a large payload."
    }

    try {
        $hash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash
        Set-Content -LiteralPath "$filePath.sha256" -Value $hash -Encoding ascii
    }
    catch {
        Write-CAInvLog -Level 'DEBUG' -Domain $Domain -Message "Hash calculation failed for $filePath."
    }

    return $filePath
}
