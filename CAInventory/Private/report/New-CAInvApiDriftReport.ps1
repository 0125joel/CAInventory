function New-CAInvApiDriftReport {
    <#
    .SYNOPSIS
        Report C — API drift report (architecture proposal Phase A).
    .DESCRIPTION
        Aggregates $ctx.GraphCallLog (populated by Invoke-CAInvGraph, every NON-cached call) into a
        compact overview: which endpoints ran on beta, and which calls failed and with which status
        code. Goal: make a Graph/beta break or a badly composed query (like the 400 on a
        non-selectable property, or a 300s timeout from an overly broad response) visible as a run
        artifact, instead of only discovering it once a collector silently returns 'Not assessed'.

        Also contains a schema-drift section (formerly CheckId Foundation-08): top-level property
        names of $ctx.CAPolicies/$ctx.CAPoliciesBeta that don't appear in
        config/ca-policy-known-properties.json. Foundation-08 looked for '@' annotations on the
        policy object; Graph never includes those on this endpoint under the standard
        odata.metadata=minimal, by design (confirmed against live tenant evidence), so the check
        could never fire. A genuine name allowlist does work: it immediately flagged
        `partialEnablementStrategy` (discovered 2026-08-29, not yet in Microsoft's own Learn
        reference). This is deliberately NOT a CheckId/record — it's a signal about the module
        itself ("is the collector still keeping up with Graph"), not about the tenant, and so
        belongs in this drift report, not in the customer scorecard. Top-level only: a nested diff
        through conditions/grantControls/sessionControls is a much bigger and more fragile schema
        tree, out of proportion with the added value.

        Never fails: if GraphCallLog is missing (e.g. a run with no Graph call at all), the
        function writes an empty report instead of crashing. If CAPolicies/CAPoliciesBeta or the
        config file is missing, the drift section stays empty instead of blocking the rest of the
        report.
    .OUTPUTS
        String: path to the written api-drift.json (or $null without Paths.Reports).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ctx = $script:CAInvContext
    $log = @(Get-CAInvProp $ctx 'GraphCallLog' @())

    $betaCalls = @($log | Where-Object { $_.ApiVersion -eq 'beta' })
    $betaUnique = @($betaCalls | Select-Object -ExpandProperty Uri -Unique)

    $failedCalls = @($log | Where-Object { $_.Failed })
    $byStatus = $failedCalls | Group-Object StatusCode | Sort-Object Count -Descending | ForEach-Object {
        [PSCustomObject]@{
            StatusCode = $_.Name
            Count      = $_.Count
            Examples   = @($_.Group | Select-Object -First 5 -Property Uri, ErrorMessage)
        }
    }

    $unknownProps = [ordered]@{}
    try { $knownProps = (Get-CAInvConfig).CaPolicyKnownProperties } catch { $knownProps = $null }
    if ($knownProps) {
        $policySetsByVersion = @{
            'v1.0' = @(Get-CAInvProp $ctx 'CAPolicies' @())
            'beta' = @(Get-CAInvProp $ctx 'CAPoliciesBeta' @())
        }
        foreach ($version in @('v1.0', 'beta')) {
            $policySet = @($policySetsByVersion[$version])
            if ($policySet.Count -eq 0) { continue }
            $known = @(Get-CAInvProp $knownProps $version @())
            if ($known.Count -eq 0) { continue }

            $found = @{}
            foreach ($p in $policySet) {
                foreach ($name in @($p.PSObject.Properties.Name)) {
                    if ($known -notcontains $name) {
                        if (-not $found.ContainsKey($name)) {
                            $found[$name] = [PSCustomObject]@{
                                Property          = $name
                                PolicyCount       = 0
                                ExamplePolicyId   = [string](Get-CAInvProp $p 'id' '')
                                ExamplePolicyName = [string](Get-CAInvProp $p 'displayName' '')
                            }
                        }
                        $found[$name].PolicyCount++
                    }
                }
            }
            if ($found.Count -gt 0) {
                $unknownProps[$version] = @($found.Values | Sort-Object Property)
            }
        }
    }

    $report = [PSCustomObject]@{
        RunId                   = Get-CAInvProp $ctx 'RunId'
        TenantId                = Get-CAInvProp $ctx 'TenantId'
        CollectedAt             = Get-CAInvProp $ctx 'CollectedAt'
        TotalCalls              = $log.Count
        BetaCallCount           = $betaCalls.Count
        BetaEndpoints           = $betaUnique
        FailedCallCount         = $failedCalls.Count
        FailuresByStatus        = @($byStatus)
        UnknownPolicyProperties = $unknownProps
    }

    $reportsDir = $null
    if ($ctx) {
        $pathsProp = $ctx.PSObject.Properties['Paths']
        if ($pathsProp -and $pathsProp.Value -is [System.Collections.IDictionary] -and $pathsProp.Value.Contains('Reports')) {
            $reportsDir = $pathsProp.Value['Reports']
        }
    }
    if (-not $reportsDir) { return $null }

    $path = Join-Path $reportsDir 'api-drift.json'
    Write-CAInvReportFile -Path $path -Content ($report | ConvertTo-Json -Depth 6)

    $summary = "API drift report: $($log.Count) calls, $($betaCalls.Count) on beta ($($betaUnique.Count) unique endpoints), $($failedCalls.Count) failed."
    if ($betaUnique.Count -gt 0) {
        Write-CAInvLog -Level 'INFO' -Message "$summary Beta-endpoints: $($betaUnique -join '; ')"
    }
    else {
        Write-CAInvLog -Level 'INFO' -Message $summary
    }

    if ($unknownProps.Count -gt 0) {
        $propNames = foreach ($version in $unknownProps.Keys) { foreach ($u in $unknownProps[$version]) { "$version/$($u.Property)" } }
        Write-CAInvLog -Level 'WARN' -Message "API drift report: unknown CA policy propert(y/ies) vs. config/ca-policy-known-properties.json: $($propNames -join ', ')."
    }

    return $path
}
