function Get-CAInvCisMapping {
    <#
    .SYNOPSIS
        Domain 6.33 — CIS controls.
    .DESCRIPTION
        Layer 7 collector. Maps the already-collected datasets onto the chosen CIS benchmark
        version via the loaded CisMap ($ctx.CisMap). The benchmark text itself is NOT copied; only
        the recommendation ID and the level. Per
        mapped control, the collector aggregates the worst status of the corresponding checks, so
        the scorecard and the register get a CIS perspective without re-measuring the controls.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.33'
    $src    = 'Aggregation: CisMap over collected records'

    $ctx = $script:CAInvContext
    $cisMap = Get-CAInvProp $ctx 'CisMap'
    if (-not $cisMap) {
        New-CAInvRecord -Domain $domain -CheckId 'Govern-03' -ObjectType 'CisControl' `
            -Property 'cisMapping' -Status 'Not assessed' `
            -NotAssessedReason ('No CIS mapping loaded (config/cis-map-*.json).') `
            -ApiVersion 'n/a' -GraphSource $src | Out-Null
        return
    }

    $records = @(if ($ctx.PSObject.Properties.Name -contains 'Records') { @($ctx.Records) } else { @() })
    $mappings = @(Get-CAInvProp $cisMap 'mappings' @())
    $version = Get-CAInvProp $cisMap 'benchmarkVersion' 'unknown'

    $rank = @{ 'Gap' = 3; 'Review required' = 2; 'Not assessed' = 1; 'Ready' = 0 }

    $layersRun = @(if ($ctx.PSObject.Properties.Name -contains 'LayersRun') { @($ctx.LayersRun) } else { @() })

    $allLayersRan = @(@('0', '1', '2', '3', '4', '5', '6', '7') | Where-Object { $layersRun -notcontains $_ }).Count -eq 0

    foreach ($m in $mappings) {
        $checkId = Get-CAInvProp $m 'checkId'
        $matched = @($records | Where-Object { $_.CheckId -eq $checkId })

        if ($matched.Count -eq 0) {
            $observed = if ($allLayersRan) {
                "Source check $checkId produced no record at all in this run, even though all layers ran."
            }
            else {
                "Source check $checkId did not run in this run."
            }
            $reason = if ($allLayersRan) {
                "Check $checkId had nothing to report: all layers ran, but this check wrote no record. That is not proof that the CIS control is covered, nor proof that it is violated. Look up the check in the reference documentation to see under which condition it writes a finding."
            }
            else {
                "Check $checkId not present; only layer $($layersRun -join ', ') ran. Run -Layer All to be able to assess this CIS control."
            }
            New-CAInvRecord -Domain $domain -CheckId 'Govern-03' -ObjectType 'CisControl' `
                -ObjectName "$version $(Get-CAInvProp $m 'recommendationId') ($(Get-CAInvProp $m 'level'))" `
                -Property (Get-CAInvProp $m 'title' $checkId) -ObservedValue $observed `
                -Status 'Not assessed' -NotAssessedReason $reason `
                -ApiVersion 'n/a' -GraphSource $src `
                -CisRef "$version $(Get-CAInvProp $m 'recommendationId') ($(Get-CAInvProp $m 'level'))" | Out-Null
            continue
        }

        $worst = ($matched | Sort-Object { $rank["$($_.Status)"] } -Descending | Select-Object -First 1).Status
        New-CAInvRecord -Domain $domain -CheckId 'Govern-03' -ObjectType 'CisControl' `
            -ObjectName "$version $(Get-CAInvProp $m 'recommendationId') ($(Get-CAInvProp $m 'level'))" `
            -Property (Get-CAInvProp $m 'title' $checkId) `
            -ObservedValue "Worst status of $checkId over $($matched.Count) record(s): $worst" `
            -Status $worst `
            -ApiVersion 'n/a' -GraphSource $src `
            -CisRef "$version $(Get-CAInvProp $m 'recommendationId') ($(Get-CAInvProp $m 'level'))" | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($mappings.Count) CIS controls mapped ($version)."
}
