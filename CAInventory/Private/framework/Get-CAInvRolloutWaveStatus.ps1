function Resolve-CAInvConditionStatus {
    <#
    .SYNOPSIS
        Evaluates a single rollout-order condition against the already-collected records.
    .DESCRIPTION
        Extracted from New-CAInvRolloutPlan.ps1 so
        Get-CAInvRolloutWaveStatus (and thereby Get-CAInvGoLiveStatus) reuses exactly the same
        wave-gate criterion instead of redefining it. Behavior
        unchanged from the original, nested version — covered by the existing
        tests/report/New-CAInvRolloutPlan.Tests.ps1 suite, which tests this purely as a behavioral
        contract, not as an implementation detail.

        A condition without mapped CheckIds is a known coverage gap (Manual = $true): it doesn't
        block the automated gate, but always stays "needs manual confirmation". Anything that is
        mapped but isn't Ready (incl. 'layer not run') simply blocks the gate.
    .OUTPUTS
        PSCustomObject: @{ Status; Manual; Detail; Recs }.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param($Condition, $AllRecords)

    $statusRank = @{ 'Gap' = 0; 'Review required' = 1; 'Not assessed' = 2; 'Ready' = 3 }

    $checkIds = @($Condition.checkIds)
    if ($checkIds.Count -eq 0) {
        return [PSCustomObject]@{
            Status = 'Not assessed'; Manual = $true
            Detail = 'No automated check available for this condition (known coverage gap). Confirm this manually; it does not block the wave gate, since a nonexistent measurement can never count as a Gap, but the wave may only truly open after your confirmation.'
            Recs   = @()
        }
    }

    $recs = @($AllRecords | Where-Object { $checkIds -contains $_.CheckId })
    if ($recs.Count -eq 0) {

        $ctx = $script:CAInvContext
        $layersRun = @(if ($ctx -and $ctx.PSObject.Properties.Name -contains 'LayersRun') { @($ctx.LayersRun) } else { @() })
        $allLayersRan = $layersRun.Count -gt 0 -and @(@('0', '1', '2', '3', '4', '5', '6', '7') | Where-Object { $layersRun -notcontains $_ }).Count -eq 0

        $needsParam = [string](Get-CAInvProp $Condition 'requiresParameter' '')

        $detail = if (-not $allLayersRan -and $layersRun.Count -gt 0) {
            "No findings for $($checkIds -join ', '): only layer $($layersRun -join ', ') ran. Run -Layer All to be able to measure this condition."
        }
        elseif ($allLayersRan -and $needsParam) {
            "No findings for $($checkIds -join ', '), even though all layers ran. This condition can only be measured when you pass $needsParam; without that parameter the module doesn't know which accounts are involved and deliberately makes no determination."
        }
        elseif ($allLayersRan) {
            "No findings for $($checkIds -join ', '), even though all layers ran. So the check wrote nothing; check the reference documentation for the condition under which it produces a finding."
        }
        else {
            "No findings for $($checkIds -join ', ') in this run (layer not run?). Run -Layer All to be able to measure this condition."
        }

        return [PSCustomObject]@{
            Status = 'Not assessed'; Manual = $false
            Detail = $detail
            Recs   = @()
        }
    }

    $worst = $recs | Sort-Object @{ Expression = { $statusRank[$_.Status] } } | Select-Object -First 1
    $detail = if ($worst.Status -eq 'Ready') { "$($recs.Count) finding(s), all Ready." }
              elseif ($worst.NotAssessedReason) { [string]$worst.NotAssessedReason }
              elseif ($worst.Recommendation) { [string]$worst.Recommendation }
              else { [string]$worst.ObservedValue }
    return [PSCustomObject]@{ Status = $worst.Status; Manual = $false; Detail = $detail; Recs = $recs }
}

function Get-CAInvRolloutWaveStatus {
    <#
    .SYNOPSIS
        Per-wave open/closed status according to the wave-gate criterion — the summary
        Get-CAInvGoLiveStatus needs, without the page-specific enrichment (DOM ids,
        per-user drilldown, finding keys) that New-CAInvRolloutPlan.ps1 itself adds.
    .PARAMETER WaveConfig
        The RolloutWaves config object ($ctx.Config.RolloutWaves), or $null.
    .PARAMETER Records
        The full record set of the run.
        ManualCount counts the conditions without any mapped check. Those deliberately don't block
        Open (a nonexistent measurement can never count as a Gap), but Get-CAInvGoLiveStatus does
        need to be able to gate on them via the requireAllConditionsMeasured criterion. Before
        0.29.0, this function discarded the Manual flag that Resolve-CAInvConditionStatus had just
        computed, which made "nothing anomalous was found" indistinguishable from "it was not
        measured".
    .OUTPUTS
        Array of PSCustomObject: @{ Id; Order; Name; Open; ManualCount; Conditions }. Empty if
        WaveConfig is missing.
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param($WaveConfig, [array] $Records)

    if (-not $WaveConfig -or -not $WaveConfig.waves) { return @() }

    $waveResults = foreach ($wave in ($WaveConfig.waves | Sort-Object order)) {

        $condIdx = 0
        $condResults = @(foreach ($cond in $wave.conditions) {
                $r = Resolve-CAInvConditionStatus -Condition $cond -AllRecords $Records
                $r | Add-Member -NotePropertyName 'Label' -NotePropertyValue ([string](Get-CAInvProp $cond 'label' '')) -Force
                $r | Add-Member -NotePropertyName 'Index' -NotePropertyValue $condIdx -Force
                $r
                $condIdx++
            })
        $blocking = @($condResults | Where-Object { $_.Status -ne 'Ready' -and -not $_.Manual })
        $manual = @($condResults | Where-Object { $_.Manual })
        [PSCustomObject]@{
            Id          = $wave.id
            Order       = $wave.order
            Name        = $wave.name
            Open        = ($blocking.Count -eq 0)
            ManualCount = $manual.Count
            Conditions  = @($condResults)
        }
    }
    return @($waveResults)
}
