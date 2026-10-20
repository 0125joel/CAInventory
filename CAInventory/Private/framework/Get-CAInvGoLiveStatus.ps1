function Get-CAInvGoLiveStatus {
    <#
    .SYNOPSIS
        Ready-for-go-live gate: one aggregated yes/no verdict on top of the scorecard.
    .DESCRIPTION
        Combines three criteria, each already computed elsewhere in the module (no new logic,
        pure aggregation — the same kind of aggregation as New-CAInvScorecard/New-CAInvRolloutPlan):
          1. Number of High-severity Gap findings, against `maxHighGapCount` (config, default 0).
          2. The four hard preconditions (Get-CAInvHardPrecondition) — must all be Ok when
             `requireAllHardPreconditions` is on.
          3. Each wave from the rollout order (Get-CAInvRolloutWaveStatus) must be open when
             `requireAllWavesOpen` is on. Without rollout-waves.json this criterion is skipped
             (non-blocking) — there is then no wave to check against.
        Configurable via config/go-live-gate.json, so a less strict gate doesn't require code.

        Default "strict" — 0 High Gaps allowed, all preconditions
        and waves mandatory. See config/go-live-gate.json for the rationale.
    .PARAMETER Records
        The full record set of the run.
    .OUTPUTS
        PSCustomObject: @{ Ready (bool); Reasons (string[]); HighGapCount; PreconditionsOk;
        WavesOpen; WaveTotal }.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array] $Records
    )

    $ctx = $script:CAInvContext

    function Get-CAInvConfigEntry {
        param($ConfigObj, [string] $Key)
        if ($null -eq $ConfigObj) { return $null }
        if ($ConfigObj -is [System.Collections.IDictionary]) { return $ConfigObj[$Key] }
        return Get-CAInvProp $ConfigObj $Key
    }

    $ctxConfig = Get-CAInvProp $ctx 'Config'
    $gateConfig = Get-CAInvConfigEntry $ctxConfig 'GoLiveGate'
    if (-not $gateConfig) {
        try { $gateConfig = (Get-CAInvConfig).GoLiveGate } catch { $gateConfig = $null }
    }
    $maxHighGap = if ($gateConfig -and $null -ne (Get-CAInvProp $gateConfig 'maxHighGapCount' $null)) { [int]$gateConfig.maxHighGapCount } else { 0 }
    $requirePreconditions = if ($gateConfig -and $null -ne (Get-CAInvProp $gateConfig 'requireAllHardPreconditions' $null)) { [bool]$gateConfig.requireAllHardPreconditions } else { $true }
    $requireWaves = if ($gateConfig -and $null -ne (Get-CAInvProp $gateConfig 'requireAllWavesOpen' $null)) { [bool]$gateConfig.requireAllWavesOpen } else { $true }
    $requireMeasured = if ($gateConfig -and $null -ne (Get-CAInvProp $gateConfig 'requireAllConditionsMeasured' $null)) { [bool]$gateConfig.requireAllConditionsMeasured } else { $true }

    $reasons = [System.Collections.Generic.List[string]]::new()

    $highGapCount = @($Records | Where-Object { $_.Status -eq 'Gap' -and $_.Severity -eq 'High' }).Count
    if ($highGapCount -gt $maxHighGap) {
        $reasons.Add("$highGapCount High-severity gap(s) (allowed: $maxHighGap).")
    }

    $preconditions = Get-CAInvHardPrecondition -Records $Records
    $failedPreconditions = @($preconditions | Where-Object { -not $_.Ok })
    $preconditionsOk = ($failedPreconditions.Count -eq 0)
    if ($requirePreconditions -and -not $preconditionsOk) {
        foreach ($p in $failedPreconditions) { $reasons.Add("Precondition '$($p.Label)' is not OK ($($p.Value)).") }
    }

    $waveConfig = Get-CAInvConfigEntry $ctxConfig 'RolloutWaves'
    if (-not $waveConfig) {
        try { $waveConfig = (Get-CAInvConfig).RolloutWaves } catch { $waveConfig = $null }
    }
    $waves = @(Get-CAInvRolloutWaveStatus -WaveConfig $waveConfig -Records $Records)
    $closedWaves = @($waves | Where-Object { -not $_.Open })
    $wavesOpen = ($waves.Count -gt 0 -and $closedWaves.Count -eq 0)
    if ($requireWaves -and $waves.Count -gt 0 -and $closedWaves.Count -gt 0) {
        foreach ($w in $closedWaves) { $reasons.Add("Wave '$($w.Name)' is not allowed to open yet.") }
    }

    $unmeasured = [System.Collections.Generic.List[object]]::new()
    foreach ($w in $waves) {
        foreach ($c in @($w.Conditions | Where-Object { $_.Manual })) {
            $unmeasured.Add([PSCustomObject]@{
                    Scope = "wave '$($w.Name)'"
                    Label = [string]$c.Label
                    Key   = Get-CAInvConditionKey -ScopeId ([string]$w.Id) -Index ([int]$c.Index)
                })
        }
    }
    $nonSeq = if ($waveConfig) { Get-CAInvProp $waveConfig 'nonSequentialConditions' $null } else { $null }
    $nsIdx = 0
    foreach ($c in @(Get-CAInvProp $nonSeq 'conditions' @())) {
        $res = Resolve-CAInvConditionStatus -Condition $c -AllRecords $Records
        if ($res.Manual) {
            $unmeasured.Add([PSCustomObject]@{
                    Scope = 'the standalone per-policy-type conditions'
                    Label = [string](Get-CAInvProp $c 'label' '')
                    Key   = Get-CAInvConditionKey -ScopeId 'nonseq' -Index $nsIdx
                })
        }
        $nsIdx++
    }

    $allConditionsMeasured = ($unmeasured.Count -eq 0)
    $unmeasuredReasons = [System.Collections.Generic.List[string]]::new()
    if ($requireMeasured -and -not $allConditionsMeasured) {
        foreach ($g in @($unmeasured | Group-Object Scope | Sort-Object Name)) {
            $labels = @($g.Group | ForEach-Object { $_.Label }) -join '; '
            $unmeasuredReasons.Add("$($g.Count) condition(s) in $($g.Name) are not measured; there is no automatic check for: $labels. Confirm them manually in the rollout plan, or set requireAllConditionsMeasured to false in config/go-live-gate.json.")
        }
        foreach ($r in $unmeasuredReasons) { $reasons.Add($r) }
    }

    $ready = ($reasons.Count -eq 0)

    return [PSCustomObject]@{
        Ready                 = $ready
        Reasons               = @($reasons)
        HighGapCount          = $highGapCount
        MaxHighGapCount       = $maxHighGap
        PreconditionsOk       = $preconditionsOk
        WavesOpen             = $wavesOpen
        WaveTotal             = $waves.Count
        AllConditionsMeasured = $allConditionsMeasured
        UnmeasuredCount       = $unmeasured.Count
        Unmeasured            = @($unmeasured)
        UnmeasuredReasons     = @($unmeasuredReasons)
    }
}
