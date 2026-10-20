function New-CAInvWorkbookExport {
    <#
    .SYNOPSIS
        Exports the Graph facts the Entra workbook needs to reports/workbook-facts.json.
    .DESCRIPTION
        The workbook (entra-workbook/) runs on live Log Analytics data, but Log Analytics
        structurally lacks two things: per-user registration status (userRegistrationDetails is
        Graph-only) and the definition of a CA policy (the logs only name which policy was
        evaluated, not its scope or grant controls). Those two come from here.

        This is deliberately a thin export file, not a second report: it contains only outcomes
        the module has already computed. No new Graph calls, no judgment of its own. The gate
        and wave logic stays where it belongs (Get-CAInvGoLiveStatus / Get-CAInvRolloutWaveStatus);
        this only writes out what came out of there, so the generator in entra-workbook/ doesn't
        have to duplicate that logic.

        NO NAMES. The userReadiness block is keyed on the object
        id, without UPN or display name: SigninLogs already contains UserPrincipalName and
        UserDisplayName itself, so the workbook fetches names live and joins on UserId. That
        saves payload, keeps the names current, and prevents a name list from ending up in an
        artifact that any reader with workbook access can open. This property is guarded by a
        test; so never add a name field here.
    .OUTPUTS
        String: path to the written workbook-facts.json.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ctx = $script:CAInvContext
    $outPath = Join-Path $ctx.Paths.Reports 'workbook-facts.json'
    $records = @($ctx.Records)

    $meta = [ordered]@{
        schemaVersion         = 2
        tenantId              = [string](Get-CAInvProp $ctx 'TenantId')
        runId                 = [string](Get-CAInvProp $ctx 'RunId')
        collectedAt           = [string](Get-CAInvProp $ctx 'CollectedAt')
        exportedAt            = [DateTimeOffset]::UtcNow.ToString('o')
        effectiveLookbackDays = [int](Get-CAInvProp $ctx 'EffectiveLookbackDays' 0)
    }

    $gateStatus = Get-CAInvGoLiveStatus -Records $records
    $gate = [ordered]@{
        ready           = [bool]$gateStatus.Ready
        reasons         = @($gateStatus.Reasons)
        highGapCount    = [int]$gateStatus.HighGapCount
        maxHighGapCount = [int]$gateStatus.MaxHighGapCount
        preconditionsOk = [bool]$gateStatus.PreconditionsOk
        wavesOpen       = [int]$gateStatus.WavesOpen
        waveTotal       = [int]$gateStatus.WaveTotal
    }

    $waveConfig = Get-CAInvProp $ctx 'Config.RolloutWaves'
    $waves = @(foreach ($w in @(Get-CAInvRolloutWaveStatus -WaveConfig $waveConfig -Records $records)) {
        [ordered]@{
            id    = [string]$w.Id
            order = [int]$w.Order
            name  = [string]$w.Name
            open  = [bool]$w.Open
        }
    })

    $statusRank = @{ 'Gap' = 0; 'Review required' = 1; 'Not assessed' = 2; 'Ready' = 3 }
    $byCheck = @{}
    foreach ($r in $records) {
        $cid = [string]$r.CheckId
        if (-not $cid) { continue }
        $status = [string]$r.Status
        $rank = if ($statusRank.ContainsKey($status)) { $statusRank[$status] } else { 9 }
        if (-not $byCheck.ContainsKey($cid)) {
            $byCheck[$cid] = [ordered]@{
                checkId  = $cid
                layer    = [string]$r.Layer
                domain   = [string]$r.Domain
                category = [string](Get-CAInvProp $r 'Category')
                status   = $status
                severity = [string]$r.Severity
                rank     = $rank
                count    = 1
            }
        }
        else {
            $byCheck[$cid].count++
            if ($rank -lt [int]$byCheck[$cid].rank) {
                $byCheck[$cid].status = $status
                $byCheck[$cid].severity = [string]$r.Severity
                $byCheck[$cid].rank = $rank
            }
        }
    }
    $readiness = @(foreach ($k in ($byCheck.Keys | Sort-Object)) {
        $e = $byCheck[$k]
        [ordered]@{ checkId = $e.checkId; layer = $e.layer; domain = $e.domain; category = $e.category; status = $e.status; severity = $e.severity; recordCount = $e.count }
    })

    $policies = @(foreach ($p in @(Get-CAInvCaPolicy)) {
        $policyId = Get-CAInvProp $p 'id'
        if (-not $policyId) { continue }
        $name = [string](Get-CAInvProp $p 'displayName' $policyId)

        $origin = Get-CAInvPolicyManagedOrigin -Policy $p
        $managedBy = if ($origin.Origin -eq 'microsoftManaged') { 'microsoftManagedHeuristic' } else { $origin.Origin }
        $managedByBasis = $origin.Basis

        [ordered]@{
            id               = [string]$policyId
            displayName      = $name
            state            = [string](Get-CAInvProp $p 'state' 'unknown')
            createdDateTime  = [string](Get-CAInvProp $p 'createdDateTime')
            modifiedDateTime = [string](Get-CAInvProp $p 'modifiedDateTime')
            templateId       = [string](Get-CAInvProp $p 'templateId')
            managedBy        = $managedBy
            managedByBasis   = $managedByBasis
            builtInControls  = @(Get-CAInvProp $p 'grantControls.builtInControls' @())
            authStrengthId   = [string](Get-CAInvProp $p 'grantControls.authenticationStrength.id')
            includesAllUsers = (Get-CAInvPolicyUserScope -Policy $p).TargetsAllUsers
            excludedUserCount  = @(Get-CAInvProp $p 'conditions.users.excludeUsers' @()).Count
            excludedGroupCount = @(Get-CAInvProp $p 'conditions.users.excludeGroups' @()).Count
        }
    })

    $strengths = @(foreach ($s in @(Get-CAInvProp $ctx 'AuthStrengths' @())) {
        $sid = Get-CAInvProp $s 'id'
        if (-not $sid) { continue }
        [ordered]@{
            id         = [string]$sid
            name       = [string](Get-CAInvProp $s 'displayName' $sid)
            policyType = [string](Get-CAInvProp $s 'policyType' 'unknown')
        }
    })

    $userReadiness = @(foreach ($u in @(Get-CAInvProp $ctx 'UserRegistrationDetails' @())) {
        $uid = Get-CAInvProp $u 'UserId'
        if (-not $uid) { continue }
        [ordered]@{
            userId               = [string]$uid
            isAdmin              = [bool](Get-CAInvProp $u 'InAdminScope' $false)
            isMfaRegistered      = [bool](Get-CAInvProp $u 'IsMfaRegistered' $false)
            belowMinimumStrength = [bool](Get-CAInvProp $u 'BelowMinimumStrength' $false)
            strongestMethodLabel = [string](Get-CAInvProp $u 'StrongestMethodLabel')
            satisfiedStrengths   = @(Get-CAInvProp $u 'SatisfiedStrengths' @())
            uncertainStrengths   = @(Get-CAInvProp $u 'UncertainStrengths' @())
        }
    })

    $facts = [ordered]@{
        meta          = $meta
        gate          = $gate
        waves         = $waves
        readiness     = $readiness
        policies      = $policies
        strengths     = $strengths
        userReadiness = $userReadiness
    }

    $json = $facts | ConvertTo-Json -Depth 8
    Write-CAInvReportFile -Path $outPath -Content $json

    Write-CAInvLog -Level 'INFO' -Message "Workbook facts written: $outPath ($($policies.Count) policies, $($userReadiness.Count) users, $($waves.Count) waves)."
    return $outPath
}
