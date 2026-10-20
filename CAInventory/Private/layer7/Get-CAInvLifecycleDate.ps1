function Get-CAInvLifecycleDate {
    <#
    .SYNOPSIS
        Domain 6.34 — Expiring Microsoft functionality that Conditional Access relies on.
    .DESCRIPTION
        Layer 7 collector. Checks the lifecycle dates from config/lifecycle-dates.json against the
        run date. Makes no Graph call at all, so it's free; the model is the same as Govern-03's,
        which also works purely on config and already-collected records.

        Why this is a check and not a paragraph in the documentation: Conditional Access relies on
        functionality that Microsoft retires on fixed dates. An assessment that doesn't know those
        dates recommends a setup that breaks down within a year, and it's exactly the kind of
        maintenance that quietly lapses in a consultancy product. Condition-08 showed that the
        model wants to flag expiring functionality; that principle is carried through here and
        moved out of the check texts into config, so updating it is a config change, not a code
        change.

        THE CORE OF THE DECISION LOGIC. A date only becomes a finding once THIS tenant is
        demonstrably affected by it. Every entry lists relatedCheckIds: the checks that show
        whether the topic applies in this tenant. If one of those checks shows a Gap or a Review
        required, the elapsed date is a real problem, not just a calendar fact. Without such a
        signal, it stays a note. The alternative, judging purely by the calendar, would give every
        customer the same list, even where it doesn't apply, and that's exactly the kind of noise
        that has cost earlier checks their place.

        All dates in the config were verified against learn.microsoft.com on 25-08-2026, with the
        source URL per entry. A date without a verifiable source doesn't belong in there.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.34'
    $src    = 'Aggregation: config/lifecycle-dates.json against the run date'

    $ctx = $script:CAInvContext

    $ctxConfig = Get-CAInvProp $ctx 'Config'
    $cfg = if ($ctxConfig -is [System.Collections.IDictionary]) { $ctxConfig['LifecycleDates'] } else { Get-CAInvProp $ctxConfig 'LifecycleDates' }
    if (-not $cfg) {
        try { $cfg = (Get-CAInvConfig).LifecycleDates } catch { $cfg = $null }
    }

    $items = @(Get-CAInvProp $cfg 'items' @())
    if ($items.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Govern-04' -ObjectType 'Tenant' `
            -Property 'lifecycleDates' -Status 'Not assessed' `
            -NotAssessedReason ('config/lifecycle-dates.json is missing or contains no items, so the lifecycle dates cannot be checked against the run date.') `
            -ApiVersion 'n/a' -GraphSource $src | Out-Null
        return
    }

    $warnDays = [int](Get-CAInvProp $cfg 'warnWithinDays' 180)
    $now = [datetime](Get-CAInvProp $ctx 'CollectedAt' (Get-Date))
    $today = $now.Date

    $statusRank = @{ 'Gap' = 0; 'Review required' = 1; 'Not assessed' = 2; 'Ready' = 3 }
    $worstByCheck = @{}
    foreach ($r in @(Get-CAInvProp $ctx 'Records' @())) {
        $cid = [string](Get-CAInvProp $r 'CheckId' '')
        if (-not $cid) { continue }
        $st = [string](Get-CAInvProp $r 'Status' '')
        $rank = if ($statusRank.ContainsKey($st)) { $statusRank[$st] } else { 2 }
        if (-not $worstByCheck.ContainsKey($cid) -or $rank -lt $worstByCheck[$cid]) { $worstByCheck[$cid] = $rank }
    }

    $expiredWithSignal = 0
    $upcoming = 0

    foreach ($item in $items) {
        $id = [string](Get-CAInvProp $item 'id' '')
        $label = [string](Get-CAInvProp $item 'label' $id)
        $effect = [string](Get-CAInvProp $item 'effect' '')
        $dateRaw = [string](Get-CAInvProp $item 'date' '')
        $related = @(Get-CAInvProp $item 'relatedCheckIds' @())
        $learnUrl = [string](Get-CAInvProp $item 'learnUrl' '')

        $parsed = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($dateRaw, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {

            New-CAInvRecord -Domain $domain -CheckId 'Govern-04' -ObjectType 'LifecycleDate' `
                -ObjectId $id -ObjectName $label -Property 'date' -Status 'Not assessed' `
                -NotAssessedReason ('The date ''{0}'' in config/lifecycle-dates.json is not readable; expected format yyyy-MM-dd.' -f @($dateRaw)) `
                -ApiVersion 'n/a' -GraphSource $src | Out-Null
            continue
        }

        $dayDiff = ($parsed.Date - $today).Days
        $dateText = $parsed.ToString('d MMMM yyyy', [cultureinfo]::GetCultureInfo('en-US'))

        $signalling = @($related | Where-Object { $worstByCheck.ContainsKey($_) -and $worstByCheck[$_] -le 1 })

        if ($dayDiff -lt 0) {
            $daysAgo = [Math]::Abs($dayDiff)
            if ($signalling.Count -gt 0) {
                $expiredWithSignal++
                New-CAInvRecord -Domain $domain -CheckId 'Govern-04' -ObjectType 'LifecycleDate' `
                    -ObjectId $id -ObjectName $label -Property 'date' `
                    -ObservedValue "Passed on $dateText ($daysAgo days ago) and this tenant is affected: $($signalling -join ', ') show a gap or review point. $effect" `
                    -Status 'Gap' -ApiVersion 'n/a' -GraphSource $src `
                    -Recommendation ('This date has passed, and {0} show that the topic is still relevant in this tenant. Resolve that first; a CA design relying on this will get stuck. {1}' -f @(($signalling -join ', '), $(if ($learnUrl) { 'Background: {0}' -f @($learnUrl) } else { '' }))) | Out-Null
            }
            else {
                New-CAInvRecord -Domain $domain -CheckId 'Govern-04' -ObjectType 'LifecycleDate' `
                    -ObjectId $id -ObjectName $label -Property 'date' `
                    -ObservedValue "Passed on $dateText ($daysAgo days ago); no risk signal in this tenant on $($related -join ', '). $effect" `
                    -Status 'Ready' -ApiVersion 'n/a' -GraphSource $src | Out-Null
            }
        }
        elseif ($dayDiff -le $warnDays) {
            $upcoming++
            New-CAInvRecord -Domain $domain -CheckId 'Govern-04' -ObjectType 'LifecycleDate' `
                -ObjectId $id -ObjectName $label -Property 'date' `
                -ObservedValue "In $dayDiff days ($dateText). $effect" `
                -Status 'Review required' -ApiVersion 'n/a' -GraphSource $src `
                -Recommendation ('This change arrives within {0} days. Assess whether the planned CA design is prepared for it, and whether {1} will still show the desired picture after rollout. {2}' -f @($warnDays, ($related -join ', '), $(if ($learnUrl) { 'Background: {0}' -f @($learnUrl) } else { '' }))) | Out-Null
        }
        else {
            New-CAInvRecord -Domain $domain -CheckId 'Govern-04' -ObjectType 'LifecycleDate' `
                -ObjectId $id -ObjectName $label -Property 'date' `
                -ObservedValue "In $dayDiff days ($dateText). $effect" `
                -Status 'Ready' -ApiVersion 'n/a' -GraphSource $src | Out-Null
        }
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($items.Count) lifecycle dates checked; $expiredWithSignal expired with a risk signal, $upcoming within $warnDays days."
}
