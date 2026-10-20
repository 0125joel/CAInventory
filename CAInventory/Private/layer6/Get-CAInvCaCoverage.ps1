function Get-CAInvCaCoverage {
    <#
    .SYNOPSIS
        Domain 6.23 — CA coverage gap: which applications get no Conditional Access applied.
    .DESCRIPTION
        Layer 6 collector. `Govern-01` aggregates the exclusions someone deliberately made; this
        check looks at the flip side, the invisible side. Exclusions live in the policy and are
        therefore discoverable; uncovered surface lives nowhere and is usually discovered only
        after an incident. For the question "what will fall outside my CA framework", this is the
        most direct measurement there is. Microsoft does the same thing in the gap analyzer
        workbook.

        No extra Graph call: reads the sign-ins that Get-CAInvSignInData has already fetched.

        THE WATERFALL. The conditionalAccessStatus field at sign-in level says nothing about
        coverage by itself. It's `notApplied` the moment no enabled policy reached success or
        failure, and that also happens when policies genuinely do target that application. The
        real answer sits one level down, in appliedConditionalAccessPolicies[].result (Microsoft
        Learn, appliedConditionalAccessPolicy + concept-conditional-access-policies, verified
        25-08-2026):

          (list empty)          No policy at all was evaluated for this sign-in. This is the real
                                coverage gap.
          notApplied            "policy isn't applied because policy conditions weren't met." The
                                policy exists and targets this application, but a condition wasn't
                                met: trusted location, platform, client app. That can be a
                                deliberate exclusion.
          notEnabled            "This is due to the policy in a disabled state." Coverage is
                                designed but off.
          reportOnly*           Phase 1 also runs for report-only policies, so this application is
                                already being evaluated; only phase 2 doesn't enforce yet. For a
                                rollout plan that's a materially different message than "nobody's
                                looking here": coverage is staged and just needs switching on.

        Microsoft summarizes the condition requirement like this: "Conditional Access policies only
        apply when all conditions are satisfied or not configured."

        THE PERMISSIONS TRAP. appliedConditionalAccessPolicies is only populated for callers with
        additional Conditional Access read permissions; without those permissions the collection
        comes back EMPTY. That's indistinguishable from "no policy targets this application", and
        would produce a report where every application is a Gap because of a missing permission.
        Hence the tenant-wide sanity check below: if not a single sign-in across the entire window
        carries an evaluated policy while the tenant does have enabled CA policies, the whole check
        goes Not assessed.

        MEASUREMENT SCOPE. /auditLogs/signIns only delivers INTERACTIVE sign-ins. That's the
        intended scope here: it's about users signing in somewhere. Calls by service principals
        aren't targeted by user-facing CA policies anyway.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.23'
    $src    = 'GET /auditLogs/signIns (conditionalAccessStatus + appliedConditionalAccessPolicies)'

    $data = Get-CAInvSignInData

    if ($data.Failed -or -not $data.Attempted) {
        $reason = if ($data.ErrorMessage) { 'Could not read the sign-in logs: {0}' -f @($data.ErrorMessage) }
        else { 'Sign-in logs were not fetched in this run.' }
        New-CAInvRecord -Domain $domain -CheckId 'Evidence-02' -ObjectType 'Application' `
            -Property 'conditionalAccessStatus' -Status 'Not assessed' -NotAssessedReason $reason `
            -GraphSource $src | Out-Null
        return
    }

    $signIns = @($data.SignIns)
    $window = $data.Window

    if ($signIns.Count -eq 0) {

        New-CAInvRecord -Domain $domain -CheckId 'Evidence-02' -ObjectType 'Application' `
            -Property 'conditionalAccessStatus' -Status 'Not assessed' `
            -NotAssessedReason ('No interactive sign-ins in the {0}-day window; without traffic there''s no way to determine which surface falls outside Conditional Access.' -f @($window)) `
            -GraphSource $src | Out-Null
        return
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $byApp = @{}
    $anyPolicyEvaluated = $false
    $notAppliedTotal = 0

    foreach ($si in $signIns) {
        $status = [string](Get-CAInvProp $si 'conditionalAccessStatus' '')
        $policies = @(Get-CAInvProp $si 'appliedConditionalAccessPolicies' @())
        if ($policies.Count -gt 0) { $anyPolicyEvaluated = $true }

        if ($status -ne 'notApplied') { continue }
        $notAppliedTotal++

        $appName = [string](Get-CAInvProp $si 'appDisplayName' '')
        $appId = [string](Get-CAInvProp $si 'appId' '')
        $key = if ($appId) { $appId } elseif ($appName) { $appName } else { '(unknown)' }

        if (-not $byApp.ContainsKey($key)) {
            $byApp[$key] = [PSCustomObject]@{
                AppId = $appId
                AppName = if ($appName) { $appName } else { $key }
                SignIns = 0
                Users = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Evaluated = 0
                ReportOnly = 0
                OnlyDisabled = 0
            }
        }
        $entry = $byApp[$key]
        $entry.SignIns++
        $upn = [string](Get-CAInvProp $si 'userPrincipalName' '')
        if ($upn) { [void]$entry.Users.Add($upn) }

        if ($policies.Count -eq 0) { continue }
        $entry.Evaluated++

        $sawReportOnly = $false
        $sawEnabled = $false
        foreach ($pol in $policies) {
            $r = [string](Get-CAInvProp $pol 'result' '')
            if ($r -like 'reportOnly*') { $sawReportOnly = $true }
            elseif ($r -ne 'notEnabled') { $sawEnabled = $true }
        }
        if ($sawReportOnly) { $entry.ReportOnly++ }
        if (-not $sawEnabled -and -not $sawReportOnly) { $entry.OnlyDisabled++ }
    }
    $sw.Stop()
    Write-CAInvLog -Level 'DEBUG' -Domain $domain -Message "CA coverage computed: $($signIns.Count) sign-ins, $([Math]::Round($sw.Elapsed.TotalSeconds, 1))s."

    $caPolicies = @(Get-CAInvCaPolicy)
    $enabledCa = @($caPolicies | Where-Object { $_.state -eq 'enabled' }).Count
    if (-not $anyPolicyEvaluated -and $enabledCa -gt 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Evidence-02' -ObjectType 'Application' `
            -Property 'appliedConditionalAccessPolicies' -Status 'Not assessed' `
            -NotAssessedReason ('None of the {0} sign-ins carries an evaluated CA policy, while the tenant has {1} enabled policies. The appliedConditionalAccessPolicies field is only populated for callers with additional Conditional Access read permissions; without those permissions, every application looks uncovered. Coverage therefore cannot be determined.' -f @($signIns.Count, $enabledCa)) `
            -GraphSource $src | Out-Null
        Write-CAInvLog -Level 'WARN' -Domain $domain -Message 'Evidence-02 skipped: appliedConditionalAccessPolicies is empty everywhere, likely a permissions issue.'
        return
    }

    $cappedNote = if ($data.Capped) { ' Note: the page limit was reached, so the window may be incompletely sampled.' } else { '' }

    if ($byApp.Count -eq 0) {

        if ($data.Capped) {
            New-CAInvRecord -Domain $domain -CheckId 'Evidence-02' -ObjectType 'Application' `
                -Property 'conditionalAccessStatus' -Status 'Not assessed' `
                -NotAssessedReason ('No uncovered traffic was found within the sign-ins retrieved, but the page limit was reached. Absence of evidence is not evidence of absence here: narrow the window with -LookbackDays to get a complete measurement.') `
                -GraphSource $src | Out-Null
        }
        else {
            New-CAInvRecord -Domain $domain -CheckId 'Evidence-02' -ObjectType 'Tenant' `
                -Property 'conditionalAccessStatus' `
                -ObservedValue "All $($signIns.Count) interactive sign-ins in $window days had Conditional Access applied; no uncovered surface found." `
                -Status 'Ready' -GraphSource $src | Out-Null
        }
        Write-CAInvLog -Level 'INFO' -Domain $domain -Message "No uncovered applications found across $($signIns.Count) sign-ins."
        return
    }

    foreach ($app in @(@($byApp.Values) | Sort-Object -Property SignIns -Descending)) {

        $userList = @(@($app.Users) | Sort-Object)
        $shown = @($userList | Select-Object -First 25)
        $userText = if ($userList.Count -eq 0) { 'no username recorded' }
        elseif ($userList.Count -gt $shown.Count) { "$($userList.Count) users, including: $($shown -join ', ')" }
        else { "$($userList.Count) user(s): $($shown -join ', ')" }

        $base = "$($app.SignIns) sign-in(s) without an applied CA policy in $window days; $userText."

        if ($app.Evaluated -eq 0) {

            New-CAInvRecord -Domain $domain -CheckId 'Evidence-02' -ObjectType 'Application' `
                -ObjectId $app.AppId -ObjectName $app.AppName -Property 'appliedConditionalAccessPolicies' `
                -ObservedValue "$base Not a single CA policy was evaluated on it.$cappedNote" `
                -Status 'Gap' -GraphSource $src `
                -Recommendation ('No Conditional Access policy has ever been evaluated on this application: it falls entirely outside the framework. This isn''t an exception someone made, it''s surface area that never came into scope. Microsoft recommends applying Conditional Access to every application. Bring it into the baseline, or record why it deliberately stays outside it.') | Out-Null
        }
        elseif ($app.ReportOnly -gt 0) {

            New-CAInvRecord -Domain $domain -CheckId 'Evidence-02' -ObjectType 'Application' `
                -ObjectId $app.AppId -ObjectName $app.AppName -Property 'appliedConditionalAccessPolicies' `
                -ObservedValue "$base For $($app.ReportOnly) of those, a report-only policy was already watching.$cappedNote" `
                -Status 'Review required' -GraphSource $src `
                -Recommendation ('This application isn''t enforced yet, but a report-only policy is already watching: phase 1 of evaluation also runs for report-only policy. Coverage is therefore already staged and only needs to be switched on. Review the report-only results over a period covering all clients in use, then set the policy to On.') | Out-Null
        }
        elseif ($app.OnlyDisabled -eq $app.Evaluated) {
            New-CAInvRecord -Domain $domain -CheckId 'Evidence-02' -ObjectType 'Application' `
                -ObjectId $app.AppId -ObjectName $app.AppName -Property 'appliedConditionalAccessPolicies' `
                -ObservedValue "$base Policies were evaluated, but all of them were off.$cappedNote" `
                -Status 'Gap' -GraphSource $src `
                -Recommendation ('Coverage for this application is designed but off: every evaluated policy is in the disabled state. That''s a different problem from a missing policy and usually easier to fix. Find out why they''re off and enable them, or clean them up so the report doesn''t suggest coverage that isn''t there.') | Out-Null
        }
        else {
            New-CAInvRecord -Domain $domain -CheckId 'Evidence-02' -ObjectType 'Application' `
                -ObjectId $app.AppId -ObjectName $app.AppName -Property 'appliedConditionalAccessPolicies' `
                -ObservedValue "$base Policies were evaluated, but for these sign-ins a condition wasn't met.$cappedNote" `
                -Status 'Review required' -GraphSource $src `
                -Recommendation ('Conditional Access is targeted at this application, but for these sign-ins not all conditions were met; a policy only applies when every condition is satisfied or left unconfigured. That can be deliberate, e.g. an exclusion on trusted location or platform. Assess whether that exclusion still fits the design, and whether it covers the users you see in this window.') | Out-Null
        }
    }

    New-CAInvRecord -Domain $domain -CheckId 'Evidence-02' -ObjectType 'Tenant' `
        -Property 'coverageSummary' `
        -ObservedValue "$notAppliedTotal of $($signIns.Count) interactive sign-ins in $window days had no CA policy applied, spread across $($byApp.Count) application(s).$cappedNote" `
        -Status 'Ready' -GraphSource $src | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($byApp.Count) application(s) with uncovered traffic ($notAppliedTotal of $($signIns.Count) sign-ins)."
}
