function Get-CAInvLegacyAuthUsageKql {
    <#
    .SYNOPSIS
        LAW/KQL drilldown for legacy authentication usage.
    .DESCRIPTION
        Condition-09 (Get-CAInvLegacyAuthUsage) already counts, via Graph, how many legacy sign-ins
        there are and by how many users, but doesn't give a per-user/per-app/per-device-type
        breakdown — that would require an unaggregated Graph result, exactly the performance trap
        that already broke Get-CAInvSignInData earlier. This function still delivers that
        breakdown, but via the Log Analytics query REST API with server-side aggregation
        (summarize), the same way Get-CAInvSignInUsageKql already does for the method matrix usage
        axis.

        Runs only when Condition-09 has actually found legacy usage (Status 'Gap' via Graph) AND
        Azure context/a workspace is available (Connect-CAInv on by default, can be turned off with
        -SkipAzure); otherwise nothing happens — no unnecessary query when there's nothing to show
        anyway, and no crash without a workspace.

        'Legacy' uses the same definition as Get-CAInvLegacyAuthUsage: the explicit allowlist from
        Get-CAInvLegacyClientApp, so the Graph count (Condition-09) and this KQL breakdown can
        never disagree about what 'legacy' means. An unknown ClientAppUsed ('Unknown', empty, or an
        unrecognized type) is explicitly NOT included: without a known protocol there's nothing to
        migrate either, and such rows made the drilldown unusable.

        Result: a Condition-11 record with the top user/app/device-type combinations (count, last
        seen), plus the raw response as evidence (Write-CAInvRaw). No new method-name vocabulary
        needed (unlike the method matrix adapter): ClientAppUsed is shown verbatim, not translated
        into a Graph vocabulary.

        Zero rows is ambiguous: it can mean "no legacy usage in this window", but also "the
        workspace doesn't export SignInLogs/NonInteractiveUserSignInLogs, so this query can never
        see it at all" — while Condition-09 already gave Gap via Graph at that point. Before this
        round, the function treated both cases identically (silent return, no record), which made
        "not measured" look like "nothing found". At 0 rows, the already-known
        `PrimaryLogWorkspace.Categories` (Resolve-CAInvLogWindow) is therefore first checked for the
        two categories this query needs; if either is missing, the function still writes a
        Condition-11 record as 'Not assessed' instead of silently doing nothing. If both categories
        are present and there are still 0 rows, behavior stays unchanged (no record): that's then a
        genuine "nothing additional to show".
    .OUTPUTS
        None. Optionally writes a Condition-11 record and evidence.
    #>
    [CmdletBinding()]
    param()

    $ctx = $script:CAInvContext
    $domain = '6.16'

    if (-not ($ctx.PSObject.Properties['Connections'] -and $ctx.Connections -and $ctx.Connections.Azure)) {
        return
    }
    if (-not ($ctx.PSObject.Properties['PrimaryLogWorkspace'] -and $ctx.PrimaryLogWorkspace)) {
        Write-CAInvLog -Level 'DEBUG' -Domain $domain -Message ("No primary Log Analytics workspace; legacy auth drilldown skipped. {0}" -f (Get-CAInvAzureUnavailableReason)).Trim()
        return
    }

    $ws = $ctx.PrimaryLogWorkspace
    $customerId = $ws.CustomerId
    if (-not $customerId) {
        Write-CAInvLog -Level 'WARN' -Domain $domain -Message "Workspace $($ws.WorkspaceId) found but customerId not readable; legacy auth drilldown skipped."
        return
    }

    $window = Get-CAInvEffectiveLookbackWindow

    $token = Get-CAInvLogAnalyticsToken -Domain $domain
    if (-not $token) { return }

    $legacyList = (@(Get-CAInvLegacyClientApp | ForEach-Object { $_ | ConvertTo-Json -Compress }) -join ',')

    $kql = @"
let win = ${window}d;
let legacyClients = dynamic([${legacyList}]);
union isfuzzy=true
  (SigninLogs
 | where TimeGenerated >= ago(win)
 | where ResultType == "0"
 | where ClientAppUsed in~ (legacyClients)
 | project TimeGenerated, UserPrincipalName, AppDisplayName, ClientAppUsed, DeviceDetail = todynamic(DeviceDetail)),
  (AADNonInteractiveUserSignInLogs
 | where TimeGenerated >= ago(win)
 | where ResultType == "0"
 | where ClientAppUsed in~ (legacyClients)
 | project TimeGenerated, UserPrincipalName, AppDisplayName, ClientAppUsed, DeviceDetail = todynamic(DeviceDetail))
| extend DeviceOS = tostring(DeviceDetail.operatingSystem)
| summarize Count = count(), LastSeen = max(TimeGenerated) by UserPrincipalName, AppDisplayName, ClientAppUsed, DeviceOS
| top 200 by Count desc
"@

    $rows = $null
    $queryResult = Invoke-CAInvLogAnalyticsQuery -CustomerId $customerId -Token $token -Kql $kql -Domain $domain
    if (-not $queryResult.Success) {
        Write-CAInvLog -Level 'WARN' -Domain $domain -Message "KQL query for legacy auth drilldown on workspace $customerId failed: $($queryResult.ErrorMessage)"
        return
    }
    $resp = $queryResult.Response
    $rows = @($resp.tables | Select-Object -First 1 | ForEach-Object { $_.rows })

    if ($null -eq $rows) { $rows = @() }
    if ($rows.Count -eq 0) {
        $wsCategories = @(Get-CAInvProp $ws 'Categories' @())
        $requiredCategories = @('SignInLogs', 'NonInteractiveUserSignInLogs')
        $missingCategories = @($requiredCategories | Where-Object { $wsCategories -notcontains $_ })
        if ($missingCategories.Count -gt 0) {
            New-CAInvRecord -Domain $domain -CheckId 'Condition-11' -ObjectType 'SignIn' `
                -Property 'legacyAuthUsageDrilldown' -Status 'Not assessed' `
                -NotAssessedReason ('Condition-09 found legacy usage via Graph, but this KQL drilldown returned 0 rows because workspace {0} does not export the {1} category/categories to Log Analytics. Without those categories, this query can never see legacy usage anyway; this is not confirmation of absent usage.' -f @($ws.WorkspaceId, ($missingCategories -join ', '))) `
                -GraphSource 'Log Analytics KQL (SigninLogs, AADNonInteractiveUserSignInLogs)' | Out-Null
            Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Legacy auth drilldown: 0 rows, but categories $($missingCategories -join ', ') are missing from workspace $($ws.WorkspaceId)'s diagnostic settings."
            return
        }
        Write-CAInvLog -Level 'DEBUG' -Domain $domain -Message "Legacy auth drilldown: 0 user/app/devicetype combinations in a $window-day window."
        return
    }

    $rawPath = Write-CAInvRaw -Domain $domain -Endpoint 'legacyAuthUsageKql' -Data $resp

    $totalCount = 0
    $byUser = [System.Collections.Generic.HashSet[string]]::new()
    $top = @($rows | Select-Object -First 10 | ForEach-Object {
        $u = [string]$_[0]; $app = [string]$_[1]; $client = [string]$_[2]; $os = [string]$_[3]; $cnt = [int]$_[4]
        "$u via $app ($client, $os): $cnt"
    })
    foreach ($row in $rows) {
        $totalCount += [int]$row[4]
        if (-not [string]::IsNullOrWhiteSpace([string]$row[0])) { [void]$byUser.Add([string]$row[0]) }
    }

    New-CAInvRecord -Domain $domain -CheckId 'Condition-11' -ObjectType 'SignIn' `
        -Property 'legacyAuthUsageDrilldown' `
        -ObservedValue "$($rows.Count) user/app/devicetype combination(s), $totalCount sign-ins by $($byUser.Count) users in a window of $window d. Top: $($top -join '; ')" `
        -Status 'Ready' -GraphSource 'Log Analytics KQL (SigninLogs, AADNonInteractiveUserSignInLogs)' `
        -RawPath $rawPath `
        -Recommendation ('The full breakdown (user, app, clientApp, device type, count, last seen) is in the evidence file. Use this to identify the users/apps that need migrating first before legacy auth is blocked.') | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Legacy auth drilldown: $($rows.Count) combination(s), $totalCount sign-ins, $($byUser.Count) users ($window-day window). Evidence: $rawPath."
}
