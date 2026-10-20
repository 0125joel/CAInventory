function Get-CAInvEffectiveWindow {
    <#
    .SYNOPSIS
        Pure calculation of the effective log window (independently testable, no I/O).
    .DESCRIPTION
        Rule (choice: 'auto-extend with cap'):
          - No detected retention -> window stays the desired number of days.
          - Retention R detected -> window = min(R, Max). If that's smaller than desired, the
            window is actually shorter than requested (retention too short) and that gets
            reported.
    .OUTPUTS
        Hashtable: @{ Effective; Source ('desired'|'detected'); Note; Capped (bool); Short (bool) }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [int] $Desired,
        [Parameter(Mandatory)] [int] $Max,
        [Nullable[int]] $DetectedRetention = $null
    )

    if ($null -eq $DetectedRetention) {
        return @{ Effective = $Desired; Source = 'desired'; Note = 'No workspace retention detected; window stays at the requested number of days (Graph retention).'; Capped = $false; Short = $false }
    }

    $cap = [Math]::Min([int]$DetectedRetention, $Max)
    $capped = ([int]$DetectedRetention -gt $Max)
    $short = ($cap -lt $Desired)

    $note = if ($short) {
        "Retention ($DetectedRetention d) is shorter than requested ($Desired d); window capped at $cap d."
    } elseif ($capped) {
        "Retention ($DetectedRetention d) capped at the -MaxLookbackDays ceiling ($Max d)."
    } else {
        "Window extended to the detected retention ($DetectedRetention d)."
    }

    return @{ Effective = $cap; Source = 'detected'; Note = $note; Capped = $capped; Short = $short }
}

function Get-CAInvGraphRetention {
    <#
    .SYNOPSIS
        Retention (days) of the Entra audit and sign-in logs in Graph itself, per license tier.
    .DESCRIPTION
        Without a Log Analytics workspace, the window isn't the requested number of days but
        whatever Graph retains, and that's license-dependent: seven days on Entra ID Free, thirty
        on P1 and P2 (audit logs and sign-ins, Microsoft Learn retention table, consulted
        25-08-2026). The module previously assumed roughly 30 days for every tenant here, which
        meant a Free tenant claimed evidence over a window three times longer than the data
        actually covered.

        Note: security signals have a different table (risky sign-ins 7/30/90, risky users no
        limit). That is deliberately NOT in this helper; the effective window in the context
        object concerns audit and sign-in logs.
    .LINK
        https://learn.microsoft.com/entra/identity/monitoring-health/reference-reports-data-retention
    .OUTPUTS
        Int: 30 with Entra ID P1 or P2, otherwise 7.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [bool] $HasP1
    )

    if ($HasP1) { return 30 }
    return 7
}

function Write-CAInvGraphRetentionWindow {
    <#
    .SYNOPSIS
        Sets the effective window to the Graph retention and writes Evidence-05, for every path
        where no workspace retention could be read.
    .DESCRIPTION
        Previously Evidence-05 only existed when a readable workspace was present. In every other
        run the window silently stayed at -LookbackDays (default 90) and there was no record at
        all saying which window actually applied instead. This function fills that gap from a
        single place, so the four failure paths say the same thing.

        When the license context is unknown, it is NOT capped: that would be a guess about the
        tier. The window then stays at the requested number of days, with a Review required record
        naming the uncertainty (status model: not measured is not a value).
    .OUTPUTS
        None. Sets $ctx.EffectiveLookbackDays and writes one Evidence-05 record.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)] [int] $Desired,
        [Parameter(Mandatory)] [string] $Domain
    )

    $ctx = $script:CAInvContext
    $src = 'Derived: license tier (subscribedSkus) x Graph retention table'

    if (-not [bool](Get-CAInvProp $ctx 'Preflight.LicensesKnown' $false)) {
        $ctx.EffectiveLookbackDays = $Desired
        New-CAInvRecord -Domain $Domain -CheckId 'Evidence-05' -ObjectType 'LogWindow' `
            -Property 'effectiveLookbackDays' -ObservedValue "$Desired d (requested; Graph retention unknown)" `
            -Status 'Review required' -ManualReview `
            -GraphSource $src -ApiVersion 'n/a' `
            -Recommendation ('Without a Log Analytics workspace, the Graph retention applies: seven days on Entra ID Free, thirty on P1 and P2. This tenant''s license context could not be read, so which of the two applies here cannot be determined. The window is set to the requested number of days ({0} d); don''t take that at face value.' -f @($Desired)) | Out-Null
        Write-CAInvLog -Level 'INFO' -Domain $Domain -Message "Log window: $Desired d (no workspace; license tier unknown, so not capped to the Graph retention)."
        return
    }

    $hasP1     = [bool](Get-CAInvProp $ctx 'Preflight.Licenses.EntraIdP1' $false)
    $retention = Get-CAInvGraphRetention -HasP1 $hasP1
    $tier      = if ($hasP1) { 'Entra ID P1/P2' } else { 'Entra ID Free' }
    $effective = [Math]::Min($Desired, $retention)
    $ctx.EffectiveLookbackDays = $effective
    $short = ($effective -lt $Desired)

    $note = if ($short) {
        'Without a Log Analytics workspace, the Graph retention applies: {0} d on {1}. The requested window of {2} d therefore cannot be substantiated; anything relying on this window actually looks back {3} d. To look back further, send the logs to a workspace via diagnostic settings.' -f @($retention, $tier, $Desired, $effective)
    } else {
        'The {0} d window falls within the Graph retention of {1} d on {2}.' -f @($effective, $retention, $tier)
    }

    New-CAInvRecord -Domain $Domain -CheckId 'Evidence-05' -ObjectType 'LogWindow' `
        -Property 'effectiveLookbackDays' -ObservedValue "$effective d (requested $Desired, Graph retention $retention on $tier)" `
        -Status ($(if ($short) { 'Review required' } else { 'Ready' })) `
        -ManualReview:$short `
        -GraphSource $src -ApiVersion 'n/a' -Recommendation $note | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $Domain -Message "Log window: effective $effective d ($note)"
}

function Get-CAInvWorkspaceRetention {
    <#
    .SYNOPSIS
        Reads the retention (days) and customerId of a Log Analytics workspace via Azure ARM.
    .DESCRIPTION
        First tries the table-specific retention of SignInLogs (which can override the workspace
        default), and falls back to the workspace default retentionInDays. Fails soft and returns
        the last error message, so a read problem (403/404/api-version) becomes visible.

        Also always fetches the workspace default when the table-specific retention was already
        found, purely to pick up `properties.customerId` (the same response as the retention
        fallback, no extra call needed if the table branch already failed). customerId is the GUID
        the Log Analytics query REST API expects (not the ARM resource ID) — needed for
        Get-CAInvSignInUsageKql, which reuses this function instead of duplicating workspace
        discovery.

        Both ARM GETs go through Invoke-CAInvArmRequest: client-side timeout +
        heartbeat, so a slow or hanging ARM call can no longer wait unbounded here.
    .OUTPUTS
        PSCustomObject: @{ Retention (nullable int); CustomerId (nullable string); Error (string) }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string] $WorkspaceResourceId,
        [Parameter(Mandatory)] [string] $Token,
        [Parameter(Mandatory)] [string] $Domain
    )

    $base = 'https://management.azure.com' + $WorkspaceResourceId
    $lastErr = $null
    $retention = $null

    $tblResp = Invoke-CAInvArmRequest -Uri "$base/tables/SignInLogs?api-version=2022-10-01" -Token $Token -Domain $Domain
    if ($tblResp.Success) {
        $tr = $tblResp.Response.properties.totalRetentionInDays
        if (-not $tr) { $tr = $tblResp.Response.properties.retentionInDays }
        if ($tr) { $retention = [int]$tr }
    }
    else {
        $lastErr = "SignInLogs-tabel: $($tblResp.ErrorMessage)"
        Write-CAInvLog -Level 'DEBUG' -Message "SignInLogs table retention not readable for $WorkspaceResourceId : $($tblResp.ErrorMessage)"
    }

    $wsResp = Invoke-CAInvArmRequest -Uri "$base`?api-version=2023-09-01" -Token $Token -Domain $Domain
    if ($wsResp.Success) {
        $customerId = $wsResp.Response.properties.customerId
        if ($null -eq $retention) {
            if ($wsResp.Response.properties.retentionInDays) { $retention = [int]$wsResp.Response.properties.retentionInDays }
            else { $lastErr = 'Workspace read but retentionInDays is missing.' }
        }
        if ($null -ne $retention -or $customerId) {
            return [PSCustomObject]@{ Retention = $retention; CustomerId = $customerId; Error = $(if ($null -eq $retention) { $lastErr } else { $null }) }
        }
    }
    else {
        $lastErr = "Workspace: $($wsResp.ErrorMessage)"
        Write-CAInvLog -Level 'WARN' -Message "Workspace retention not readable for $WorkspaceResourceId : $($wsResp.ErrorMessage)"
    }

    return [PSCustomObject]@{ Retention = $retention; CustomerId = $null; Error = $(if ($null -eq $retention) { $lastErr } else { $null }) }
}

function Resolve-CAInvPrimaryWorkspace {
    <#
    .SYNOPSIS
        Pure selection of the primary Log Analytics workspace from deduplicated candidates
        (independently testable, no I/O) — analogous to Get-CAInvEffectiveWindow.
    .DESCRIPTION
        Rule. Before this round, the workspace with the highest retention
        silently won — even if another workspace had the category the KQL adapters
        (Get-CAInvSignInUsageKql, Get-CAInvLegacyAuthUsageKql) actually needed, resulting in a
        silently empty outcome. Now:
          - If -OverrideWorkspaceId is set (from -PrimaryWorkspaceId on Invoke-CAInventory), that
            always wins, provided it appears among Candidates. If it isn't among them: Review
            required, no primary workspace, with the candidates that were found in the text.
          - Without an override and exactly 1 candidate: selected automatically (unchanged
            behavior for a single workspace).
          - Without an override and multiple candidates: NO guessing. Review required with all
            candidates (workspace ID, retention, categories) so the user sees them in the report
            and can pass -PrimaryWorkspaceId on a subsequent run if desired.
        Counts ALL workspaces with readable retention, regardless of which categories they log: a
        category filter would itself be another assumption about what's "relevant," and the user
        is better placed to judge that than the module.
    .PARAMETER Candidates
        Deduplicated workspace objects (one per WorkspaceId) with at least WorkspaceId, Retention,
        Categories.
    .PARAMETER OverrideWorkspaceId
        Optional: the ARM resource ID (properties.workspaceId form) the caller wants to pin.
    .OUTPUTS
        PSCustomObject: @{ Primary; Status ('Ready'|'Review required'); ObservedValue; Recommendation }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [AllowEmptyCollection()]
        [object[]] $Candidates = @(),

        [string] $OverrideWorkspaceId
    )

    $describe = {
        param($ws)
        "$($ws.WorkspaceId) ($($ws.Retention)d, categories: $((@($ws.Categories) -join ', ')))"
    }

    if ($OverrideWorkspaceId) {
        $match = $Candidates | Where-Object { $_.WorkspaceId -eq $OverrideWorkspaceId } | Select-Object -First 1
        if ($match) {
            return [PSCustomObject]@{
                Primary         = $match
                Status          = 'Ready'
                ObservedValue   = (& $describe $match)
                Recommendation  = ('Workspace pinned via -PrimaryWorkspaceId.')
            }
        }
        $available = if ($Candidates.Count -gt 0) { (($Candidates | ForEach-Object { & $describe $_ }) -join '; ') } else { '(no workspace with readable retention found)' }
        return [PSCustomObject]@{
            Primary        = $null
            Status         = 'Review required'
            ObservedValue  = $available
            Recommendation = ('The specified -PrimaryWorkspaceId ''{0}'' does not match any detected workspace(s). See ObservedValue for the valid values.' -f @($OverrideWorkspaceId))
        }
    }

    if ($Candidates.Count -eq 1) {
        return [PSCustomObject]@{
            Primary        = $Candidates[0]
            Status         = 'Ready'
            ObservedValue  = (& $describe $Candidates[0])
            Recommendation = ('Diagnostic settings to Log Analytics present.')
        }
    }

    if ($Candidates.Count -eq 0) {
        return [PSCustomObject]@{
            Primary        = $null
            Status         = 'Review required'
            ObservedValue  = 'no workspace with readable retention'
            Recommendation = ('No workspace with readable retention found.')
        }
    }

    $list = ($Candidates | ForEach-Object { & $describe $_ }) -join '; '
    return [PSCustomObject]@{
        Primary        = $null
        Status         = 'Review required'
        ObservedValue  = "$($Candidates.Count) workspaces found, no automatic choice made: $list"
        Recommendation = ('Multiple Log Analytics workspaces found in the Entra ID diagnostic settings; no automatic choice was made deliberately. Pass -PrimaryWorkspaceId ''<full ARM resource ID>'' to Invoke-CAInventory to pin one — see ObservedValue for the candidates. Until then, the method matrix usage axis and the legacy-auth drilldown remain Not assessed.')
    }
}

function Resolve-CAInvLogWindow {
    <#
    .SYNOPSIS
        Detects Entra diagnostic settings + LAW retention and sets the effective log window. Runs early, before log-dependent checks.
    .DESCRIPTION
        Requires the Azure context (on by default; can be turned off with -SkipAzure); diagnostic
        settings and workspace retention live in Azure Resource Manager, not Graph. Without an
        Azure context, the window stays equal to -LookbackDays and that is reported as Evidence-04
        'Not assessed'. Always sets $ctx.EffectiveLookbackDays. When multiple workspaces are
        found, the primary selection is delegated to Resolve-CAInvPrimaryWorkspace: one workspace = automatic, multiple = Review required unless
        $ctx.PrimaryWorkspaceId (-PrimaryWorkspaceId on Invoke-CAInventory) points to one of the
        candidates.
    #>
    [CmdletBinding()]
    param()

    $ctx = $script:CAInvContext
    $domain  = '6.25'
    $desired = [int]$ctx.LookbackDays
    $max     = [int]$ctx.MaxLookbackDays

    $ctx.EffectiveLookbackDays = $desired

    $azure = $false
    if ($ctx.Connections -and $ctx.Connections.Azure) { $azure = $true }

    if (-not $azure) {
        Set-CAInvAzureUnavailable -Reason 'No Azure context.' -Quiet
        New-CAInvRecord -Domain $domain -CheckId 'Evidence-04' -ObjectType 'DiagnosticSettings' `
            -Property 'workspaceDetection' -Status 'Not assessed' `
            -NotAssessedReason ('No Azure context: Log Analytics retention cannot be read, so the requested {0} d window cannot be extended. The effective window falls back to the Graph sign-in retention (see Evidence-05).' -f @($desired)) `
            -GraphSource 'ARM /providers/microsoft.aadiam/diagnosticSettings' -ApiVersion 'n/a' `
            -Recommendation ('Install Az.Accounts and run without -SkipAzure to take advantage of a longer, retention-based window.') | Out-Null
        Write-CAInvGraphRetentionWindow -Desired $desired -Domain $domain
        return
    }

    $token = $null
    try {
        $t = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop
        $token = if ($t.Token -is [System.Security.SecureString]) {
            [System.Net.NetworkCredential]::new('', $t.Token).Password
        } else { $t.Token }
    }
    catch {

        Set-CAInvAzureUnavailable -Reason "Could not obtain an ARM token: $($_.Exception.Message)"
        New-CAInvRecord -Domain $domain -CheckId 'Evidence-04' -ObjectType 'DiagnosticSettings' `
            -Property 'workspaceDetection' -Status 'Not assessed' `
            -NotAssessedReason ('Could not obtain an ARM token: {0}' -f @($_.Exception.Message)) `
            -GraphSource 'ARM' -ApiVersion 'n/a' `
            -Recommendation ('Log in again with an ARM scope: Connect-AzAccount -AuthScope https://management.azure.com/. Without an ARM token, the Log Analytics routes from 6.16 and the method matrix drop out.') | Out-Null
        Write-CAInvGraphRetentionWindow -Desired $desired -Domain $domain
        return
    }

    $azTenant = $null; $azAccount = $null
    $visibleSubs = [System.Collections.Generic.HashSet[string]]::new()
    try { $azc = Get-AzContext -ErrorAction Stop; if ($azc) { $azTenant = $azc.Tenant.Id; $azAccount = $azc.Account.Id } }
    catch { Write-CAInvLog -Level 'DEBUG' -Domain $domain -Message 'Az context not retrievable.' }
    try { foreach ($s in @(Get-AzSubscription -ErrorAction SilentlyContinue)) { [void]$visibleSubs.Add($s.Id) } }
    catch { Write-CAInvLog -Level 'DEBUG' -Domain $domain -Message 'Visible subscriptions not retrievable.' }
    if ($azTenant) { Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Az context: account $azAccount, tenant $azTenant, $($visibleSubs.Count) visible subscription(s)." }

    $dsUri = 'https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview'

    $dsResp = Invoke-CAInvArmRequest -Uri $dsUri -Token $token -Domain $domain
    if (-not $dsResp.Success) {
        New-CAInvRecord -Domain $domain -CheckId 'Evidence-04' -ObjectType 'DiagnosticSettings' `
            -Property 'workspaceDetection' -Status 'Not assessed' `
            -NotAssessedReason ('Diagnostic settings not readable (permissions?): {0}' -f @($dsResp.ErrorMessage)) `
            -GraphSource 'ARM /providers/microsoft.aadiam/diagnosticSettings' -ApiVersion 'n/a' | Out-Null
        Write-CAInvGraphRetentionWindow -Desired $desired -Domain $domain
        return
    }
    $settings = @($dsResp.Response.value)
    Write-CAInvRaw -Domain $domain -Endpoint 'aadiamDiagnosticSettings' -Data $settings | Out-Null

    if ($settings.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Evidence-04' -ObjectType 'DiagnosticSettings' `
            -Property 'workspaceDetection' -ObservedValue 'no diagnostic settings' -Status 'Gap' `
            -GraphSource 'ARM /providers/microsoft.aadiam/diagnosticSettings' -ApiVersion 'n/a' `
            -Recommendation ('Configure Entra diagnostic settings to a Log Analytics workspace for usage analysis over a longer window.') | Out-Null
        Write-CAInvGraphRetentionWindow -Desired $desired -Domain $domain
        return
    }

    $found = [System.Collections.Generic.List[object]]::new()
    $retErrors = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $settings) {
        $wsId = Get-CAInvProp $s 'properties.workspaceId'
        if (-not $wsId) { continue }
        $logs = @(Get-CAInvProp $s 'properties.logs' @())
        $enabledCats = @($logs | Where-Object { $_.enabled } | ForEach-Object { $_.category })
        $rr = Get-CAInvWorkspaceRetention -WorkspaceResourceId $wsId -Token $token -Domain $domain
        if ($rr.Error) {
            $parts = $wsId.Split('/')
            $subId = if ($parts.Length -gt 2) { $parts[2] } else { '?' }
            $subVisible = $visibleSubs.Contains($subId)
            $subNote = if (-not $subVisible) { " [subscription $subId NOT in your Az context — likely another tenant/Lighthouse]" } else { " [subscription $subId visible]" }
            [void]$retErrors.Add("$($parts[-1]): $($rr.Error)$subNote")
        }
        [void]$found.Add([PSCustomObject]@{
            SettingName = Get-CAInvProp $s 'name'
            WorkspaceId = $wsId
            Categories  = $enabledCats
            Retention   = $rr.Retention
            CustomerId  = $rr.CustomerId
        })
    }

    $withRetention = @($found | Where-Object { $null -ne $_.Retention })
    if ($withRetention.Count -eq 0) {
        $errDetail = if ($retErrors.Count -gt 0) { ' Reason: ' + (($retErrors | Select-Object -Unique) -join ' | ') } else { '' }
        $ctxNote = if ($azTenant) { " Az context: tenant $azTenant, account $azAccount, $($visibleSubs.Count) subscription(s) visible." } else { '' }
        New-CAInvRecord -Domain $domain -CheckId 'Evidence-04' -ObjectType 'DiagnosticSettings' `
            -Property 'workspaceDetection' -ObservedValue "$($settings.Count) diagnostic setting(s), $($found.Count) with workspace, no readable retention.$errDetail$ctxNote" `
            -Status 'Review required' -ManualReview `
            -GraphSource 'ARM' -ApiVersion 'n/a' `
            -Recommendation ('If the subscription isn''t in your Az context, the workspace lives in another tenant (e.g. with a SOC partner): log in to that tenant with Connect-AzAccount -Tenant <id>. If the subscription is present, Log Analytics Reader (or Reader) on the workspace is required; RBAC can take up to ~30 min to propagate.') | Out-Null
        Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Workspace retention unreadable.$errDetail"
        Write-CAInvGraphRetentionWindow -Desired $desired -Domain $domain
        return
    }

    $uniqueWorkspaces = @(
        foreach ($g in ($withRetention | Group-Object WorkspaceId)) {
            $first = $g.Group[0]
            [PSCustomObject]@{
                WorkspaceId = $first.WorkspaceId
                Categories  = @($g.Group | ForEach-Object { $_.Categories } | Select-Object -Unique)
                Retention   = $first.Retention
                CustomerId  = $first.CustomerId
            }
        }
    )

    $primaryWorkspaceIdParam = Get-CAInvProp $ctx 'PrimaryWorkspaceId'
    $selection = Resolve-CAInvPrimaryWorkspace -Candidates $uniqueWorkspaces -OverrideWorkspaceId $primaryWorkspaceIdParam
    if ($selection.Primary) {
        Add-CAInvContextData -Context $ctx -Name 'PrimaryLogWorkspace' -Value $selection.Primary
    }

    $bestRetention = ($withRetention | ForEach-Object { $_.Retention } | Measure-Object -Maximum).Maximum
    $win = Get-CAInvEffectiveWindow -Desired $desired -Max $max -DetectedRetention ([int]$bestRetention)
    $ctx.EffectiveLookbackDays = $win.Effective

    New-CAInvRecord -Domain $domain -CheckId 'Evidence-04' -ObjectType 'DiagnosticSettings' `
        -Property 'workspaces' -ObservedValue $selection.ObservedValue -Status $selection.Status `
        -ManualReview:($selection.Status -eq 'Review required') `
        -GraphSource 'ARM /providers/microsoft.aadiam/diagnosticSettings' -ApiVersion 'n/a' `
        -Recommendation $selection.Recommendation | Out-Null

    New-CAInvRecord -Domain $domain -CheckId 'Evidence-05' -ObjectType 'LogWindow' `
        -Property 'effectiveLookbackDays' -ObservedValue "$($win.Effective) d (requested $desired, max $max, retention $bestRetention)" `
        -Status ($(if ($win.Short) { 'Review required' } else { 'Ready' })) `
        -ManualReview:$win.Short `
        -GraphSource 'ARM Log Analytics' -ApiVersion 'n/a' -Recommendation $win.Note | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Log window: effective $($win.Effective) d ($($win.Note))"
}
