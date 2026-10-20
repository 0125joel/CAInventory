function New-CAInvScorecard {
    <#
    .SYNOPSIS
        Report A — readiness scorecard. Colors come from
        New-CAInvReportPalette, the brand bar from New-CAInvReportTopbar.
    .DESCRIPTION
        Aggregates the findings register (no new data). Shows a readiness score, the hard
        preconditions (emergency accounts, license coverage, diagnostic settings) and, per layer,
        the count of controls per status PLUS a coverage percentage: the share of controls that
        were actually assessed (Not assessed doesn't count as 'assessed'). That way a layer
        doesn't turn green on half coverage. The page is self-contained: all records sit as JSON
        in the file, so the counts are click-through-able client-side without external files or
        libraries.
    .OUTPUTS
        String: the HTML content of the scorecard.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ctx = $script:CAInvContext
    $records = @($ctx.Records)

    $pal = New-CAInvReportPalette -As 'Map' -Brand (Get-CAInvProp $ctx 'Brand')
    $INK = $pal.Ink; $CORAL = $pal.Coral; $YELLOW = $pal.Yellow; $GREY = $pal.Grey

    $catalog = $null
    if ($ctx.PSObject.Properties['Config'] -and $ctx.Config -and $ctx.Config.CheckIds) {
        $catalog = $ctx.Config.CheckIds
    }
    else {
        try { $catalog = (Get-CAInvConfig).CheckIds } catch { $catalog = $null }
    }

    $sectionsCfg = $null
    $cfgObj = Get-CAInvProp $ctx 'Config'
    if ($cfgObj -is [hashtable]) {
        if ($cfgObj.ContainsKey('Sections')) { $sectionsCfg = $cfgObj['Sections'] }
    }
    elseif ($cfgObj) {
        $sectionsCfg = Get-CAInvProp $cfgObj 'Sections'
    }
    if (-not $sectionsCfg) {
        try { $sectionsCfg = (Get-CAInvConfig).Sections } catch { $sectionsCfg = $null }
    }
    $sectionByPrefix = @{}
    $sectionOrder = @{}
    foreach ($sec in @($sectionsCfg.sections)) {
        $sectionByPrefix[[string]$sec.prefix] = $sec
        $sectionOrder[[string]$sec.title] = [int]$sec.order
    }

    function Resolve-Section {
        param([string] $CheckId)
        $prefix = ($CheckId -split '-')[0]
        if ($sectionByPrefix.ContainsKey($prefix)) { return [string]$sectionByPrefix[$prefix].title }
        return 'Other'
    }

    function E([string]$s) { ConvertTo-CAInvHtmlSafe -Text $s }

    $orgRec = @($records | Where-Object { $_.CheckId -eq 'Foundation-02' -and $_.ObjectName }) | Select-Object -First 1
    $orgName = if ($orgRec) { [string]$orgRec.ObjectName } else { 'the organization' }

    $months = @('January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December')
    $collectedText = [string]$ctx.CollectedAt
    try {
        $dto = [DateTimeOffset]::Parse([string]$ctx.CollectedAt)
        $collectedText = ('{0} {1} {2}, {3:00}:{4:00}' -f $dto.Day, $months[$dto.Month - 1], $dto.Year, $dto.Hour, $dto.Minute)
    }
    catch {

        Write-CAInvLog -Level 'DEBUG' -Message "Could not parse CollectedAt into a readable date: $($_.Exception.Message)"
    }

    $preconditions = Get-CAInvHardPrecondition -Records $records

    $effWindow = if ($ctx.PSObject.Properties['EffectiveLookbackDays'] -and $ctx.EffectiveLookbackDays) { [int]$ctx.EffectiveLookbackDays } else { [int]$ctx.LookbackDays }

    $readyN = @($records | Where-Object Status -eq 'Ready').Count
    $gapN = @($records | Where-Object Status -eq 'Gap').Count
    $reviewN = @($records | Where-Object Status -eq 'Review required').Count
    $naN = @($records | Where-Object Status -eq 'Not assessed').Count
    $assessed = $readyN + $gapN + $reviewN
    $score = if ($assessed -gt 0) { [math]::Round(100 * $readyN / $assessed) } else { 0 }

    $catalogChecks = @(if ($catalog -and $catalog.checks) { $catalog.checks } else { @() })
    $assessedCheckIds = @($records | Where-Object { $_.Status -in @('Ready', 'Gap', 'Review required') } | Select-Object -ExpandProperty CheckId -Unique)
    $coverage = if ($catalogChecks.Count -gt 0) { [math]::Round(100 * $assessedCheckIds.Count / $catalogChecks.Count) } else { 0 }

    $catalogCountBySection = @{}
    foreach ($c in $catalogChecks) {
        $sec = Resolve-Section ([string]$c.checkId)
        $catalogCountBySection[$sec] = 1 + $(if ($catalogCountBySection.ContainsKey($sec)) { $catalogCountBySection[$sec] } else { 0 })
    }
    $sections = $records | Group-Object { Resolve-Section ([string]$_.CheckId) } |
        Sort-Object { if ($sectionOrder.ContainsKey($_.Name)) { $sectionOrder[$_.Name] } else { 99 } }, Name
    $sectionRows = foreach ($lg in $sections) {
        $recs = @($lg.Group)
        $ready = @($recs | Where-Object Status -eq 'Ready').Count
        $gap = @($recs | Where-Object Status -eq 'Gap').Count
        $review = @($recs | Where-Object Status -eq 'Review required').Count
        $na = @($recs | Where-Object Status -eq 'Not assessed').Count

        $sectionCatalogCount = if ($catalogCountBySection.ContainsKey($lg.Name)) { $catalogCountBySection[$lg.Name] } else { 0 }
        $assessedCheckIdsL = @($recs | Where-Object { $_.Status -in @('Ready', 'Gap', 'Review required') } | Select-Object -ExpandProperty CheckId -Unique).Count
        $cov = if ($sectionCatalogCount -gt 0) { [math]::Round(100 * $assessedCheckIdsL / $sectionCatalogCount) } else { 0 }
        [PSCustomObject]@{ Section = $lg.Name; Ready = $ready; Gap = $gap; Review = $review; NotAssessed = $na; Coverage = $cov }
    }

    $export = [System.Collections.Generic.List[object]]::new()
    $idx = 0
    foreach ($rec in $records) {

        $keyObj = if (-not [string]::IsNullOrWhiteSpace([string]$rec.ObjectId)) { [string]$rec.ObjectId }
                  elseif (-not [string]::IsNullOrWhiteSpace([string]$rec.ObjectName)) { [string]$rec.ObjectName }
                  else { '' }
        $key = ('{0}|{1}|{2}|{3}' -f [string]$rec.TenantId, [string]$rec.CheckId, $keyObj, [string]$rec.Property)
        [void]$export.Add([ordered]@{
                idx           = $idx; key = $key; Layer = $rec.Layer; Category = (Get-CAInvProp $rec 'Category'); CheckId = $rec.CheckId
                Section       = (Resolve-Section ([string]$rec.CheckId))
                ObjectType    = $rec.ObjectType; ObjectName = $rec.ObjectName; Property = $rec.Property
                ObservedValue = [string]$rec.ObservedValue; Status = $rec.Status; Severity = $rec.Severity
                Recommendation = $rec.Recommendation; NotAssessedReason = $rec.NotAssessedReason
                RawPath       = $rec.RawPath; GraphSource = $rec.GraphSource; ApiVersion = $rec.ApiVersion
                ManualReview  = [bool](Get-CAInvProp $rec 'ManualReview' $false)
            })
        $idx++
    }
    $json = if ($export.Count -eq 0) { '[]' } elseif ($export.Count -eq 1) { '[' + ($export[0] | ConvertTo-Json -Depth 5 -Compress) + ']' } else { $export | ConvertTo-Json -Depth 5 -Compress }

    $json = $json -replace '</', '<\/'

    $catExport = [System.Collections.Generic.List[object]]::new()
    if ($catalog -and $catalog.checks) {
        foreach ($c in $catalog.checks) {
            [void]$catExport.Add([ordered]@{ checkId = $c.checkId; title = $c.title; description = $c.description; category = $c.category })
        }
    }
    $catJson = if ($catExport.Count -eq 0) { '[]' } elseif ($catExport.Count -eq 1) { '[' + ($catExport[0] | ConvertTo-Json -Depth 4 -Compress) + ']' } else { $catExport | ConvertTo-Json -Depth 4 -Compress }
    $catJson = $catJson -replace '</', '<\/'

    function CountCell {
        param([int]$Count, [string]$Cls, [string]$Section, [string]$Status)
        if ($Count -gt 0) {
            return "<button class='cnt $Cls' data-section=""$(E $Section)"" data-status=""$(E $Status)"">$Count</button>"
        }
        return "<button class='cnt zero' disabled>0</button>"
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Readiness scorecard · Conditional Access</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine((New-CAInvReportPalette -Surface 'Card' -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine(@'
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--body);font-family:Aileron,'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased;padding:0 0 80px}
a{color:var(--ink);text-decoration:underline;text-underline-offset:2px}a:hover{color:var(--coral)}
input,button,select{font-family:inherit}
.mono{font-family:ui-monospace,Consolas,monospace}
/* nav + footer */
.topbar{background:var(--ink);color:#fff;padding:14px 48px;display:flex;align-items:baseline;justify-content:space-between;gap:24px}
.brand{display:flex;align-items:baseline;gap:10px}
.brand .arrow{color:var(--yellow);font-size:18px;font-weight:700;line-height:1}
.brand .name{font-size:17px;font-weight:700;letter-spacing:-.01em}
.topbar .tag{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--tabmuted)}
.footbar{background:var(--ink);color:#fff;padding:36px 64px;display:flex;justify-content:space-between;align-items:baseline;gap:32px;flex-wrap:wrap}
.footbar .l{display:flex;align-items:baseline;gap:10px;font-size:14px}
.footbar .arrow{color:var(--yellow);font-size:16px;font-weight:700}
.footbar .r{font-size:12px;color:var(--tabmuted)}
/* container */
.page{max-width:1180px;margin:0 auto;background:var(--card)}
.sec{padding:48px 64px;border-bottom:1px solid var(--line)}
.sec:last-of-type{border-bottom:0}
.eyebrow{font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:var(--coral);font-weight:700;margin-bottom:18px}
h1{font-size:44px;line-height:1.08;font-weight:700;color:var(--ink);margin:0 0 10px;max-width:22em;letter-spacing:-.02em}
.lead{margin:0;max-width:44em;font-size:17px;color:var(--body)}
.sechead{display:flex;align-items:baseline;gap:14px;margin-bottom:6px}
.sechead .no{font-size:12px;font-weight:700;color:var(--coral);letter-spacing:.14em}
h2{font-size:26px;font-weight:700;color:var(--ink);margin:0;letter-spacing:-.015em}
.sec p.intro{margin:0 0 24px;max-width:46em}
/* header meta */
.header{padding:56px 64px 40px;border-bottom:3px solid var(--ink)}
.meta{display:grid;grid-template-columns:repeat(5,1fr);border-top:1px solid var(--line);margin-top:36px}
.meta .cell{padding:14px 20px;border-right:1px solid var(--line)}
.meta .cell:first-child{padding-left:0}.meta .cell:last-child{border-right:0;padding-right:0}
.meta .k{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:4px}
.meta .v{font-size:14px;color:var(--ink)}
.meta .v.mono{font-size:12.5px;word-break:break-all}
.meta .sub{color:var(--muted)}
/* score */
.score{display:grid;grid-template-columns:minmax(260px,340px) 1fr;gap:56px;align-items:start}
.score .lbl{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:8px}
.score .big{display:flex;align-items:baseline;gap:6px}
.score .num{font-size:104px;line-height:.86;font-weight:700;color:var(--ink);letter-spacing:-.04em;font-variant-numeric:tabular-nums}
.score .den{font-size:22px;font-weight:700;color:var(--muted)}
.track{height:10px;background:var(--bg);margin-top:22px}.track>span{display:block;height:100%;background:var(--yellow)}
.score .cap{font-size:13px;color:var(--muted);margin-top:10px}
.golive{display:inline-flex;align-items:center;gap:8px;margin-top:18px;font-size:13px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:8px 14px}
.golive .godot{width:9px;height:9px;border-radius:50%;display:block;flex-shrink:0}
.golive.ready{background:var(--tint);color:var(--ink);border:1px solid var(--ink)}
.golive.ready .godot{background:var(--ink)}
.golive.notready{background:var(--tint);color:var(--coral);border:1px solid var(--coral)}
.golive.notready .godot{background:var(--coral)}
.goreasons{margin:8px 0 0;padding-left:18px;font-size:13px;color:var(--body)}
.goreasons li{margin-bottom:3px}
.score h2{font-size:22px;margin:0 0 12px}
.score .explain{margin:0 0 18px;max-width:46em}
.totals{display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--line)}
.totals .t{padding:16px 18px 16px 0}
.totals .row{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.totals .sw{width:10px;height:10px;display:block}
.totals .tl{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.totals .tc{font-size:32px;font-weight:700;color:var(--ink);font-variant-numeric:tabular-nums;line-height:1}
.cid{font-family:ui-monospace,Consolas,monospace;font-size:11.5px;color:var(--muted);letter-spacing:.04em}
.sev{display:flex;align-items:center;gap:6px}.sev .sw{width:8px;height:8px;display:block}
/* tables */
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);font-weight:700;padding:0 16px 10px;border-bottom:2px solid var(--ink)}
th:first-child{padding-left:0}th:last-child{padding-right:0}
td{padding:15px 16px;border-bottom:1px solid var(--line)}
td:first-child{padding-left:0}td:last-child{padding-right:0}
tr.clickable{cursor:pointer}tr.clickable:hover td{background:var(--tint)}
td.name,.pre td.name{font-weight:700;color:var(--ink)}
.status{display:flex;align-items:center;gap:8px;font-weight:700}.status .sw{width:10px;height:10px;display:block}
.status.ok{color:var(--ink)}.status.att{color:var(--coral)}
td.num{text-align:right}
.cnt{background:transparent;border:0;padding:2px 0;font-size:15px;font-variant-numeric:tabular-nums;cursor:pointer;border-bottom:1px solid transparent}
.cnt.ready{color:var(--ink)}.cnt.gap{color:var(--coral)}.cnt.review{color:var(--review)}.cnt.na{color:var(--body)}
.cnt.zero{color:var(--grey);cursor:default}
.cnt:not(.zero):hover{border-bottom-color:var(--ink)}
.cov{display:flex;align-items:center;gap:10px}
.covtrack{height:8px;width:110px;background:var(--bg);display:block}.covtrack>span{display:block;height:100%;background:var(--ink)}
.covpct{font-size:13px;color:var(--muted);font-variant-numeric:tabular-nums}
/* drawer */
#overlay{position:fixed;inset:0;background:rgba(28,8,42,.45);opacity:0;pointer-events:none;transition:opacity .18s;z-index:10}
#overlay.open{opacity:1;pointer-events:auto}
#drawer{position:fixed;top:0;right:0;height:100%;width:min(720px,94vw);background:#fff;border-left:3px solid var(--yellow);transform:translateX(100%);transition:transform .2s;z-index:11;display:flex;flex-direction:column}
#drawer.open{transform:translateX(0)}
.dhead{background:var(--ink);color:#fff;padding:22px 28px;display:flex;align-items:flex-start;gap:16px}
.dhead .eb{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--yellow);margin-bottom:4px}
.dhead h3{margin:0;font-size:20px;font-weight:700;letter-spacing:-.01em}
.dhead .sub{font-size:13px;color:var(--tabmuted);margin-top:3px}
#dclose{margin-left:auto;background:transparent;border:1px solid #6B4B8F;color:#fff;font-size:18px;line-height:1;padding:6px 11px;cursor:pointer}
.dfilterbar{padding:14px 28px;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.dfilterbar input{flex:1;min-width:200px;padding:9px 12px;border:1px solid var(--grey);background:#fff;color:var(--body);font-size:14px}
.chip{border:1px solid var(--ink);padding:7px 13px;font-size:13px;cursor:pointer;background:#fff;color:var(--ink)}
.chip.active{background:var(--ink);color:#fff}
#dlist{overflow:auto;padding:20px 28px 48px;flex:1}
.dcard{border-top:1px solid var(--line);padding:18px 0}
.dtop{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}
.dtop .sev{font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
.dtop .stpill{font-size:12px;padding:3px 9px;background:var(--bg);color:var(--ink);font-weight:700}
.dtop .dt{font-weight:700;color:var(--ink)}
.dkv{margin:3px 0;font-size:14px}.dkv .k{color:var(--muted)}
.dkv .mono{font-size:12.5px;word-break:break-word}
.advice{margin-top:10px;border-left:3px solid var(--yellow);background:var(--tint);padding:10px 14px;font-size:14px}
.empty{color:var(--muted);padding:18px 0}
/* beslissingen (confirm/dismiss) */
.dcard.decided-confirmed{border-left:3px solid var(--ink);padding-left:14px;margin-left:-14px}
.dcard.decided-dismissed{border-left:3px solid var(--grey);padding-left:14px;margin-left:-14px;opacity:.7}
.dcard.decided-resolved{border-left:3px solid var(--yellow);padding-left:14px;margin-left:-14px}
.decide{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:12px}
.decide .db{border:1px solid var(--grey);background:#fff;color:var(--body);padding:6px 13px;font-size:13px;font-weight:700;cursor:pointer}
.decide .db:hover{border-color:var(--ink);color:var(--ink)}
.decide .db.on-confirm{background:var(--ink);border-color:var(--ink);color:#fff}
.decide .db.on-dismiss{background:var(--grey);border-color:var(--grey);color:#fff}
.decide .db.on-resolve{background:var(--yellow);border-color:var(--yellow);color:var(--ink)}
.decide .dwhen{font-size:12.5px;color:var(--muted)}
.decide .changed{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--coral);border:1px solid var(--coral);padding:2px 7px}
.decidebar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:12px 0 4px;font-size:13px;color:var(--muted)}
.decidebar .dbtn{background:transparent;border:0;border-bottom:1px solid var(--ink);color:var(--ink);padding:0 0 1px;font-size:13px;cursor:pointer}
.decidebar .dbtn:hover{color:var(--coral);border-bottom-color:var(--coral)}
@media (max-width:760px){
  .topbar,.footbar{padding-left:24px;padding-right:24px}
  .header{padding:36px 24px 28px}.sec{padding:32px 24px}
  h1{font-size:32px}
  .meta,.score,.totals{grid-template-columns:1fr}
  .meta .cell{border-right:0;border-bottom:1px solid var(--line);padding-left:0}
  .score{gap:32px}
}
</style></head><body>
'@)

    [void]$sb.AppendLine((New-CAInvReportTopbar -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine('<div class="page">')

    [void]$sb.AppendLine('<div class="header">')
    [void]$sb.AppendLine('<div class="eyebrow">Pre-implementation inventory &middot; Conditional Access</div>')
    [void]$sb.AppendLine("<h1>Readiness scorecard for $(E $orgName)</h1>")
    [void]$sb.AppendLine('<p class="lead">This report shows what is ready for the new Conditional Access rollout, what to fix first, and which checks still need a human. The counts are click-through: every finding is backed by the evidence behind it.</p>')
    [void]$sb.AppendLine('<div class="meta">')
    [void]$sb.AppendLine("<div class=""cell""><div class=""k"">Tenant</div><div class=""v mono"">$(E $ctx.TenantId)</div></div>")
    [void]$sb.AppendLine("<div class=""cell""><div class=""k"">Run</div><div class=""v mono"">$(E $ctx.RunId)</div></div>")
    [void]$sb.AppendLine("<div class=""cell""><div class=""k"">Collected</div><div class=""v"">$(E $collectedText)</div></div>")
    $logWinTxt = if ($effWindow -ne [int]$ctx.LookbackDays) { "$effWindow days <span class='sub'>(requested $($ctx.LookbackDays))</span>" } else { "$effWindow days" }
    [void]$sb.AppendLine("<div class=""cell""><div class=""k"">Log window</div><div class=""v"">$logWinTxt</div></div>")
    [void]$sb.AppendLine('</div></div>')

    $goLive = Get-CAInvGoLiveStatus -Records $records
    $goLiveCls = if ($goLive.Ready) { 'golive ready' } else { 'golive notready' }
    $goLiveTxt = if ($goLive.Ready) { 'Ready for go-live' } else { 'Not yet ready for go-live' }

    $unmeasuredSet = [System.Collections.Generic.HashSet[string]]::new([string[]]@($goLive.UnmeasuredReasons), [System.StringComparer]::Ordinal)
    $goLiveReasons = if ($goLive.Reasons.Count -gt 0) {
        '<ul class="goreasons" id="goreasons">' + (($goLive.Reasons | ForEach-Object {
                    $cls = if ($unmeasuredSet.Contains([string]$_)) { ' class="unmeasured"' } else { '' }
                    "<li$cls>$(E $_)</li>"
                }) -join '') + '</ul>'
    } else { '<ul class="goreasons" id="goreasons"></ul>' }

    $goLiveSync = [PSCustomObject]@{
        tenantId       = [string]$ctx.TenantId
        otherReasons   = @($goLive.Reasons.Count - $goLive.UnmeasuredReasons.Count)[0]
        unmeasuredKeys = @(@($goLive.Unmeasured) | ForEach-Object { [string]$_.Key })
    }
    $goLiveSyncJson = ($goLiveSync | ConvertTo-Json -Depth 5 -Compress) -replace '</', '<\/'

    [void]$sb.AppendLine('<div class="sec"><div class="score">')
    [void]$sb.AppendLine('<div><div class="lbl">Readiness</div>')
    [void]$sb.AppendLine("<div class=""big""><span class=""num"">$score</span><span class=""den"">/100</span></div>")
    [void]$sb.AppendLine("<div class=""track""><span style=""width:$score%""></span></div>")
    [void]$sb.AppendLine("<div class=""cap"" title=""Coverage is the share of checks we could reach a verdict on (Ready + Gap + Review required), not how many of those are already OK."">$($assessedCheckIds.Count) of $($catalogChecks.Count) checks assessed &middot; coverage $coverage% <em>(measurement reach, not readiness)</em></div>")
    [void]$sb.AppendLine("<div id=""golive"" class=""$goLiveCls""><span class=""godot""></span><span id=""golivetxt"">$goLiveTxt</span></div>$goLiveReasons</div>")
    [void]$sb.AppendLine('<script id="golive-sync-data" type="application/json">')
    [void]$sb.AppendLine($goLiveSyncJson)
    [void]$sb.AppendLine('</script>')
    [void]$sb.AppendLine('<div><h2>What this score means</h2>')
    [void]$sb.AppendLine('<p class="explain">The score only counts a check that is actually ready: a gap does not count, and a check that still needs a human verdict (Review required) does not count either, in a zero-trust spirit &mdash; not confirmed is not trusted. Checks we could not measure are left out of the score and shown separately as <em>not assessed</em>. Coverage is a separate number: it shows how many checks we could assess (regardless of outcome), not how ready the tenant is.</p>')
    [void]$sb.AppendLine('<div class="totals">')
    $totalsDef = @(
        @{ L = 'Ready'; N = $readyN; C = $INK; P = '' }
        @{ L = 'Gap'; N = $gapN; C = $CORAL; P = 'gap' }
        @{ L = 'Review required'; N = $reviewN; C = $YELLOW; P = 'review' }
        @{ L = 'Not assessed'; N = $naN; C = $GREY; P = '' }
    )
    foreach ($t in $totalsDef) {

        $prog = if ($t.P) { "<div class=""tprog"" id=""prog-$($t.P)"" style=""font-size:12px;color:var(--muted);margin-top:4px;min-height:1em""></div>" } else { '' }
        [void]$sb.AppendLine("<div class=""t""><div class=""row""><span class=""sw"" style=""background:$($t.C)""></span><span class=""tl"">$(E $t.L)</span></div><div class=""tc"">$($t.N)</div>$prog</div>")
    }
    [void]$sb.AppendLine('</div></div></div></div>')

    $precChecks = @{
        'Break-glass accounts found'       = 'Emergency-01,Emergency-02,Emergency-03,Emergency-04,Emergency-05,Emergency-06'
        'Entra ID P1 (CA licensable)'      = 'Foundation-01'
        'Permanent Global Admins'          = 'Identity-09,Identity-10'
        'Diagnostic settings / log window' = 'Evidence-04,Evidence-05'
        'Security defaults off'            = 'Foundation-03'
    }
    [void]$sb.AppendLine('<div class="sec"><div class="sechead"><span class="no">01</span><h2>Hard preconditions</h2></div>')
    [void]$sb.AppendLine('<p class="intro">Five conditions that need to be settled before you start enforcing policy. Where it says <em>attention</em>, that is where you start.</p>')
    [void]$sb.AppendLine('<table class="pre"><tr><th>Precondition</th><th>Observation</th><th style="width:150px">Status</th></tr>')
    foreach ($pc in $preconditions) {
        $stCls = if ($pc.Ok) { 'ok' } else { 'att' }
        $stTxt = if ($pc.Ok) { 'OK' } else { 'Attention' }
        $swC = if ($pc.Ok) { $INK } else { $CORAL }
        $checks = [string]$precChecks[$pc.Label]
        $rowAttr = if ($checks) { " class='clickable' data-checks=""$(E $checks)"" data-title=""$(E $pc.Label)""" } else { '' }
        [void]$sb.AppendLine("<tr$rowAttr><td class='name'>$(E $pc.Label)</td><td>$(E ([string]$pc.Value))</td><td><span class='status $stCls'><span class='sw' style='background:$swC'></span>$stTxt</span></td></tr>")
    }
    [void]$sb.AppendLine('</table></div>')

    $caStateRecs = @($records | Where-Object { $_.CheckId -eq 'Foundation-06' -and $_.Property -eq 'state' })
    $mgdRecs = @($records | Where-Object { $_.CheckId -eq 'Foundation-10' -and $_.ObjectType -eq 'ConditionalAccessPolicy' })
    if ($caStateRecs.Count -gt 0) {
        $mgdCount = @($mgdRecs | Select-Object -ExpandProperty ObjectId -Unique).Count
        $ownCount = [Math]::Max(0, $caStateRecs.Count - $mgdCount)
        [void]$sb.AppendLine('<div class="sec"><div class="sechead"><span class="no">02</span><h2>Who manages the policy</h2></div>')
        [void]$sb.AppendLine("<p class=""intro"">Of the $($caStateRecs.Count) Conditional Access policies in this tenant, <strong>$ownCount</strong> were set up by the organization itself and <strong>$mgdCount</strong> were delivered by the vendor. Microsoft-managed policies can't be renamed or deleted; you can only change the state and the exclusions. If left in report-only, Microsoft turns them on by itself no less than thirty days after introduction.</p>")
        if ($mgdCount -gt 0) {
            [void]$sb.AppendLine('<table><tr><th>Vendor-managed policy</th><th style="width:190px">State</th><th style="width:150px">Status</th></tr>')
            foreach ($m in $mgdRecs) {
                $mSt = [string]$m.Status
                $mCls = switch ($mSt) { 'Gap' { 'att' } 'Review required' { 'att' } default { 'ok' } }
                $mSw = switch ($mSt) { 'Gap' { $CORAL } 'Review required' { $YELLOW } default { $INK } }
                $mTxt = switch ($mSt) { 'Gap' { 'Attention' } 'Review required' { 'Review' } default { 'OK' } }

                $stateTxt = if ("$($m.ObservedValue)" -match ',\s*state ([^.]+)\.') { $Matches[1] } else { 'unknown' }
                [void]$sb.AppendLine("<tr class='clickable' data-checks=""Foundation-10"" data-title=""$(E ([string]$m.ObjectName))""><td class='name'>$(E ([string]$m.ObjectName))</td><td>$(E $stateTxt)</td><td><span class='status $mCls'><span class='sw' style='background:$mSw'></span>$mTxt</span></td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }
        [void]$sb.AppendLine('</div>')
    }

    [void]$sb.AppendLine('<div class="sec"><div class="sechead"><span class="no">03</span><h2>By section</h2></div>')
    [void]$sb.AppendLine('<p class="intro">The inventory is grouped by what you need to arrange, in the order in which you arrange it: emergency access first, management and sustainability last. Coverage is the share of checks we actually ran. Click a count for the findings behind it.</p>')
    [void]$sb.AppendLine('<table><tr><th>Section</th><th class="num" style="width:90px">Ready</th><th class="num" style="width:90px">Gap</th><th class="num" style="width:90px">Review</th><th class="num" style="width:120px">Not assessed</th><th style="width:190px">Coverage</th></tr>')
    foreach ($r in $sectionRows) {
        $cReady = CountCell -Count $r.Ready -Cls 'ready' -Section $r.Section -Status 'Ready'
        $cGap = CountCell -Count $r.Gap -Cls 'gap' -Section $r.Section -Status 'Gap'
        $cReview = CountCell -Count $r.Review -Cls 'review' -Section $r.Section -Status 'Review required'
        $cNa = CountCell -Count $r.NotAssessed -Cls 'na' -Section $r.Section -Status 'Not assessed'
        $intro = if ($sectionByPrefix.Values | Where-Object { $_.title -eq $r.Section }) {
            [string](@($sectionByPrefix.Values | Where-Object { $_.title -eq $r.Section })[0].intro)
        } else { '' }
        $nameCell = if ($intro) { "$(E $r.Section)<div style='font-size:12px;color:var(--muted);font-weight:400'>$(E $intro)</div>" } else { E $r.Section }
        [void]$sb.AppendLine("<tr><td class='name'>$nameCell</td><td class='num'>$cReady</td><td class='num'>$cGap</td><td class='num'>$cReview</td><td class='num'>$cNa</td><td><span class='cov'><span class='covtrack'><span style='width:$($r.Coverage)%'></span></span><span class='covpct'>$($r.Coverage)%</span></span></td></tr>")
    }
    [void]$sb.AppendLine('</table></div>')

    [void]$sb.AppendLine((New-CAInvReportFooter -RunId $ctx.RunId -IncludePrintLink -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<div id="overlay"></div><aside id="drawer" aria-hidden="true"><div class="dhead"><div style="flex:1;min-width:0"><div class="eb">Findings</div><h3 id="dtitle">Findings</h3><div class="sub" id="dsub"></div></div><button id="dclose" aria-label="Close">&times;</button></div><div class="dfilterbar"><input id="dfilter" type="search" placeholder="Filter within this list"><div id="dfacets" style="display:flex;gap:10px;flex-wrap:wrap"></div></div><div class="decidebar" id="decidebar"><button class="chip" id="hidedecided" type="button">Hide reviewed</button><button class="chip" id="hidemanual" type="button" title="Hide findings that can only be judged by a human (no technically provable gap)">Hide &quot;manual review&quot;</button><span style="flex:1"></span><button class="dbtn" id="btnexport" type="button">Export decisions</button><button class="dbtn" id="btnimport" type="button">Import</button><input id="fileimport" type="file" accept="application/json,.json" style="display:none"></div><div id="dlist"></div></aside>')
    [void]$sb.AppendLine("<script>window.__CAINV_TENANT=""$(E $ctx.TenantId)"";</script>")
    [void]$sb.AppendLine('<script id="findings-data" type="application/json">')
    [void]$sb.AppendLine($json)
    [void]$sb.AppendLine('</script>')
    [void]$sb.AppendLine('<script id="checks-data" type="application/json">')
    [void]$sb.AppendLine($catJson)
    [void]$sb.AppendLine('</script>')
    [void]$sb.AppendLine('<script>')
    [void]$sb.AppendLine('(function(){')
    [void]$sb.AppendLine((New-CAInvReportPalette -As 'Script' -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine(@'
  var DATA = JSON.parse(document.getElementById('findings-data').textContent);
  var CHECKS = JSON.parse(document.getElementById('checks-data').textContent);
  var CMAP={}; CHECKS.forEach(function(c){ CMAP[c.checkId]=c; });
  var SEV_COLOR={High:CORAL,Medium:YELLOW,Low:GREY,Info:GREY};
  var SEV_ORDER={High:0,Medium:1,Low:2,Info:3};
  var STATUS_LABEL={'Ready':'Ready','Gap':'Gap','Review required':'Review','Not assessed':'Not assessed'};
  var STATE_LABEL={'confirmed':'Confirmed','dismissed':'Accepted','resolved':'Resolved'};
  var overlay=document.getElementById('overlay'), drawer=document.getElementById('drawer');
  var dtitle=document.getElementById('dtitle'), dsub=document.getElementById('dsub');
  var dlist=document.getElementById('dlist'), dfilter=document.getElementById('dfilter'), dfacets=document.getElementById('dfacets');
  var current=[], fSev=new Set(), hideDecided=false, hideManual=false;

  // --- Decisions (confirmed/dismissed/resolved), client-side in localStorage ---------------
  // Keyed on finding identity (r.key), so a new run reads the same decisions back in.
  // 'confirmed' = seen and acknowledged, still blocks the wave gate in the rollout plan.
  // 'dismissed' = accepted risk, may be ignored, no longer blocks the wave gate.
  // 'resolved'  = actually resolved, counts as Done in the wave gate. The rollout plan tab
  // reads the same localStorage key (cainv-decisions:{tenant}) and recomputes client-side.
  var TENANT = window.__CAINV_TENANT || '';
  var STORE_KEY = 'cainv-decisions:' + TENANT;
  var decisions = {};
  try { decisions = JSON.parse(localStorage.getItem(STORE_KEY) || '{}') || {}; } catch(e){ decisions = {}; }
  function persist(){ try { localStorage.setItem(STORE_KEY, JSON.stringify(decisions)); } catch(e){} }

  // --- Criterion 4 of the go-live gate, client-side -------------------------------------------
  // Conditions with no measurement at all always keep the gate closed server-side: PowerShell
  // doesn't see the checkbox decisions, because those live here in the browser. The rollout
  // plan lets them be confirmed and writes that to the same store. Here we factor those
  // confirmations in, so the gate moves along without the findings record carrying a softer
  // verdict than it has coverage for.
  function recomputeGoLive(){
    var raw = document.getElementById('golive-sync-data');
    if (!raw) return;
    var G; try { G = JSON.parse(raw.textContent); } catch(e) { return; }
    var keys = G.unmeasuredKeys || [];
    if (!keys.length) return;
    var pending = keys.filter(function(k){ var d = decisions[k]; return !(d && d.state === 'resolved'); });
    var ul = document.getElementById('goreasons');
    var badge = document.getElementById('golive');
    var txt = document.getElementById('golivetxt');
    if (!ul || !badge || !txt) return;

    var lis = ul.querySelectorAll('li.unmeasured');
    Array.prototype.forEach.call(lis, function(li){ li.hidden = (pending.length === 0); });
    if (pending.length > 0 && pending.length < keys.length) {
      Array.prototype.forEach.call(lis, function(li){
        if (!li.dataset.orig) li.dataset.orig = li.textContent;
        li.textContent = li.dataset.orig + ' ' + pending.length + ' of ' + keys.length + ' still to confirm in the rollout plan.';
      });
    }

    // The badge may only flip when criterion 4 was the only remaining objection.
    if ((G.otherReasons || 0) === 0) {
      var ok = (pending.length === 0);
      badge.className = 'golive ' + (ok ? 'ready' : 'notready');
      txt.textContent = ok ? 'Ready for go-live, after your manual confirmations' : 'Not yet ready for go-live';
    }
  }
  function isDecidable(r){ return r.Status==='Review required' || r.Status==='Gap'; }
  function getDecision(key){ return decisions[key] || null; }
  function setDecision(r, state){
    var cur = decisions[r.key];
    if (cur && cur.state===state){ delete decisions[r.key]; }   // clicking again = clear
    else { decisions[r.key] = { state:state, at:new Date().toISOString(), observedAtDecision:(r.ObservedValue==null?'':String(r.ObservedValue)) }; }
    persist(); paint(); refreshCounters(); recomputeGoLive();
  }
  var MONTHS=['January','February','March','April','May','June','July','August','September','October','November','December'];
  function fmtDate(iso){ try{ var d=new Date(iso); return d.getDate()+' '+MONTHS[d.getMonth()]; }catch(e){ return ''; } }
  function decidableList(list){ return list.filter(isDecidable); }
  function openCount(list){ return decidableList(list).filter(function(r){ return !getDecision(r.key); }).length; }

  function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function kv(label,val,mono){ if(val==null||val==='')return ''; return '<div class="dkv"><span class="k">'+esc(label)+'</span> <span'+(mono?' class="mono"':'')+'>'+esc(val)+'</span></div>'; }
  function cardHtml(r){
    var sev=r.Severity||'Info'; var c=CMAP[r.CheckId]||{};
    var source=(r.GraphSource||'n/a')+(r.RawPath?('  ·  evidence '+r.RawPath):'');
    var advice=r.Recommendation||r.NotAssessedReason||'Recorded as context, no action needed.';
    var dec=isDecidable(r)?getDecision(r.key):null;
    var cls='dcard'+(dec?(' decided-'+dec.state):'');
    var h='<div class="'+cls+'"><div class="dtop">';
    h+='<span class="sev"><span class="sw" style="width:9px;height:9px;display:inline-block;background:'+SEV_COLOR[sev]+'"></span> '+esc(sev)+'</span>';
    h+='<span class="stpill">'+esc(STATUS_LABEL[r.Status]||r.Status)+'</span>';
    h+='<span class="dt">'+esc(c.title||r.CheckId)+'</span><span class="cid">'+esc(r.CheckId)+'</span></div>';
    h+=kv('Object',r.ObjectName||'tenant-wide',false);
    h+=kv(r.Property||'Value',r.ObservedValue,true);
    h+=kv('Source',source,true);
    h+='<div class="advice">'+esc(advice)+'</div>';
    if(isDecidable(r)){
      var conf=dec&&dec.state==='confirmed', dism=dec&&dec.state==='dismissed', res=dec&&dec.state==='resolved';
      var changed = dec && dec.observedAtDecision!=null && String(dec.observedAtDecision)!==String(r.ObservedValue==null?'':r.ObservedValue);
      h+='<div class="decide" data-key="'+esc(r.key)+'">';
      h+='<button class="db'+(conf?' on-confirm':'')+'" data-act="confirmed" title="Seen, gap confirmed. Still blocks the wave gate.">Confirmed</button>';
      h+='<button class="db'+(dism?' on-dismiss':'')+'" data-act="dismissed" title="Accepted risk, can be ignored. No longer blocks the wave gate.">Accepted</button>';
      h+='<button class="db'+(res?' on-resolve':'')+'" data-act="resolved" title="Actually resolved. Counts as Ready in the wave gate.">Resolved</button>';
      if(dec){ h+='<span class="dwhen">'+(STATE_LABEL[dec.state]||dec.state)+' on '+esc(fmtDate(dec.at))+'</span>'; }
      if(changed){ h+='<span class="changed" title="The observation changed since you reviewed this finding">changed since review</span>'; }
      h+='</div>';
    }
    h+='</div>';
    return h;
  }
  function buildFacets(){
    var sev={}; current.forEach(function(r){ sev[r.Severity]=(sev[r.Severity]||0)+1; });
    var keys=Object.keys(sev).sort(function(a,b){return (SEV_ORDER[a]||9)-(SEV_ORDER[b]||9);});
    if(keys.length<2){ dfacets.innerHTML=''; return; }
    dfacets.innerHTML=keys.map(function(k){ return '<button class="chip'+(fSev.has(k)?' active':'')+'" data-val="'+esc(k)+'">'+esc(k)+' ('+sev[k]+')</button>'; }).join('');
    dfacets.querySelectorAll('.chip').forEach(function(ch){
      ch.addEventListener('click',function(){ var v=ch.dataset.val; if(fSev.has(v))fSev.delete(v); else fSev.add(v); ch.classList.toggle('active'); paint(); });
    });
  }
  function paint(){
    var q=(dfilter.value||'').toLowerCase();
    var list=current.filter(function(r){
      if(fSev.size && !fSev.has(r.Severity)) return false;
      if(hideDecided && isDecidable(r) && getDecision(r.key)) return false;
      if(hideManual && r.ManualReview) return false;
      if(!q) return true;
      var c=CMAP[r.CheckId]||{};
      return [r.CheckId,c.title,c.description,r.ObjectName,r.Property,r.ObservedValue,r.Recommendation,r.NotAssessedReason,r.Category].join(' ').toLowerCase().indexOf(q)>=0;
    });
    list.sort(function(a,b){ return (SEV_ORDER[a.Severity]||9)-(SEV_ORDER[b.Severity]||9); });
    var open=openCount(current), decN=decidableList(current).length;
    var sub=list.length+' of '+current.length+' finding'+(current.length===1?'':'s');
    if(decN>0){ sub+=' · '+open+' still to review'; }
    dsub.textContent=sub;
    // Only show the decide bar (hide/export/import) when there are decidable items.
    var db=document.getElementById('decidebar'); if(db){ db.style.display = decN>0 ? '' : 'none'; }
    var hb=document.getElementById('hidedecided'); if(hb){ hb.classList.toggle('active',hideDecided); }
    var hm=document.getElementById('hidemanual');
    if(hm){
      hm.classList.toggle('active',hideManual);
      hm.style.display = current.some(function(r){return r.ManualReview;}) ? '' : 'none';
    }
    dlist.innerHTML = list.length ? list.map(cardHtml).join('') : '<div class="empty">No findings match this filter.</div>';
  }
  function openFindings(list,title){ current=list; dtitle.textContent=title; fSev.clear(); dfilter.value=''; buildFacets(); paint(); overlay.classList.add('open'); drawer.classList.add('open'); drawer.setAttribute('aria-hidden','false'); dfilter.focus(); }
  function close(){ overlay.classList.remove('open'); drawer.classList.remove('open'); drawer.setAttribute('aria-hidden','true'); }
  document.getElementById('dclose').onclick=close;
  overlay.onclick=close;
  document.addEventListener('keydown',function(e){ if(e.key==='Escape') close(); });
  dfilter.addEventListener('input',paint);

  document.querySelectorAll('button.cnt:not(.zero)').forEach(function(b){
    b.addEventListener('click',function(){ var section=b.dataset.section, status=b.dataset.status; openFindings(DATA.filter(function(r){return r.Section===section && r.Status===status;}), section+' — '+(STATUS_LABEL[status]||status)); });
  });
  document.querySelectorAll('tr.clickable[data-checks]').forEach(function(tr){
    tr.addEventListener('click',function(){ var set=tr.dataset.checks.split(','); openFindings(DATA.filter(function(r){return set.indexOf(r.CheckId)>=0;}), tr.dataset.title||'Findings'); });
  });

  // --- Wiring up decisions ----------------------------------------------------------------
  // Update the progress captions under the score tiles (Gap/Review).
  function refreshCounters(){
    [['gap','Gap'],['review','Review required']].forEach(function(pair){
      var el=document.getElementById('prog-'+pair[0]); if(!el) return;
      var all=DATA.filter(function(r){return r.Status===pair[1];});
      if(!all.length){ el.textContent=''; return; }
      var open=all.filter(function(r){return !getDecision(r.key);}).length;
      el.textContent = open===0 ? ('all '+all.length+' reviewed') : (open+' of '+all.length+' still to review');
    });
  }

  // Confirm/Dismiss clicks via event delegation (cards get re-rendered by paint()).
  dlist.addEventListener('click',function(e){
    var btn=e.target.closest ? e.target.closest('.decide .db') : null; if(!btn) return;
    var wrap=btn.closest('.decide'); if(!wrap) return;
    var key=wrap.getAttribute('data-key');
    var r=DATA.filter(function(x){return x.key===key;})[0]; if(!r) return;
    setDecision(r, btn.getAttribute('data-act'));
  });

  var hb=document.getElementById('hidedecided');
  if(hb){ hb.addEventListener('click',function(){ hideDecided=!hideDecided; paint(); }); }

  var hm=document.getElementById('hidemanual');
  if(hm){ hm.addEventListener('click',function(){ hideManual=!hideManual; paint(); }); }

  var btnExport=document.getElementById('btnexport');
  if(btnExport){ btnExport.addEventListener('click',function(){
    var payload={ tenantId:TENANT, exportedAt:new Date().toISOString(), decisions:decisions };
    var blob=new Blob([JSON.stringify(payload,null,2)],{type:'application/json'});
    var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='review-decisions.json';
    document.body.appendChild(a); a.click(); setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); },0);
  }); }

  var fileImport=document.getElementById('fileimport'), btnImport=document.getElementById('btnimport');
  if(btnImport && fileImport){
    btnImport.addEventListener('click',function(){ fileImport.click(); });
    fileImport.addEventListener('change',function(){
      var f=fileImport.files && fileImport.files[0]; if(!f){ return; }
      var rd=new FileReader();
      rd.onload=function(){
        try{
          var obj=JSON.parse(rd.result); var inc=(obj && obj.decisions) ? obj.decisions : obj;
          Object.keys(inc||{}).forEach(function(k){
            var mine=decisions[k], theirs=inc[k]; if(!theirs || !theirs.state){ return; }
            // Existing decision stays unless the import is demonstrably newer.
            if(!mine || !mine.at || (theirs.at && theirs.at>mine.at)){ decisions[k]=theirs; }
          });
          persist(); paint(); refreshCounters(); recomputeGoLive();
        }catch(err){ alert('Could not read this file as decisions JSON.'); }
        fileImport.value='';
      };
      rd.readAsText(f);
    });
  }

  refreshCounters();
  recomputeGoLive();

  // Live sharing between report pages: see the same
  // explanation in New-CAInvReviewQueue.ps1. A decision made elsewhere (Review required, Rollout
  // plan, Open work) immediately updates the counters, the go-live badge, and any open drawer
  // here.
  window.addEventListener('storage', function(e){
    if (e.key !== STORE_KEY) return;
    try { decisions = JSON.parse(localStorage.getItem(STORE_KEY) || '{}') || {}; } catch(err){ decisions = {}; }
    paint(); refreshCounters(); recomputeGoLive();
  });
})();
</script>
'@)
    [void]$sb.AppendLine('</body></html>')
    Write-CAInvLog -Level 'INFO' -Message 'Scorecard HTML built.'
    return $sb.ToString()
}
