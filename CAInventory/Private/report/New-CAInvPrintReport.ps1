function New-CAInvPrintReport {
    <#
    .SYNOPSIS
        The full report as one printable document, including the decisions made so far.
    .DESCRIPTION
        The five HTML pages are interactive and therefore not printable: reference.html is complete
        without JavaScript and rollout-plan.html mostly is too, but scorecard.html only delivers the
        summary tables (the findings sit in a JSON block that only gets rendered in the drawer) and
        review-queue.html and mfa-methods.html are practically empty without JS. report.html is
        moreover nothing more than an iframe shell; a hidden iframe is not rendered by most print
        engines. Printing those pages therefore produces an empty document, regardless of the print
        CSS.

        This page reverses that relationship, and that is the core of the design: PowerShell puts
        the FULL document statically into the HTML, and JavaScript only does the overlay. Without
        JS the document is complete and readable, just without the decisions. With JS the decisions
        and notes are added, plus the counts. A print page that has to pull its layout from
        JavaScript is exactly what goes wrong when printing.

        THE DECISIONS. Those live exclusively in localStorage under cainv-decisions:{tenantId} and
        never reach PowerShell. Only code running in the browser can therefore know them. This page
        READS that store and never writes to it; decisions are made on the review page. A colleague
        who is forwarded this HTML file sees an empty decisions overview, because localStorage
        doesn't travel along. That's what the import button is for: it reads the same envelope that
        the scorecard and the review page export.

        THE DEPTH SWITCH. Every finding is in the HTML, including the Ready ones. A screen button
        sets a class on body: in 'mode-attention' the Ready blocks are hidden and a summary line is
        shown per check, in 'mode-all' it's exactly the reverse. Purely a CSS switch, so what you
        see on screen is what gets printed.

        The document renders the findings stream plus the decisions, and nothing else. The
        per-user table from mfa-methods.html comes from its own data source and isn't included;
        only its summary is. That table stays in its own HTML page and in the findings register.
    .OUTPUTS
        String: path to reports/report-print.html.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ctx = $script:CAInvContext
    $records = @($ctx.Records)
    $outPath = Join-Path $ctx.Paths.Reports 'report-print.html'

    function E([string]$s) { ConvertTo-CAInvHtmlSafe -Text $s }

    $pal = New-CAInvReportPalette -As 'Map' -Brand (Get-CAInvProp $ctx 'Brand')

    function CfgPart([string] $Name) {
        $cfg = Get-CAInvProp $ctx 'Config'
        $val = $null
        if ($cfg -is [System.Collections.IDictionary]) { if ($cfg.Contains($Name)) { $val = $cfg[$Name] } }
        elseif ($cfg) { $val = Get-CAInvProp $cfg $Name }
        if (-not $val) { try { $val = (Get-CAInvConfig).$Name } catch { $val = $null } }
        return $val
    }

    $catalog = CfgPart 'CheckIds'
    $checkMap = @{}
    if ($catalog -and $catalog.checks) { foreach ($c in $catalog.checks) { $checkMap[[string]$c.checkId] = $c } }
    function CheckProp([string]$id, [string]$prop, [string]$fallback = '') {
        if ($checkMap.ContainsKey($id)) {
            $v = [string](Get-CAInvProp $checkMap[$id] $prop)
            if ($v) { return $v }
        }
        return $fallback
    }

    $sectionsCfg = CfgPart 'Sections'
    $sectionByPrefix = @{}
    $sectionOrder = @{}
    foreach ($sec in @($sectionsCfg.sections)) {
        $sectionByPrefix[[string]$sec.prefix] = $sec
        $sectionOrder[[string]$sec.title] = [int]$sec.order
    }
    function SectionOf([string]$checkId) {
        $prefix = ($checkId -split '-')[0]
        if ($sectionByPrefix.ContainsKey($prefix)) { return [string]$sectionByPrefix[$prefix].title }
        return 'Other'
    }

    $sevOrder = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2; 'Info' = 3 }
    function SevRank([string]$s) { if ($sevOrder.ContainsKey($s)) { return $sevOrder[$s] } return 9 }

    $readyN  = @($records | Where-Object Status -eq 'Ready').Count
    $gapN    = @($records | Where-Object Status -eq 'Gap').Count
    $reviewN = @($records | Where-Object Status -eq 'Review required').Count
    $naN     = @($records | Where-Object Status -eq 'Not assessed').Count
    $assessed = $readyN + $gapN + $reviewN
    $score = if ($assessed -gt 0) { [math]::Round(100 * $readyN / $assessed) } else { 0 }

    $catalogChecks = @(if ($catalog -and $catalog.checks) { $catalog.checks } else { @() })
    $assessedCheckIds = @($records | Where-Object { $_.Status -in @('Ready', 'Gap', 'Review required') } | Select-Object -ExpandProperty CheckId -Unique)
    $coverage = if ($catalogChecks.Count -gt 0) { [math]::Round(100 * $assessedCheckIds.Count / $catalogChecks.Count) } else { 0 }

    $orgRec = @($records | Where-Object { $_.CheckId -eq 'Foundation-02' -and $_.ObjectName }) | Select-Object -First 1
    $orgName = if ($orgRec) { [string]$orgRec.ObjectName } else { 'the organization' }
    $lang = 'en'
    $dateCulture = 'en-US'

    $preconditions = @(Get-CAInvHardPrecondition -Records $records)
    $gate = Get-CAInvGoLiveStatus -Records $records
    $waves = @(Get-CAInvRolloutWaveStatus -WaveConfig (CfgPart 'RolloutWaves') -Records $records)

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!doctype html><html lang="' + $lang + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine("<title>$('CA Inventory &middot; {0}' -f @((E $orgName)))</title>")
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine((New-CAInvReportPalette -Surface 'Print' -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine(@'
*{box-sizing:border-box}
body{margin:0;font-family:Aileron,'Helvetica Neue',Helvetica,Arial,sans-serif;color:var(--text);font-size:11pt;line-height:1.45;background:#fff}
h1{font-size:24pt;margin:0 0 6px;letter-spacing:-.01em;color:var(--ink)}
h2{font-size:15pt;margin:0 0 4px;color:var(--ink);letter-spacing:-.01em}
h3{font-size:12pt;margin:16px 0 4px;color:var(--ink)}
h4{font-size:10.5pt;margin:12px 0 3px}
p{margin:0 0 8px}
table{width:100%;border-collapse:collapse;margin:6px 0 12px;font-size:10pt}
th{text-align:left;border-bottom:2px solid var(--ink);padding:5px 7px;font-size:8.5pt;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
td{border-bottom:1px solid var(--line);padding:5px 7px;vertical-align:top}
.doc{max-width:200mm;margin:0 auto;padding:0 12mm 24mm}
.lead{color:var(--muted);font-size:11pt;max-width:60em}
.muted{color:var(--muted)}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:9pt}
.sw{display:inline-block;width:9px;height:9px;border-radius:2px;vertical-align:middle;margin-right:5px}
.sec{break-before:page;padding-top:6mm}
.sec:first-of-type{break-before:auto}
.cover{text-align:left;padding:30mm 0 0}
.cover .eyebrow{font-size:9pt;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin-bottom:8px}
.cover .score{font-size:64pt;font-weight:700;color:var(--ink);line-height:1}
.cover dl{display:grid;grid-template-columns:42mm 1fr;gap:3px 10px;margin:16px 0 0;font-size:10pt}
.cover dt{color:var(--muted)}
.cover dd{margin:0}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:9.5pt;font-weight:700}
.badge.ok{background:var(--ok);color:#fff}
.badge.no{background:var(--coral);color:#fff}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:10px 0 14px}
.tile{border:1px solid var(--line);border-radius:6px;padding:9px 11px}
.tile .n{font-size:20pt;font-weight:700;color:var(--ink);line-height:1.1}
.tile .l{font-size:9pt;color:var(--muted)}
.st{display:inline-block;padding:1px 7px;border-radius:10px;font-size:8.5pt;font-weight:700;white-space:nowrap}
.st.Ready{background:#E4F4EC;color:#12613F}
.st.Gap{background:#FFE7E7;color:#8C1F1F}
.st.Review{background:#FFF3D1;color:#6B5200}
.st.NotAssessed{background:#EFEDF2;color:#4A4458}
.find{break-inside:avoid;border:1px solid var(--line);border-radius:6px;padding:9px 11px;margin:0 0 7px}
.find .fh{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap;margin-bottom:4px}
.find .obj{font-weight:700}
.find .kv{font-size:9.5pt;margin-top:3px}
.find .kv b{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:8pt;letter-spacing:.05em;display:block}
.find .ev{font-family:ui-monospace,Consolas,monospace;font-size:8.5pt;color:var(--muted);word-break:break-all}
.chk{break-inside:avoid-page;margin:0 0 14px}
.chk .ch{border-bottom:1px solid var(--ink);padding-bottom:3px;margin-bottom:6px}
.chk .cid{font-family:ui-monospace,Consolas,monospace;font-size:9pt;color:var(--muted)}
.chk .ask{background:#FFF7DE;border-left:3px solid var(--yellow);padding:5px 9px;font-size:10pt;margin:0 0 7px}
.dec{margin-top:5px;font-size:9.5pt;border-top:1px dashed var(--line);padding-top:4px}
.dec .lbl{font-weight:700}
.dec .note{font-style:italic;color:var(--muted)}
.rdysum{font-size:10pt;color:var(--muted);margin:0 0 7px}
/* Depth switch: pure CSS, so the screen and the print cannot drift apart. */
body.mode-attention .find[data-status="Ready"]{display:none}
body.mode-all .rdysum{display:none}
.wave{break-inside:avoid;border:1px solid var(--line);border-radius:6px;padding:9px 11px;margin:0 0 8px}
.wave .wh{display:flex;gap:9px;align-items:baseline;margin-bottom:4px}
.wave .wn{font-weight:700;color:var(--ink)}
.toolbar{position:sticky;top:0;z-index:9;background:var(--ink);color:#fff;padding:9px 12mm;display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.toolbar button{border:1px solid rgba(255,255,255,.35);background:transparent;color:#fff;border-radius:5px;padding:5px 11px;font:inherit;font-size:10pt;cursor:pointer}
.toolbar button:hover{background:rgba(255,255,255,.15)}
.toolbar button.on{background:var(--yellow);color:#3a2c00;border-color:transparent;font-weight:700}
.toolbar .sp{flex:1}
.toolbar .hint{font-size:9pt;opacity:.75}
@media print{
  .toolbar{display:none}
  body{font-size:9.5pt}
  .doc{max-width:none;padding:0}
  a{color:inherit;text-decoration:none}
  /* Without this, the severity colors and status badges drop out of the PDF. */
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  thead{display:table-header-group}
  tr,img{break-inside:avoid}
  h2,h3,h4{break-after:avoid}
}
@page{size:A4;margin:16mm 14mm 18mm}
</style>
'@)

    [void]$sb.AppendLine('</head><body class="mode-attention">')

    [void]$sb.AppendLine('<div class="toolbar">' +
        '<button id="btnprint" type="button">' + ('Print to PDF') + '</button>' +
        '<span class="hint">' + ('Depth:') + '</span>' +
        '<button id="mode-att" class="on" type="button">' + ('Everything needing attention') + '</button>' +
        '<button id="mode-all" type="button">' + ('Everything, including what''s fine') + '</button>' +
        '<span class="sp"></span>' +
        '<span class="hint" id="decsum">' + ('loading decisions&hellip;') + '</span>' +
        '<button id="btnimport" type="button">' + ('Import decisions') + '</button>' +
        '<input id="fileimport" type="file" accept="application/json,.json" style="display:none">' +
        '</div>')

    [void]$sb.AppendLine('<div class="doc">')

    $gateCls = if ($gate.Ready) { 'ok' } else { 'no' }
    $gateTxt = if ($gate.Ready) { 'Ready to enable' } else { 'Not ready to enable yet' }
    [void]$sb.AppendLine('<div class="sec cover">')
    [void]$sb.AppendLine('<div class="eyebrow">' + ('Pre-implementation inventory &middot; Conditional Access') + '</div>')
    [void]$sb.AppendLine("<h1>$(E $orgName)</h1>")
    [void]$sb.AppendLine("<div class=""score"">$score<span style=""font-size:20pt"">%</span></div>")
    [void]$sb.AppendLine('<p class="lead">' + ('Share of controls objectively read out and satisfied. Only confirmed controls count: not measured is not fine. Coverage {0}%.' -f @($coverage)) + '</p>')
    [void]$sb.AppendLine("<p><span class=""badge $gateCls"">$gateTxt</span></p>")
    if (@($gate.Reasons).Count -gt 0) {
        [void]$sb.AppendLine('<ul>')
        foreach ($r in @($gate.Reasons)) { [void]$sb.AppendLine("<li>$(E ([string]$r))</li>") }
        [void]$sb.AppendLine('</ul>')
    }
    $nu = (Get-Date).ToString('d MMMM yyyy, HH:mm', [cultureinfo]::GetCultureInfo($dateCulture))
    [void]$sb.AppendLine('<dl>')
    [void]$sb.AppendLine("<dt>$('Tenant')</dt><dd class=""mono"">$(E ([string]$ctx.TenantId))</dd>")
    [void]$sb.AppendLine("<dt>$('Run')</dt><dd class=""mono"">$(E ([string]$ctx.RunId))</dd>")
    [void]$sb.AppendLine("<dt>$('Collected at')</dt><dd>$(E ([string]$ctx.CollectedAt))</dd>")
    [void]$sb.AppendLine("<dt>$('Document created at')</dt><dd>$(E $nu)</dd>")
    [void]$sb.AppendLine("<dt>$('Findings')</dt><dd>$('{0} total &middot; {1} gap, {2} review needed, {3} not assessed, {4} fine' -f @($records.Count, $gapN, $reviewN, $naN, $readyN))</dd>")
    [void]$sb.AppendLine("<dt>$('Selection')</dt><dd id=""cover-mode"">$('Everything needing attention')</dd>")
    [void]$sb.AppendLine('</dl>')
    [void]$sb.AppendLine('<p class="muted" style="margin-top:10mm;font-size:9pt">' + ('The decisions in this document come from the browser in which it was opened. If they were made elsewhere, import the decisions file first.') + '</p>')
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<div class="sec"><h2>' + ('Scorecard') + '</h2>')
    [void]$sb.AppendLine('<div class="tiles">')
    foreach ($t in @(
            @{ N = $readyN;  L = ('Fine') }
            @{ N = $gapN;    L = ('Gap') }
            @{ N = $reviewN; L = ('Review needed') }
            @{ N = $naN;     L = ('Not assessed') })) {
        [void]$sb.AppendLine("<div class=""tile""><div class=""n"">$($t.N)</div><div class=""l"">$(E $t.L)</div></div>")
    }
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<h3>' + ('Hard preconditions') + '</h3>')
    [void]$sb.AppendLine('<p class="lead">' + ('Conditions that must be in place before you start enforcing policy.') + '</p>')
    [void]$sb.AppendLine('<table><tr><th>' + ('Precondition') + '</th><th>' + ('Observation') + '</th><th style="width:26mm">' + ('Status') + '</th></tr>')
    foreach ($pc in $preconditions) {
        $cls = if ($pc.Ok) { 'Ready' } else { 'Gap' }
        $txt = if ($pc.Ok) { 'Fine' } else { 'Attention' }
        [void]$sb.AppendLine("<tr><td>$(E ([string]$pc.Label))</td><td>$(E ([string]$pc.Value))</td><td><span class=""st $cls"">$txt</span></td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h3>' + ('By category') + '</h3>')
    [void]$sb.AppendLine('<table><tr><th>' + ('Category') + '</th><th style="width:18mm">' + ('Fine') + '</th><th style="width:18mm">' + ('Gap') + '</th><th style="width:18mm">' + ('Review') + '</th><th style="width:24mm">' + ('Not assessed') + '</th></tr>')
    $bySection = $records | Group-Object { SectionOf ([string]$_.CheckId) } |
        Sort-Object { if ($sectionOrder.ContainsKey($_.Name)) { $sectionOrder[$_.Name] } else { 99 } }, Name
    foreach ($g in $bySection) {
        $items = @($g.Group)
        [void]$sb.AppendLine("<tr><td>$(E $g.Name)</td><td>$(@($items | Where-Object Status -eq 'Ready').Count)</td><td>$(@($items | Where-Object Status -eq 'Gap').Count)</td><td>$(@($items | Where-Object Status -eq 'Review required').Count)</td><td>$(@($items | Where-Object Status -eq 'Not assessed').Count)</td></tr>")
    }
    [void]$sb.AppendLine('</table></div>')

    [void]$sb.AppendLine('<div class="sec"><h2>' + ('Decisions as of now') + '</h2>')
    [void]$sb.AppendLine('<p class="lead">' + ('The check-off decisions as they stand in this browser at the moment of printing. Confirmed keeps blocking the wave, accepted is a risk accepted, resolved counts as done.') + '</p>')
    [void]$sb.AppendLine('<div id="dectiles" class="tiles"></div>')
    [void]$sb.AppendLine('<div id="dectable"></div></div>')

    [void]$sb.AppendLine('<div class="sec"><h2>' + ('Findings') + '</h2>')
    [void]$sb.AppendLine('<p class="lead">' + ('Grouped by category and within that by control, in the order category, severity, code.') + '</p>')
    foreach ($g in $bySection) {
        [void]$sb.AppendLine("<h3>$(E $g.Name)</h3>")
        $byCheck = @($g.Group) | Group-Object CheckId | Sort-Object `
            @{ Expression = { ($_.Group | ForEach-Object { SevRank ([string]$_.Severity) } | Measure-Object -Minimum).Minimum } },
            @{ Expression = { $_.Name } }
        foreach ($cg in $byCheck) {
            $cid = [string]$cg.Name
            $items = @($cg.Group | Sort-Object @{ Expression = { SevRank ([string]$_.Severity) } }, @{ Expression = { [string]$_.ObjectName } })
            $readyCount = @($items | Where-Object Status -eq 'Ready').Count
            [void]$sb.AppendLine('<div class="chk">')
            [void]$sb.AppendLine("<div class=""ch""><span class=""cid"">$(E $cid)</span> &middot; <b>$(E (CheckProp -id $cid -prop 'title' -fallback $cid))</b> &middot; <span class=""muted"">$(E (CheckProp -id $cid -prop 'category'))</span></div>")
            $ask = CheckProp -id $cid -prop 'reviewQuestion'
            if ($ask) { [void]$sb.AppendLine("<div class=""ask"">$(E $ask)</div>") }
            if ($readyCount -gt 0) {
                $verbForm = if ($readyCount -eq 1) { 'finding is' } else { 'findings are' }
                [void]$sb.AppendLine("<div class=""rdysum"">$('{0} {1} fine and summarized here. Set the selection to &quot;everything&quot; to list them in full.' -f @($readyCount, $verbForm))</div>")
            }
            foreach ($rec in $items) {
                $st = [string]$rec.Status
                $stCls = switch ($st) { 'Ready' { 'Ready' } 'Gap' { 'Gap' } 'Review required' { 'Review' } default { 'NotAssessed' } }
                $keyObj = if (-not [string]::IsNullOrWhiteSpace([string]$rec.ObjectId)) { [string]$rec.ObjectId }
                          elseif (-not [string]::IsNullOrWhiteSpace([string]$rec.ObjectName)) { [string]$rec.ObjectName }
                          else { '' }
                $key = ('{0}|{1}|{2}|{3}' -f [string]$rec.TenantId, [string]$rec.CheckId, $keyObj, [string]$rec.Property)
                [void]$sb.AppendLine("<div class=""find"" data-status=""$(E $st)"" data-key=""$(E $key)"">")
                [void]$sb.AppendLine("<div class=""fh""><span class=""sw"" style=""background:$(if ($rec.Severity -eq 'High') { $pal.Coral } elseif ($rec.Severity -eq 'Medium') { $pal.Yellow } else { $pal.Grey })""></span>" +
                    "<span class=""obj"">$(E ([string]$rec.ObjectName)) </span>" +
                    "<span class=""st $stCls"">$(E $st)</span><span class=""muted mono"">$(E ([string]$rec.Property))</span></div>")
                if ($rec.ObservedValue) { [void]$sb.AppendLine("<div class=""kv""><b>$('What we saw')</b>$(E ([string]$rec.ObservedValue))</div>") }
                $advice = if ($rec.Recommendation) { [string]$rec.Recommendation } elseif ($rec.NotAssessedReason) { [string]$rec.NotAssessedReason } else { '' }
                if ($advice) { [void]$sb.AppendLine("<div class=""kv""><b>$('What to do about it')</b>$(E $advice)</div>") }
                $evidence = ((@([string]$rec.GraphSource, [string]$rec.RawPath) | Where-Object { $_ }) -join '  ·  ')
                if ($evidence) { [void]$sb.AppendLine("<div class=""kv""><b>$('Evidence')</b><span class=""ev"">$(E $evidence)</span></div>") }
                [void]$sb.AppendLine('<div class="dec" data-dec></div>')
                [void]$sb.AppendLine('</div>')
            }
            [void]$sb.AppendLine('</div>')
        }
    }
    [void]$sb.AppendLine('</div>')

    if ($waves.Count -gt 0) {
        [void]$sb.AppendLine('<div class="sec"><h2>' + ('Rollout order') + '</h2>')
        [void]$sb.AppendLine('<p class="lead">' + ('A wave only opens once every condition in it is Ready. A condition without a mapped control doesn''t block the gate, but still needs manual confirmation.') + '</p>')
        foreach ($w in $waves) {
            $wCls = if ($w.Open) { 'ok' } else { 'no' }
            $wTxt = if ($w.Open) { 'open' } else { 'still closed' }
            [void]$sb.AppendLine('<div class="wave">')
            [void]$sb.AppendLine("<div class=""wh""><span class=""wn"">$('Wave {0} &middot; {1}' -f @($w.Order, (E ([string]$w.Name))))</span><span class=""badge $wCls"">$wTxt</span></div>")
            [void]$sb.AppendLine('<table><tr><th>' + ('Condition') + '</th><th style="width:26mm">' + ('Status') + '</th><th>' + ('Observation') + '</th></tr>')
            foreach ($c in @($w.Conditions)) {
                $cSt = [string]$c.Status
                $cCls = switch ($cSt) { 'Ready' { 'Ready' } 'Gap' { 'Gap' } 'Review required' { 'Review' } default { 'NotAssessed' } }
                $handmatig = if ($c.Manual) { " <span class=""muted"">($('manual'))</span>" } else { '' }
                [void]$sb.AppendLine("<tr><td>$(E ([string]$c.Label))$handmatig</td><td><span class=""st $cCls"">$(E $cSt)</span></td><td>$(E ([string]$c.Detail))</td></tr>")
            }
            [void]$sb.AppendLine('</table></div>')
        }
        [void]$sb.AppendLine('</div>')
    }

    $mfaRecs = @($records | Where-Object { $_.CheckId -in @('Auth-11', 'Auth-12', 'Auth-13') -and $_.ObjectType -eq 'Report' })
    $mfaAgg = @($records | Where-Object { $_.CheckId -in @('Auth-05', 'Auth-11') -and $_.ObjectType -ne 'Report' })
    if ($mfaAgg.Count -gt 0 -or $mfaRecs.Count -gt 0) {
        [void]$sb.AppendLine('<div class="sec"><h2>' + ('MFA methods, summarized') + '</h2>')
        [void]$sb.AppendLine('<p class="lead">' + ('The aggregates from the method matrix and registration readiness. The full per-user table is in mfa-methods.html and in the findings register.') + '</p>')
        [void]$sb.AppendLine('<table><tr><th style="width:24mm">' + ('Control') + '</th><th>' + ('Subject') + '</th><th>' + ('Observation') + '</th></tr>')
        foreach ($m in ($mfaAgg | Sort-Object CheckId, Property)) {
            [void]$sb.AppendLine("<tr><td class=""mono"">$(E ([string]$m.CheckId))</td><td>$(E ([string]$m.ObjectName)) $(E ([string]$m.Property))</td><td>$(E ([string]$m.ObservedValue))</td></tr>")
        }
        [void]$sb.AppendLine('</table></div>')
    }

    if ($catalog -and $catalog.checks) {
        [void]$sb.AppendLine('<div class="sec"><h2>' + ('Appendix: what each control means') + '</h2>')
        [void]$sb.AppendLine('<p class="lead">' + ('Each code stands for a control with a fixed meaning, so you can compare runs with each other.') + '</p>')
        [void]$sb.AppendLine('<table><tr><th style="width:26mm">' + ('Code') + '</th><th style="width:40mm">' + ('Resolved in') + '</th><th>' + ('What the control does') + '</th></tr>')
        $catSorted = @($catalog.checks | Sort-Object `
            @{ Expression = { $p = ([string]$_.checkId -split '-')[0]; if ($sectionByPrefix.ContainsKey($p)) { [int]$sectionByPrefix[$p].order } else { 99 } } },
            @{ Expression = { [string]$_.checkId } })
        foreach ($c in $catSorted) {
            [void]$sb.AppendLine("<tr><td class=""mono"">$(E ([string]$c.checkId))</td><td>$(E ([string](Get-CAInvProp $c 'category')))</td><td><b>$(E ([string]$c.title))</b><br>$(E ([string]$c.description))</td></tr>")
        }
        [void]$sb.AppendLine('</table></div>')
    }

    [void]$sb.AppendLine('<div class="sec"><h2>' + ('Appendix: run details') + '</h2><table>')
    $beta = @($records | Where-Object { $_.ApiVersion -eq 'beta' } | Select-Object -ExpandProperty GraphSource -Unique)
    $scopes = if ($ctx.PSObject.Properties['Preflight'] -and $ctx.Preflight) { (@(Get-CAInvProp $ctx.Preflight 'Scopes') -join ', ') } else { '' }
    foreach ($row in @(
            @{ K = ('Tenant');              V = [string]$ctx.TenantId }
            @{ K = ('Run');                 V = [string]$ctx.RunId }
            @{ K = ('Collected at');         V = [string]$ctx.CollectedAt }
            @{ K = ('Effective log window'); V = ('{0} days' -f @([string](Get-CAInvProp $ctx 'EffectiveLookbackDays'))) }
            @{ K = ('Authentication mode');       V = [string](Get-CAInvProp $ctx 'AuthMode') }
            @{ K = ('Beta endpoints used');  V = $(if ($beta.Count -gt 0) { $beta -join '; ' } else { 'none' }) }
            @{ K = ('Scopes');         V = $scopes })) {
        if ([string]::IsNullOrWhiteSpace([string]$row.V)) { continue }
        [void]$sb.AppendLine("<tr><td style=""width:44mm"" class=""muted"">$(E ([string]$row.K))</td><td>$(E ([string]$row.V))</td></tr>")
    }
    [void]$sb.AppendLine('</table></div>')

    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine("<script>window.__CAINV_TENANT=""$(E ([string]$ctx.TenantId))"";</script>")
    [void]$sb.AppendLine(@'
<script>
(function(){
  // This page READS the decision store and never writes to it. Decisions are made on
  // review-queue.html; here you're only capturing what currently stands.
  var TENANT = window.__CAINV_TENANT || '';
  var STORE_KEY = 'cainv-decisions:' + TENANT;
  var LBL = {confirmed:'Confirmed',dismissed:'Accepted',resolved:'Resolved'};
  var SUB = {confirmed:'keeps blocking',dismissed:'risk accepted',resolved:'counts as done'};
  var decisions = {};
  try { decisions = JSON.parse(localStorage.getItem(STORE_KEY) || '{}') || {}; } catch(e){ decisions = {}; }

  function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }
  function fmt(iso){ try{ var d=new Date(iso); var loc='en-US'; return d.toLocaleDateString(loc)+' '+d.toLocaleTimeString(loc,{hour:'2-digit',minute:'2-digit'}); }catch(e){ return ''; } }

  function paint(){
    var counts = { confirmed:0, dismissed:0, resolved:0 };
    var rows = [];
    document.querySelectorAll('.find').forEach(function(el){
      var k = el.getAttribute('data-key');
      var d = decisions[k];
      var slot = el.querySelector('[data-dec]');
      if(!slot) return;
      if(!d || !d.state){ slot.innerHTML=''; slot.style.display='none'; return; }
      slot.style.display='';
      counts[d.state] = (counts[d.state]||0) + 1;
      var note = d.note ? ' <span class="note">' + esc(d.note) + '</span>' : '';
      slot.innerHTML = '<span class="lbl">' + esc(LBL[d.state]||d.state) + '</span> <span class="muted">(' + esc(SUB[d.state]||'') + ')</span>'
        + (d.at ? ' <span class="muted">at ' + esc(fmt(d.at)) + '</span>' : '') + note;
      var head = el.querySelector('.obj');
      rows.push({ obj:(head?head.textContent.trim():''), key:k, state:d.state, at:d.at, note:d.note||'' });
    });

    var open = document.querySelectorAll('.find').length - (counts.confirmed+counts.dismissed+counts.resolved);
    var tiles = [['Still to review', open], [LBL.confirmed, counts.confirmed], [LBL.dismissed, counts.dismissed], [LBL.resolved, counts.resolved]];
    document.getElementById('dectiles').innerHTML = tiles.map(function(t){
      return '<div class="tile"><div class="n">'+t[1]+'</div><div class="l">'+esc(t[0])+'</div></div>';
    }).join('');

    var tbl = document.getElementById('dectable');
    if(!rows.length){
      tbl.innerHTML = '<p class="muted">' + esc('No decisions are recorded in this browser. If they were made elsewhere, import the decisions file with the button above.') + '</p>';
    } else {
      rows.sort(function(a,b){ return (a.state<b.state?-1:a.state>b.state?1:0); });
      tbl.innerHTML = '<table><tr><th>' + esc('Object') + '</th><th style="width:26mm">' + esc('Decision') + '</th><th style="width:30mm">' + esc('When') + '</th><th>' + esc('Why') + '</th></tr>'
        + rows.map(function(r){
            return '<tr><td>'+esc(r.obj||'tenant-wide')+'<div class="mono muted">'+esc(r.key.split('|').slice(1,2).join(''))+'</div></td>'
              + '<td>'+esc(LBL[r.state]||r.state)+'</td><td>'+esc(fmt(r.at))+'</td><td>'+esc(r.note)+'</td></tr>';
          }).join('') + '</table>';
    }

    var n = rows.length;
    document.getElementById('decsum').textContent = n ? (n + ' ' + (n===1?'decision':'decisions') + ' ' + 'loaded') : 'no decisions in this browser';
  }

  // Depth switch: just a class on body, so screen and print never diverge.
  function setMode(mode){
    document.body.className = mode;
    document.getElementById('mode-att').classList.toggle('on', mode==='mode-attention');
    document.getElementById('mode-all').classList.toggle('on', mode==='mode-all');
    document.getElementById('cover-mode').textContent =
      mode==='mode-all' ? 'Everything, including what\'s fine' : 'Everything needing attention';
  }
  document.getElementById('mode-att').addEventListener('click', function(){ setMode('mode-attention'); });
  document.getElementById('mode-all').addEventListener('click', function(){ setMode('mode-all'); });
  document.getElementById('btnprint').addEventListener('click', function(){ window.print(); });

  // Importing reads the same envelope that the scorecard and the review page export, and keeps
  // the result in memory: localStorage stays untouched.
  var fileImport=document.getElementById('fileimport'), btnImport=document.getElementById('btnimport');
  btnImport.addEventListener('click', function(){ fileImport.click(); });
  fileImport.addEventListener('change', function(){
    var f = fileImport.files && fileImport.files[0]; if(!f) return;
    var rd = new FileReader();
    rd.onload = function(){
      try{
        var obj = JSON.parse(rd.result);
        var inc = (obj && obj.decisions) ? obj.decisions : obj;
        Object.keys(inc||{}).forEach(function(k){ if(inc[k] && inc[k].state){ decisions[k] = inc[k]; } });
        paint();
      }catch(err){ alert('Could not read this file as decisions JSON.'); }
      fileImport.value='';
    };
    rd.readAsText(f);
  });

  paint();
})();
</script>
'@)
    [void]$sb.AppendLine('</body></html>')
    Write-CAInvReportFile -Path $outPath -Content $sb.ToString()
    Write-CAInvLog -Level 'INFO' -Message "Printable report written: $outPath ($($records.Count) findings)."
    return $outPath
}
