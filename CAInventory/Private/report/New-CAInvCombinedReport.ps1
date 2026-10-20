function New-CAInvCombinedReport {
    <#
    .SYNOPSIS
        Single-file report shell:
        brings the six report pages together behind tabs in reports/report.html, so the customer
        opens a single link.
    .DESCRIPTION
        Generates no new data: all six pages supply their HTML as text (the generators no longer
        write anything to disk themselves, see their own .OUTPUTS). This function is the only place
        left in the chain that still writes these six pages to disk.

        Revised 29-08-2026: the four pages that read/write the shared
        decision store (localStorage key cainv-decisions:{tenantId}) — Scorecard, Review needed,
        Rollout order, Open work — are mounted as a same-origin `srcdoc` iframe. Research showed
        that `src="scorecard.html"` on `file://` does NOT guarantee shared localStorage
        (Chrome/Edge isolate storage per exact file, Firefox blocks localStorage on `file://`
        entirely); a `srcdoc` iframe without a `sandbox` attribute, on the other hand, is
        same-origin with the parent page and can read its storage/DOM. Each of the four therefore
        gets a small, additive shim before its own (unchanged) script: that shim routes
        `localStorage.getItem`/`setItem` to `window.CAINV_SHARED`, an in-memory store on this
        parent page, and registers itself there. A write in one fragment dispatches a real
        `StorageEvent` to all other registered fragments (not to itself — the same behavior as a
        natural storage event), and also makes a best-effort attempt to write to the real browser
        storage (persisting across sessions; works in Chrome/Edge, still fails in Firefox on
        `file://`).

        Revised 01-09-2026 (from eight report files to one): MFA methods and Reference used to go
        in as a plain `src` iframe to their own separate file — that worked, because they don't
        touch the decision store. Once the six pages no longer exist as separate files on disk,
        `src` is no longer an option: all six now become `srcdoc`. MFA methods and Reference don't
        get the shim injection (unchanged — they don't touch the store), but do get the same
        inline mount as the other four.

        Revised to remove a duplicate brand bar: each of the six pages is also
        an independently regenerable document and so carries its own full New-CAInvReportTopbar.
        Within this combined report that produces a visible duplicate bar — the tabbar above
        already shows the brand identity. A small, always-applied style injection (not tied to
        `Shim`, since this affects all six, not just the four with the decision store) hides
        `.topbar`/`.top` within each fragment; the page itself stays unchanged and shows its own
        bar again as soon as it's opened standalone.

        ScorecardHtml and RolloutPlanHtml remain mandatory (unchanged behavior): if either is
        empty, nothing is written and $null is returned — deliberately a soft outcome, not a throw,
        consistent with the rest of the report layer (a missing sub-report is a degradation, not a
        reason to crash the whole run). ReviewQueueHtml, MfaMethodsHtml, ReferenceHtml, and
        OpenWorkHtml are optional — if there's no content, that one tab is left out instead of
        blocking the whole report.
    .PARAMETER ReportsPath
        The folder report.html goes into. This function used to derive its target folder from
        scorecard.html's path; now that no file path comes in anymore, the caller must pass the
        folder explicitly (`Invoke-CAInventory` passes its already-existing `$paths.Reports` for
        this).
    .PARAMETER Brand
        Optional hashtable as returned by Get-CAInvBrand, passed to the tab-shell palette and the
        brand bar. This function doesn't read $ctx itself (it only receives already-rendered HTML
        text), so the caller must pass $ctx.Brand explicitly.
    .OUTPUTS
        String: path to reports/report.html, or $null when scorecard or rollout plan is missing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $ReportsPath,

        [string] $ScorecardHtml,

        [string] $RolloutPlanHtml,

        [string] $ReviewQueueHtml,

        [string] $MfaMethodsHtml,

        [string] $ReferenceHtml,

        [string] $OpenWorkHtml,

        [hashtable] $Brand
    )

    if ([string]::IsNullOrWhiteSpace($ScorecardHtml) -or [string]::IsNullOrWhiteSpace($RolloutPlanHtml)) {
        Write-CAInvLog -Level 'WARN' -Message 'Scorecard or rollout plan report missing; no combined report generated.'
        return $null
    }

    $outPath = Join-Path $ReportsPath 'report.html'

    function E([string]$s) { ConvertTo-CAInvHtmlSafe -Text $s }

    $candidates = @(
        @{ Label = ('Scorecard'); Html = $ScorecardHtml; Shim = $true }
        @{ Label = ('Review needed'); Html = $ReviewQueueHtml; Shim = $true }
        @{ Label = ('MFA methods'); Html = $MfaMethodsHtml; Shim = $false }
        @{ Label = ('Rollout order'); Html = $RolloutPlanHtml; Shim = $true }
        @{ Label = ('Open work'); Html = $OpenWorkHtml; Shim = $true }
        @{ Label = ('Reference'); Html = $ReferenceHtml; Shim = $false }
    )
    $tabs = @()
    $n = 0
    foreach ($c in $candidates) {
        if ([string]::IsNullOrWhiteSpace($c.Html)) { continue }
        $n++
        $tabs += @{ Id = "t$n"; Label = $c.Label; Html = $c.Html; Shim = $c.Shim }
    }

    $labelCss = ($tabs | ForEach-Object { "#$($_.Id):checked ~ .tabbar label[for=""$($_.Id)""]" }) -join ', '
    $labelCss = "$labelCss{color:#fff;border-bottom-color:var(--yellow)}"
    $frameCss = ($tabs | ForEach-Object { "#$($_.Id):checked ~ .frames .$($_.Id){display:block}" }) -join "`n"

    $radios = ($tabs | ForEach-Object { $checked = if ($_.Id -eq 't1') { ' checked' } else { '' }; "<input type=""radio"" name=""tab"" id=""$($_.Id)""$checked>" }) -join "`n"
    $labels = ($tabs | ForEach-Object { "<label for=""$($_.Id)"">$(E $_.Label)</label>" }) -join ''

    $shim = @'
<script>
(function(){
  try {
    var host = window.parent;
    if (!host || host === window || !host.CAINV_SHARED) { return; }
    var shared = host.CAINV_SHARED;
    var realGetItem = window.localStorage.getItem.bind(window.localStorage);
    window.localStorage.getItem = function(key){
      if (Object.prototype.hasOwnProperty.call(shared.store, key)) { return shared.store[key]; }
      try { return realGetItem(key); } catch(e) { return null; }
    };
    window.localStorage.setItem = function(key, value){ shared.write(key, value, window); };
    shared.register(window);
  } catch(e) { /* falls back to real localStorage, e.g. on a cross-origin exception */ }
})();
</script>
'@

    $hideTopbar = '<style>.topbar,.top{display:none}</style>'

    $frames = ($tabs | ForEach-Object {
            $content = $_.Html
            $inject = if ($_.Shim) { "$shim$hideTopbar" } else { $hideTopbar }
            $content = $content.Replace('<head>', "<head>$inject")
            "<iframe class=""$($_.Id) frame"" title=""$(E $_.Label)"" srcdoc=""$(E $content)""></iframe>"
        }) -join "`n"

    $pageTitle = 'CA Inventory &middot; report'
    $printLinkLabel = 'Report as PDF'
    $html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>$pageTitle</title>
<style>
$(New-CAInvReportPalette -Surface 'Minimal' -Brand $Brand)
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{display:flex;flex-direction:column;font-family:Aileron,'Helvetica Neue',Helvetica,Arial,sans-serif}
input[type=radio]{display:none}
.tabbar{background:var(--ink);display:flex;align-items:baseline;gap:0;padding:0 48px;flex:0 0 auto;overflow-x:auto}
.tabbar .brand{display:flex;align-items:baseline;gap:10px;padding:14px 24px 14px 0;flex-shrink:0}
.tabbar .brand .arrow{color:var(--yellow);font-size:18px;font-weight:700;line-height:1}
.tabbar .brand .name{font-size:17px;font-weight:700;letter-spacing:-.01em;color:#fff}
.tabbar label{padding:16px 20px;color:var(--tabmuted);cursor:pointer;font-size:12px;letter-spacing:.1em;text-transform:uppercase;font-weight:700;border-bottom:3px solid transparent;user-select:none;white-space:nowrap}
.tabbar label:hover{color:#fff}
/* Deliberately a link and not an extra tab: a hidden iframe is not rendered by the print engine, so the print page must open in its own window. */
.tabbar .pdflink{margin-left:auto;align-self:center;color:var(--yellow);font-size:12px;letter-spacing:.1em;text-transform:uppercase;font-weight:700;text-decoration:none;padding:16px 0 16px 20px;white-space:nowrap}
.tabbar .pdflink:hover{color:#fff}
$labelCss
.frames{flex:1;min-height:0;display:flex}
.frame{display:none;flex:1;border:0;width:100%;height:100%}
$frameCss
</style></head>
<body>
<script>
// Shared in-memory decision store for the srcdoc fragments (see .DESCRIPTION). Must come before
// the tabbar/iframes in document order, so it already exists by the time the first
// fragment runs its shim.
window.CAINV_SHARED = (function(){
  var store = {};
  // Best-effort seed from our own localStorage: a previously opened report (Chrome/Edge, same
  // file) then immediately shows the previous session. Fails silently on Firefox/file://, exactly
  // like the standalone pages already do today.
  try {
    for (var i = 0; i < window.localStorage.length; i++) {
      var k = window.localStorage.key(i);
      store[k] = window.localStorage.getItem(k);
    }
  } catch(e) {}
  var frames = [];
  return {
    store: store,
    register: function(win){ frames.push(win); },
    write: function(key, value, sourceWin){
      store[key] = value;
      frames.forEach(function(f){
        if (f === sourceWin) { return; }
        try { f.dispatchEvent(new f.StorageEvent('storage', { key: key, newValue: value, storageArea: f.localStorage })); } catch(e) {}
      });
      try { window.localStorage.setItem(key, value); } catch(e) {}
    }
  };
})();
</script>
$radios
<div class="tabbar">$(New-CAInvReportTopbar -Variant 'BrandOnly' -Brand $Brand)$labels<a class="pdflink" href="report-print.html" target="_blank">$printLinkLabel</a></div>
<div class="frames">
$frames
</div>
</body></html>
"@

    Write-CAInvReportFile -Path $outPath -Content $html
    Write-CAInvLog -Level 'INFO' -Message "Combined report written: $outPath"
    return $outPath
}
