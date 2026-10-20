function New-CAInvReference {
    <#
    .SYNOPSIS
        Reference page — check catalog + evidence and sources.
    .DESCRIPTION
        Moves what used to be scorecard sections "05 What each control means" and "06 Evidence and
        sources" onto their own page: content and purpose unchanged, just no longer part of the
        main flow. This page is deliberately NOT a numbered step — pure reference material,
        reachable via New-CAInvCombinedReport's tab bar, not something the reader needs to go
        through chronologically.
    .OUTPUTS
        String: the HTML content of the reference page.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ctx = $script:CAInvContext
    $records = @($ctx.Records)
    $lang = 'en'

    $catalog = $null
    if ($ctx.PSObject.Properties['Config'] -and $ctx.Config -and $ctx.Config.CheckIds) {
        $catalog = $ctx.Config.CheckIds
    }
    else {
        try { $catalog = (Get-CAInvConfig).CheckIds } catch { $catalog = $null }
    }
    $checkMap = @{}
    if ($catalog -and $catalog.checks) {
        foreach ($c in $catalog.checks) { $checkMap[$c.checkId] = $c }
    }
    function CheckTitle([string]$id) {
        if ($checkMap.ContainsKey($id)) { return $checkMap[$id].title }
        return $id
    }

    function E([string]$s) { ConvertTo-CAInvHtmlSafe -Text $s }

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
    foreach ($sec in @($sectionsCfg.sections)) { $sectionByPrefix[[string]$sec.prefix] = $sec }

    $sevOrder = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2; 'Info' = 3 }

    $catExport = [System.Collections.Generic.List[object]]::new()
    if ($catalog -and $catalog.checks) {
        foreach ($c in $catalog.checks) {
            $learnUrl = Get-CAInvProp $c 'learnUrl'
            $selfDesigned = [bool](Get-CAInvProp $c 'selfDesigned' $false)
            $prefix = ([string]$c.checkId -split '-')[0]
            $sec = if ($sectionByPrefix.ContainsKey($prefix)) { $sectionByPrefix[$prefix] } else { $null }
            [void]$catExport.Add([ordered]@{
                    checkId = $c.checkId; title = $c.title; description = $c.description
                    category = [string](Get-CAInvProp $c 'category')
                    section = if ($sec) { [string]$sec.title } else { 'Other' }
                    sectionIntro = if ($sec) { [string]$sec.intro } else { '' }
                    sectionOrder = if ($sec) { [int]$sec.order } else { 99 }
                    severity = [string](Get-CAInvProp $c 'defaultSeverity')
                    learnUrl = $learnUrl; selfDesigned = $selfDesigned
                })
        }
    }

    $catExport = [System.Collections.Generic.List[object]](@($catExport | Sort-Object `
        @{ Expression = { [int]$_.sectionOrder } },
        @{ Expression = { if ($sevOrder.ContainsKey([string]$_.severity)) { $sevOrder[[string]$_.severity] } else { 9 } } },
        @{ Expression = { [string]$_.checkId } }))

    $evidence = @()
    $evGroups = $records | Where-Object { $_.RawPath } | Group-Object RawPath | Sort-Object Name
    foreach ($eg in $evGroups) {
        $titles = @($eg.Group | Select-Object -ExpandProperty CheckId -Unique | ForEach-Object { CheckTitle $_ })
        $what = ($titles | Select-Object -First 2) -join '; '
        if ($titles.Count -gt 2) { $what += ' …' }
        $evidence += [PSCustomObject]@{ Path = $eg.Name; What = $what }
    }
    $evidence += [PSCustomObject]@{ Path = './normalized/findings.csv'; What = ('All normalized findings from this run') }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!doctype html><html lang="' + $lang + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>' + ('Reference · Conditional Access') + '</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine((New-CAInvReportPalette -Surface 'Card' -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine(@'
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--body);font-family:Aileron,'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased;padding:0 0 80px}
a{color:var(--ink);text-decoration:underline;text-underline-offset:2px}a:hover{color:var(--coral)}
input,button{font-family:inherit}
.mono{font-family:ui-monospace,Consolas,monospace}
.topbar{background:var(--ink);color:#fff;padding:14px 48px;display:flex;align-items:baseline;justify-content:space-between;gap:24px}
.brand{display:flex;align-items:baseline;gap:10px}
.brand .arrow{color:var(--yellow);font-size:18px;font-weight:700;line-height:1}
.brand .name{font-size:17px;font-weight:700;letter-spacing:-.01em}
.topbar .tag{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--tabmuted)}
.footbar{background:var(--ink);color:#fff;padding:36px 64px;display:flex;justify-content:space-between;align-items:baseline;gap:32px;flex-wrap:wrap}
.footbar .l{display:flex;align-items:baseline;gap:10px;font-size:14px}
.footbar .arrow{color:var(--yellow);font-size:16px;font-weight:700}
.footbar .r{font-size:12px;color:var(--tabmuted)}
.page{max-width:1180px;margin:0 auto;background:var(--card)}
.sec{padding:48px 64px;border-bottom:1px solid var(--line)}
.sec:last-of-type{border-bottom:0}
.eyebrow{font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:var(--coral);font-weight:700;margin-bottom:18px}
h1{font-size:36px;line-height:1.1;font-weight:700;color:var(--ink);margin:0 0 10px;letter-spacing:-.02em}
.lead{margin:0;max-width:44em;font-size:17px;color:var(--body)}
.sechead{display:flex;align-items:baseline;gap:14px;margin-bottom:6px}
h2{font-size:26px;font-weight:700;color:var(--ink);margin:0;letter-spacing:-.015em}
.sec p.intro{margin:0 0 24px;max-width:46em}
.refsearch{width:100%;max-width:420px;padding:11px 14px;border:1px solid var(--grey);background:#fff;color:var(--body);font-size:14px;margin-bottom:8px}
#reflist{border-top:1px solid var(--line)}
.refitem{display:grid;grid-template-columns:120px 1fr;gap:24px;padding:16px 0;border-bottom:1px solid var(--line);align-items:start}
.refitem .rc{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;color:var(--ink);font-weight:700}
.refitem .rdom{font-size:12px;color:var(--muted)}
.refsechead{padding:26px 0 10px;border-bottom:1px solid var(--line)}
.refsechead h3{margin:0;font-size:15px;color:var(--ink);letter-spacing:-.01em}
.refsechead .refsecintro{margin-top:3px;font-size:13px;color:var(--muted);max-width:52em}
.refitem .rt{font-weight:700;color:var(--ink)}
.refitem .rd{margin:4px 0 0;max-width:56em;font-size:14.5px}
.learnlink{display:inline-block;margin-top:8px;font-size:12.5px;font-weight:700;color:var(--ink);text-decoration:none;border-bottom:1px solid var(--ink)}
.learnlink:hover{color:var(--coral);border-bottom-color:var(--coral)}
.owndesign{display:inline-block;margin-top:8px;font-size:12.5px;font-style:italic;color:var(--muted)}
.evgrid{display:grid;grid-template-columns:1fr 1fr;gap:0 48px;border-top:1px solid var(--line)}
.evitem{padding:14px 0;border-bottom:1px solid var(--line)}
.evitem .p{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;color:var(--ink);word-break:break-all}
.evitem .w{font-size:13px;color:var(--muted);margin-top:2px}
.evnote{margin:28px 0 0;font-size:13px;color:var(--muted);max-width:46em}
@media (max-width:760px){
  .topbar,.footbar{padding-left:24px;padding-right:24px}
  .sec{padding-left:24px;padding-right:24px}
  h1{font-size:28px}
  .evgrid{grid-template-columns:1fr}
}
</style></head><body>
'@)

    [void]$sb.AppendLine((New-CAInvReportTopbar -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine('<div class="page">')

    [void]$sb.AppendLine('<div class="sec"><div class="eyebrow">' + ('Pre-implementation inventory &middot; Conditional Access') + '</div><h1>' + ('Reference') + '</h1><p class="lead">' + ('What each control means, and where each finding comes from.') + '</p></div>')

    [void]$sb.AppendLine('<div class="sec" id="refsection"><div class="sechead"><h2>' + ('What does each control mean?') + '</h2></div>')
    [void]$sb.AppendLine('<p class="intro">' + ('Each code stands for one control with a fixed meaning, so you can compare runs with each other.') + '</p>')
    [void]$sb.AppendLine('<input id="reffilter" class="refsearch" type="search" placeholder="' + ('Filter by name, code, or text') + '">')
    [void]$sb.AppendLine('<div id="reflist">')
    $lastSection = $null
    foreach ($c in $catExport) {
        if ([string]$c.section -ne $lastSection) {
            $lastSection = [string]$c.section
            $introHtml = if ($c.sectionIntro) { "<div class='refsecintro'>$(E $c.sectionIntro)</div>" } else { '' }
            [void]$sb.AppendLine("<div class='refsechead' data-text=""$(E $lastSection.ToLower())""><h3>$(E $lastSection)</h3>$introHtml</div>")
        }
        $txt = "$($c.checkId) $($c.title) $($c.description) $($c.category) $($c.section)"
        $learnHtml = ''
        if (-not [string]::IsNullOrWhiteSpace([string]$c.learnUrl)) {
            $learnHtml = "<a class='learnlink' href=""$(E $c.learnUrl)"" target=""_blank"" rel=""noopener"">$('Microsoft Learn &#8599;')</a>"
        }
        elseif ($c.selfDesigned) {
            $learnHtml = "<span class='owndesign' title=""$('This control is CAInventory''s own insight, not traceable to one specific Microsoft Learn article.')"">$('Own design, no Microsoft Learn source')</span>"
        }
        [void]$sb.AppendLine("<div class='refitem' data-text=""$(E $txt.ToLower())""><div><div class='rc'>$(E $c.checkId)</div><div class='rdom'>$(E $c.category)</div></div><div><div class='rt'>$(E $c.title)</div><div class='rd'>$(E $c.description)</div>$learnHtml</div></div>")
    }
    [void]$sb.AppendLine('</div></div>')

    [void]$sb.AppendLine('<div class="sec"><div class="sechead"><h2>' + ('Evidence and sources') + '</h2></div>')
    [void]$sb.AppendLine('<p class="intro">' + ('Everything in this report comes from a read-only run. The raw Graph response sits alongside this file, with a hash per file, so every finding can be traced back to the moment it was measured.') + '</p>')
    [void]$sb.AppendLine('<div class="evgrid">')
    foreach ($ev in $evidence) {
        [void]$sb.AppendLine("<div class='evitem'><div class='p'>$(E $ev.Path)</div><div class='w'>$(E $ev.What)</div></div>")
    }
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('<p class="evnote">' + ('Read-only run. No changes to the tenant, no credentials in the output. Controls without the necessary context stay <em>not assessed</em>, with a reason &mdash; an unmeasured control is never the same as an approved control.') + '</p>')
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine((New-CAInvReportFooter -RunId $ctx.RunId -IncludePrintLink -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine(@'
<script>
(function(){
  var reffilter=document.getElementById('reffilter');
  if(reffilter){ reffilter.addEventListener('input',function(){
    var q=(reffilter.value||'').toLowerCase();
    document.querySelectorAll('#reflist .refitem').forEach(function(el){ el.style.display=(!q||el.dataset.text.indexOf(q)>=0)?'':'none'; });
    // A section header should only stay visible while something below it is still visible.
    document.querySelectorAll('#reflist .refsechead').forEach(function(head){
      var visible=false, el=head.nextElementSibling;
      while(el && !el.classList.contains('refsechead')){
        if(el.classList.contains('refitem') && el.style.display!=='none'){ visible=true; break; }
        el=el.nextElementSibling;
      }
      head.style.display=visible?'':'none';
    });
  }); }
})();
</script>
'@)
    [void]$sb.AppendLine('</body></html>')
    Write-CAInvLog -Level 'INFO' -Message 'Reference HTML built.'
    return $sb.ToString()
}
