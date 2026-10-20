function New-CAInvRolloutPlan {
    <#
    .SYNOPSIS
        Report C — rollout order recommendation. Translates
        CA_Voorwaardenketen_Wat_Moet_Waar_Zijn_Voor_Aanzetten.md (root) into an objective
        wave-gate verdict based on the findings that already exist.
    .DESCRIPTION
        Aggregates the findings register (no new data, no new Graph calls). The condition-chain
        doc describes a fixed persona order (emergency accounts, then admins, then end users) and,
        per persona, a series of conditions that must be demonstrably true before a policy is
        turned on. The "How to measure this without manual work" section of that same doc says it
        explicitly: "A wave may open once every finding attached to it is Ready and none is a
        Gap." This function implements that criterion literally, via the external mapping in
        config/rollout-waves.json (condition -> CheckIds).

        A condition without mapped CheckIds is a known coverage gap: CAInventory can't yet measure
        it automatically. That condition blocks the wave just as hard as a Gap would (zero-trust:
        not measured is not confirmed), but is labeled separately so the distinction between
        "still needs fixing" and "still needs to be built" stays visible.

        Conditions that trace back to UserRegistrationDetails (domain 6.8) also show a per-user
        drilldown (which role holders are missing a phishing-resistant method, which users aren't
        yet MFA-registered) once that condition isn't Ready — reuses the already-enriched data
        from Get-CAInvUserRegistrationDetail, no new Graph call.

        Reacts live to scorecard decisions: every condition with mapped CheckIds embeds the
        finding keys of its underlying records (same key format as New-CAInvScorecard,
        TenantId|CheckId|ObjectId-or-Name|Property). Client-side JS reads the same localStorage
        key (cainv-decisions:{tenant}) and recomputes per condition and per wave gate: 'resolved'
        counts as Done, 'dismissed' no longer blocks (accepted risk), 'confirmed' keeps blocking
        (acknowledged, not resolved). Without JavaScript (or without decisions) the page shows
        exactly the server-rendered status computed at run time.
    .OUTPUTS
        String: the HTML content of the report, or $null if rollout-waves.json is missing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ctx = $script:CAInvContext
    $records = @($ctx.Records)

    $waveConfig = $null
    if ($ctx.PSObject.Properties['Config'] -and $ctx.Config -and $ctx.Config.RolloutWaves) {
        $waveConfig = $ctx.Config.RolloutWaves
    }
    else {
        try { $waveConfig = (Get-CAInvConfig).RolloutWaves } catch { $waveConfig = $null }
    }
    if (-not $waveConfig) {
        Write-CAInvLog -Level 'WARN' -Message 'rollout-waves.json missing; no rollout plan report generated.'
        return $null
    }

    $pal = New-CAInvReportPalette -As 'Map' -Brand (Get-CAInvProp $ctx 'Brand')
    $INK = $pal.Ink; $CORAL = $pal.Coral; $YELLOW = $pal.Yellow; $GREY = $pal.Grey
    function E([string]$s) { ConvertTo-CAInvHtmlSafe -Text $s }

    function Get-CAInvRolloutFindingKey {
        param($Rec)
        $objId = [string](Get-CAInvProp $Rec 'ObjectId' '')
        $objName = [string](Get-CAInvProp $Rec 'ObjectName' '')
        $objKey = if (-not [string]::IsNullOrWhiteSpace($objId)) { $objId } elseif (-not [string]::IsNullOrWhiteSpace($objName)) { $objName } else { '' }
        $tenantId = [string](Get-CAInvProp $Rec 'TenantId' '')
        $property = [string](Get-CAInvProp $Rec 'Property' '')
        return ('{0}|{1}|{2}|{3}' -f $tenantId, [string]$Rec.CheckId, $objKey, $property)
    }

    $userDrilldownFilters = @{
        'adminsWithoutPhishingResistant' = { param($u) $u.InAdminScope -and -not $u.PhishingResistantCapable }
        'notMfaRegistered'                = { param($u) -not $u.IsMfaRegistered }
    }

    function Get-ConditionUserDrilldown {
        param($Condition, $Ctx)
        if (-not $Condition.PSObject.Properties['userDrilldown'] -or -not $Condition.userDrilldown) { return @() }
        $key = [string]$Condition.userDrilldown
        if (-not $userDrilldownFilters.ContainsKey($key)) { return @() }
        if (-not $Ctx.PSObject.Properties['UserRegistrationDetails']) { return @() }
        $details = @($Ctx.UserRegistrationDetails)
        if ($details.Count -eq 0) { return @() }
        $filter = $userDrilldownFilters[$key]
        return @($details | Where-Object { & $filter $_ } | Select-Object -ExpandProperty UserPrincipalName | Sort-Object -Unique)
    }

    $waveResults = foreach ($wave in (@(Get-CAInvProp $waveConfig 'waves' @()) | Sort-Object order)) {
        $condIdx = 0
        $condResults = foreach ($cond in $wave.conditions) {
            $r = Resolve-CAInvConditionStatus -Condition $cond -AllRecords $records
            $users = Get-ConditionUserDrilldown -Condition $cond -Ctx $ctx
            $recKeys = @(@($r.Recs) | ForEach-Object { [PSCustomObject]@{ key = (Get-CAInvRolloutFindingKey $_); status = $_.Status } })
            [PSCustomObject]@{
                DomId = "$($wave.id)-$condIdx"; Label = $cond.label; Why = $cond.why; Status = $r.Status
                Manual = $r.Manual; Detail = $r.Detail; Users = $users; RecKeys = $recKeys
                ConditionKey = (Get-CAInvConditionKey -ScopeId ([string]$wave.id) -Index $condIdx)
            }
            $condIdx++
        }
        $condResults = @($condResults)
        $blocking = @($condResults | Where-Object { $_.Status -ne 'Ready' -and -not $_.Manual })
        $manualPending = @($condResults | Where-Object { $_.Manual })
        [PSCustomObject]@{
            Id = $wave.id; Order = $wave.order; Name = $wave.name; Intro = $wave.intro
            Conditions = $condResults; Open = ($blocking.Count -eq 0); Blocking = $blocking; ManualPending = $manualPending
        }
    }
    $waveResults = @($waveResults)

    $nonSeqCfg = Get-CAInvProp $waveConfig 'nonSequentialConditions' $null
    $nonSeq = $null
    if ($nonSeqCfg) {
        $nsIdx = 0
        $nsCond = foreach ($cond in @(Get-CAInvProp $nonSeqCfg 'conditions' @())) {
            $r = Resolve-CAInvConditionStatus -Condition $cond -AllRecords $records
            $recKeys = @(@($r.Recs) | ForEach-Object { [PSCustomObject]@{ key = (Get-CAInvRolloutFindingKey $_); status = $_.Status } })
            [PSCustomObject]@{
                DomId = "nonseq-$nsIdx"; Label = $cond.label; Why = $cond.why; Status = $r.Status
                Manual = $r.Manual; Detail = $r.Detail; RecKeys = $recKeys
                ConditionKey = (Get-CAInvConditionKey -ScopeId 'nonseq' -Index $nsIdx)
            }
            $nsIdx++
        }
        $nonSeq = [PSCustomObject]@{
            Name = (Get-CAInvProp $nonSeqCfg 'name' ''); Intro = (Get-CAInvProp $nonSeqCfg 'intro' '')
            Conditions = @($nsCond)
        }
    }

    $statusColor = @{ 'Ready' = $INK; 'Gap' = $CORAL; 'Review required' = $YELLOW; 'Not assessed' = $GREY }
    $statusLabel = @{
        'Ready'            = 'Ready'
        'Gap'              = 'Gap'
        'Review required'  = 'Review needed'
        'Not assessed'     = 'Not assessed'
    }
    $gateText = @{
        Closed            = 'Wave may not open yet'
        OpenPendingManual = 'Wave may open, pending manual confirmation'
        Open              = 'Wave may open'
    }
    $manualToConfirmLabel = 'Manual confirmation needed'
    $confirmCheckboxLabel = 'I have manually checked this and confirm it'

    $lang = 'en'
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!doctype html><html lang="' + $lang + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>' + ('Rollout order · Conditional Access') + '</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine((New-CAInvReportPalette -Surface 'Card' -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine(@'
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--body);font-family:Aileron,'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased;padding:0 0 80px}
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
h1{font-size:40px;line-height:1.1;font-weight:700;color:var(--ink);margin:0 0 10px;max-width:24em;letter-spacing:-.02em}
.lead{margin:0;max-width:46em;font-size:17px}
h2{font-size:24px;font-weight:700;color:var(--ink);margin:0 0 6px;letter-spacing:-.015em}
.wavehead{display:flex;align-items:center;gap:16px;margin-bottom:8px;flex-wrap:wrap}
.waveno{width:38px;height:38px;background:var(--ink);color:#fff;font-weight:700;font-size:16px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.gate{font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:6px 14px}
.gate.open{background:var(--ink);color:#fff}
.gate.closed{background:var(--coral);color:#fff}
.intro{margin:0 0 24px;max-width:52em;color:var(--muted)}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);font-weight:700;padding:0 16px 10px;border-bottom:2px solid var(--ink)}
th:first-child{padding-left:0}
td{padding:15px 16px;border-bottom:1px solid var(--line);vertical-align:top}
td:first-child{padding-left:0}
td.name{font-weight:700;color:var(--ink)}
.why{font-size:13px;color:var(--muted);margin-top:3px}
.status{display:inline-flex;align-items:center;gap:8px;font-weight:700;white-space:nowrap}
.status .sw{width:10px;height:10px;display:block;flex-shrink:0}
.detail{font-size:13.5px;color:var(--body)}
.na{color:var(--muted);font-style:italic}
.condconfirm{display:flex;align-items:center;gap:7px;margin-top:9px;font-size:12.5px;font-weight:700;color:var(--ink);cursor:pointer}
.condconfirm input{cursor:pointer;margin:0}
.userlist{margin-top:8px}
.userlist summary{cursor:pointer;font-size:12.5px;font-weight:700;color:var(--ink)}
.userlist ul{margin:8px 0 0;padding-left:18px;font-size:13px;columns:2;column-gap:24px}
.userlist li{break-inside:avoid;padding:1px 0}
.userlist .more{color:var(--muted);font-style:italic;font-size:12.5px;margin-top:4px}
@media (max-width:760px){
  .topbar,.footbar{padding-left:24px;padding-right:24px}
  .sec{padding:32px 24px}
  h1{font-size:30px}
}
</style></head><body>
'@)
    [void]$sb.AppendLine((New-CAInvReportTopbar -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine('<div class="page">')
    [void]$sb.AppendLine('<div class="sec">')
    [void]$sb.AppendLine('<div class="eyebrow">' + ('Pre-implementation inventory &middot; Conditional Access') + '</div>')
    [void]$sb.AppendLine('<h1>' + ('Rollout order: what needs to be in place before a wave can open') + '</h1>')
    [void]$sb.AppendLine('<p class="lead">' + ('Allow the method in policy, then enable registration, then demonstrate registration, only then enforce. Emergency accounts first, then admins, then everyone else. A wave may open once every finding attached to it is Ready and none is a gap.') + '</p>')
    [void]$sb.AppendLine('</div>')

    $anyBlockedBefore = $false
    foreach ($wave in $waveResults) {
        $gateCls = if ($wave.Open) { 'open' } else { 'closed' }
        $gateTxt = if (-not $wave.Open) { $gateText.Closed }
                   elseif ($wave.ManualPending.Count -gt 0) { $gateText.OpenPendingManual }
                   else { $gateText.Open }
        [void]$sb.AppendLine('<div class="sec">')
        [void]$sb.AppendLine("<div class=""wavehead""><span class=""waveno"">$($wave.Order)</span><h2 style=""margin:0"">$(E $wave.Name)</h2><span id=""gate-$($wave.Id)"" class=""gate $gateCls"">$gateTxt</span></div>")
        if ($anyBlockedBefore -and $wave.Open) {
            [void]$sb.AppendLine('<p class="intro" style="color:var(--coral)">' + ('Note: an earlier wave is still open. The persona order is fixed (emergency accounts &rarr; admins &rarr; everyone else); getting this wave technically ready before the previous one closes reverses the intended order.') + '</p>')
        }
        [void]$sb.AppendLine("<p class=""intro"">$(E $wave.Intro)</p>")
        [void]$sb.AppendLine('<table><tr><th style="width:32%">' + ('Condition') + '</th><th style="width:14%">' + ('Status') + '</th><th>' + ('Observation') + '</th></tr>')
        foreach ($c in $wave.Conditions) {
            $sc = $statusColor[$c.Status]; if (-not $sc) { $sc = $GREY }
            $lbl = if ($c.Manual) { $manualToConfirmLabel } else { $statusLabel[$c.Status] }
            if (-not $lbl) { $lbl = $c.Status }
            $detailCls = if ($c.Status -eq 'Not assessed') { 'detail na' } else { 'detail' }
            $userBlock = ''
            $users = @($c.Users)
            if ($c.Status -ne 'Ready' -and $users.Count -gt 0) {
                $shown = @($users | Select-Object -First 50)
                $items = ($shown | ForEach-Object { "<li>$(E $_)</li>" }) -join ''
                $more = if ($users.Count -gt $shown.Count) { "<div class='more'>$('+ {0} more' -f @($users.Count - $shown.Count))</div>" } else { '' }
                $userBlock = "<details class='userlist'><summary>$('Show {0} user(s)' -f @($users.Count))</summary><ul>$items</ul>$more</details>"
            }

            $confirmBlock = if ($c.Manual) {
                "<label class='condconfirm'><input type='checkbox' data-condkey=""$(E $c.ConditionKey)"" id=""condconfirm-$($c.DomId)""> $confirmCheckboxLabel</label>"
            } else { '' }
            [void]$sb.AppendLine("<tr><td class='name'>$(E $c.Label)<div class='why'>$(E $c.Why)</div></td><td><span id=""condstatus-$($c.DomId)"" class='status'><span class='sw' style='background:$sc'></span>$(E $lbl)</span></td><td class='$detailCls'>$(E $c.Detail)<span id=""condnote-$($c.DomId)""></span>$confirmBlock$userBlock</td></tr>")
        }
        [void]$sb.AppendLine('</table></div>')
        if (-not $wave.Open) { $anyBlockedBefore = $true }
    }

    if ($nonSeq) {
        [void]$sb.AppendLine('<div class="sec">')
        [void]$sb.AppendLine("<h2>$(E $nonSeq.Name)</h2>")
        [void]$sb.AppendLine("<p class=""intro"">$(E $nonSeq.Intro)</p>")
        [void]$sb.AppendLine('<table><tr><th style="width:32%">' + ('Condition') + '</th><th style="width:14%">' + ('Status') + '</th><th>' + ('Observation') + '</th></tr>')
        foreach ($c in $nonSeq.Conditions) {
            $sc = $statusColor[$c.Status]; if (-not $sc) { $sc = $GREY }
            $lbl = if ($c.Manual) { $manualToConfirmLabel } else { $statusLabel[$c.Status] }
            if (-not $lbl) { $lbl = $c.Status }
            $detailCls = if ($c.Status -eq 'Not assessed') { 'detail na' } else { 'detail' }

            $confirmBlock = if ($c.Manual) {
                "<label class='condconfirm'><input type='checkbox' data-condkey=""$(E $c.ConditionKey)"" id=""condconfirm-$($c.DomId)""> $confirmCheckboxLabel</label>"
            } else { '' }
            [void]$sb.AppendLine("<tr><td class='name'>$(E $c.Label)<div class='why'>$(E $c.Why)</div></td><td><span id=""condstatus-$($c.DomId)"" class='status'><span class='sw' style='background:$sc'></span>$(E $lbl)</span></td><td class='$detailCls'>$(E $c.Detail)<span id=""condnote-$($c.DomId)""></span>$confirmBlock</td></tr>")
        }
        [void]$sb.AppendLine('</table></div>')
    }

    function ConditionsPayload($conds) {
        return @(@($conds) | ForEach-Object {
                [PSCustomObject]@{ domId = $_.DomId; status = $_.Status; manual = [bool]$_.Manual; recKeys = @($_.RecKeys); condKey = [string]$_.ConditionKey }
            })
    }
    $syncPayload = [PSCustomObject]@{
        tenantId = [string]$ctx.TenantId
        waves    = @($waveResults | ForEach-Object { [PSCustomObject]@{ id = $_.Id; conditions = ConditionsPayload $_.Conditions } })
        nonSeq   = if ($nonSeq) { ConditionsPayload $nonSeq.Conditions } else { @() }
        statusLabel = $statusLabel
        gateText = @{ closed = $gateText.Closed; openPendingManual = $gateText.OpenPendingManual; open = $gateText.Open }
        manualConfirmedSentinel = ('manually confirmed')
    }
    $syncJson = $syncPayload | ConvertTo-Json -Depth 8 -Compress
    $syncJson = $syncJson -replace '</', '<\/'

    [void]$sb.AppendLine('<script id="rollout-sync-data" type="application/json">')
    [void]$sb.AppendLine($syncJson)
    [void]$sb.AppendLine('</script>')
    [void]$sb.AppendLine('<script>')
    [void]$sb.AppendLine('(function(){')
    [void]$sb.AppendLine((New-CAInvReportPalette -As 'Script' -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine(@'
  var raw = document.getElementById('rollout-sync-data');
  if (!raw) return;
  var CFG; try { CFG = JSON.parse(raw.textContent); } catch(e) { return; }
  var STORE_KEY = 'cainv-decisions:' + (CFG.tenantId || '');
  var decisions = {};
  try { decisions = JSON.parse(localStorage.getItem(STORE_KEY) || '{}') || {}; } catch(e) { decisions = {}; }

  var RANK = {'Gap':0,'Review required':1,'Not assessed':2,'Ready':3};
  var LABEL = CFG.statusLabel;
  var COLOR = {'Ready':INK,'Gap':CORAL,'Review required':YELLOW,'Not assessed':GREY};

  // 'resolved'/'dismissed' -> counts as Done for the gate (resolved, resp. accepted risk that no
  // longer blocks); 'confirmed' -> keeps the original status (acknowledged, not resolved).
  function effectiveStatus(rec){
    var dec = decisions[rec.key];
    if (dec && (dec.state==='resolved' || dec.state==='dismissed')) return 'Ready';
    return rec.status;
  }

  // Recomputes a single condition: returns the effective status and, if decisions apply to it,
  // updates the status badge + a short note in the DOM.
  function recomputeCondition(c){
    if (!c.recKeys || !c.recKeys.length) return c.status;
    var worst = null, worstRank = -1, resolvedN = 0, dismissedN = 0, confirmedN = 0, any = false;
    c.recKeys.forEach(function(rec){
      var dec = decisions[rec.key];
      if (dec) { any = true; if (dec.state==='resolved') resolvedN++; else if (dec.state==='dismissed') dismissedN++; else if (dec.state==='confirmed') confirmedN++; }
      var eff = effectiveStatus(rec);
      var r = RANK[eff]===undefined ? 2 : RANK[eff];
      if (worst===null || r<worstRank) { worst=eff; worstRank=r; }
    });
    if (!any) return c.status;
    var statusEl = document.getElementById('condstatus-'+c.domId);
    if (statusEl) { statusEl.innerHTML = '<span class="sw" style="background:'+(COLOR[worst]||GREY)+'"></span>'+(LABEL[worst]||worst); }
    var noteEl = document.getElementById('condnote-'+c.domId);
    if (noteEl) {
      var bits=[];
      if (resolvedN) bits.push(resolvedN+' resolved');
      if (dismissedN) bits.push(dismissedN+' dismissed (no longer counted)');
      if (confirmedN) bits.push(confirmedN+' confirmed (still blocking)');
      noteEl.textContent = bits.length ? (' — updated from scorecard decisions in this browser: '+bits.join(', ')+'.') : '';
    }
    return worst;
  }

  // A condition with no measurement at all is confirmed as soon as a 'resolved' decision exists
  // on its condition key. That key only exists for such conditions; see Get-CAInvConditionKey
  // for why it's built on the position and not on the label.
  function isConfirmed(c){
    if (!c.condKey) return false;
    var dec = decisions[c.condKey];
    return !!(dec && dec.state === 'resolved');
  }

  function saveDecisions(){
    try { localStorage.setItem(STORE_KEY, JSON.stringify(decisions)); } catch(e) { /* private mode: the checkbox then only works for this session */ }
  }

  function recomputeGate(wave){
    var open = wave.conditions.every(function(c){
      if (c.manual) return true;
      return recomputeCondition(c) === 'Ready';
    });
    var badge = document.getElementById('gate-'+wave.id);
    if (!badge) return;
    var anyManualPending = wave.conditions.some(function(c){ return c.manual && !isConfirmed(c); });
    badge.className = 'gate ' + (open ? 'open' : 'closed');
    badge.textContent = !open ? CFG.gateText.closed : (anyManualPending ? CFG.gateText.openPendingManual : CFG.gateText.open);
  }

  function recomputeAll(){
    CFG.waves.forEach(recomputeGate);
    (CFG.nonSeq || []).forEach(recomputeCondition);
  }

  // Checkboxes on the unmeasured conditions. They write to the same store as the scorecard
  // decisions, so export/import picks them up too, and the scorecard can recompute the
  // go-live gate from them.
  Array.prototype.forEach.call(document.querySelectorAll('input[data-condkey]'), function(box){
    var key = box.getAttribute('data-condkey');
    var dec = decisions[key];
    box.checked = !!(dec && dec.state === 'resolved');
    box.addEventListener('change', function(){
      if (box.checked) { decisions[key] = { state: 'resolved', at: new Date().toISOString(), observedAtDecision: CFG.manualConfirmedSentinel }; }
      else { delete decisions[key]; }
      saveDecisions();
      recomputeAll();
    });
  });

  recomputeAll();

  // Live sharing between report pages: see the same
  // explanation in New-CAInvReviewQueue.ps1. A decision made elsewhere (Scorecard, Review
  // required, Open work) immediately recomputes the wave gates here.
  window.addEventListener('storage', function(e){
    if (e.key !== STORE_KEY) return;
    try { decisions = JSON.parse(localStorage.getItem(STORE_KEY) || '{}') || {}; } catch(err){ decisions = {}; }
    recomputeAll();
  });
})();
</script>
'@)

    [void]$sb.AppendLine((New-CAInvReportFooter -RunId $ctx.RunId -IncludePrintLink -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine('</div></body></html>')

    Write-CAInvLog -Level 'INFO' -Message 'Rollout plan HTML built.'
    return $sb.ToString()
}
