function New-CAInvReviewQueue {
    <#
    .SYNOPSIS
        Step 2 of the guided flow — "Assess review needed".
    .DESCRIPTION
        Collects all findings with Status 'Review required' from every layer into one scrollable,
        filterable list. Uses exactly the same decision mechanism as New-CAInvScorecard
        (localStorage key cainv-decisions:{tenantId}, finding key TenantId|CheckId|ObjectId-or-
        Name|Property), so a decision made here also carries through to the scorecard and to the
        wave gate in New-CAInvRolloutPlan.

        Revised 26-08-2026 following the approach from review-nodig-voorstel.html. The underlying
        architecture stayed in place; what was added is the layer around it, because the reviewer
        used to be handed a raw observation and had to work out the question themselves:

          - THE QUESTION. Every check with a reviewQuestion in config/checkids.json shows that
            question above the group and in the side panel. Not what was measured (that's
            description) and not what to do about it (that's Recommendation), but what you
            decide. The field is optional: without a question the block disappears and nothing
            else changes.
          - GROUP DECISION UP FRONT. A button in the group header selects every not-yet-reviewed
            finding in that group. Sixteen findings that together are one judgment call used to
            cost sixteen separate actions. The order is now reversed: the group first, then
            deviate.
          - PROGRESS. A four-segment bar with the count next to it. This is the only place where
            someone sees how far along they are and which decisions are still blocking the wave
            gate.
          - GROUPING IS SWITCHABLE: by check (default), by category, or by severity. Plus a
            filter on category alongside the one on severity, because that's the selection you
            make when you're sitting at the table with a single administrator.
          - LISTS AS CHIPS. On the reference run, ObservedValue has a p90 of 308 characters and a
            maximum of 3179. A list of objects reads better as separate chips than as a comma
            string. That split happens here and not in the collector: ObservedValue is part of
            the findings record, and that's a public contract.
          - BUTTON LABELS WITH THEIR CONSEQUENCE. "Dismissed" read as "this finding is wrong",
            while it actually means "risk accepted". Now called "Accepted", with the consequence
            as a subtitle on the button itself instead of in a title attribute. NOTE: the stored
            key stays 'dismissed', otherwise previously exported decisions can no longer be read
            back.
          - A NOTE on every decision. Carried along in the store, the export, and the import. In
            an audit, that's often the only thing that matters.
          - SHORTCUTS: j/k move, 1/2/3 decide and advance, / searches, Esc closes.

        The card view remains as an alternative for anyone who prefers reading everything spelled
        out.

        Extended: status chips (Open/Confirmed/Accepted/Resolved)
        alongside the severity chips, so a finding just confirmed during the review round can be
        found again afterward to resolve it — "hide reviewed" hides all three handled statuses at
        once and doesn't let you show just one of them again. That checkbox remains next to it as
        a shortcut. A broader cross-section worklist (every Confirmed finding across all eight
        report sections, so also Gap findings that never reach this page since it filters hard on
        Status 'Review required') is a separate, deliberately not-yet-built proposal.
    .OUTPUTS
        String: the HTML content of the review queue.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ctx = $script:CAInvContext
    $lang = 'en'
    $records = @($ctx.Records | Where-Object Status -eq 'Review required')

    $catalog = $null
    $cfgObj = Get-CAInvProp $ctx 'Config'
    if ($cfgObj -is [System.Collections.IDictionary]) {
        if ($cfgObj.Contains('CheckIds')) { $catalog = $cfgObj['CheckIds'] }
    }
    elseif ($cfgObj) {
        $catalog = Get-CAInvProp $cfgObj 'CheckIds'
    }
    if (-not $catalog) {
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
    function CheckQuestion([string]$id) {
        if ($checkMap.ContainsKey($id)) { return [string](Get-CAInvProp $checkMap[$id] 'reviewQuestion') }
        return ''
    }

    function E([string]$s) { ConvertTo-CAInvHtmlSafe -Text $s }

    $export = [System.Collections.Generic.List[object]]::new()
    $idx = 0
    foreach ($rec in $records) {
        $keyObj = if (-not [string]::IsNullOrWhiteSpace([string]$rec.ObjectId)) { [string]$rec.ObjectId }
                  elseif (-not [string]::IsNullOrWhiteSpace([string]$rec.ObjectName)) { [string]$rec.ObjectName }
                  else { '' }
        $key = ('{0}|{1}|{2}|{3}' -f [string]$rec.TenantId, [string]$rec.CheckId, $keyObj, [string]$rec.Property)
        [void]$export.Add([ordered]@{
                idx           = $idx; key = $key; Layer = $rec.Layer; Category = (Get-CAInvProp $rec 'Category'); CheckId = $rec.CheckId
                ObjectType    = $rec.ObjectType; ObjectName = $rec.ObjectName; Property = $rec.Property
                ObservedValue = [string]$rec.ObservedValue; Status = $rec.Status; Severity = $rec.Severity
                Recommendation = $rec.Recommendation; NotAssessedReason = $rec.NotAssessedReason
                RawPath       = $rec.RawPath; GraphSource = $rec.GraphSource; ApiVersion = $rec.ApiVersion
                Title         = (CheckTitle $rec.CheckId); ReviewQuestion = (CheckQuestion $rec.CheckId)
                ManualReview  = [bool](Get-CAInvProp $rec 'ManualReview' $false)
            })
        $idx++
    }
    $json = if ($export.Count -eq 0) { '[]' } elseif ($export.Count -eq 1) { '[' + ($export[0] | ConvertTo-Json -Depth 5 -Compress) + ']' } else { $export | ConvertTo-Json -Depth 5 -Compress }
    $json = $json -replace '</', '<\/'

    $emptySideState = 'Choose a finding on the left.<br>Or press <kbd>j</kbd> to jump to the first one.'

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!doctype html><html lang="' + $lang + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>' + ('Review needed &middot; Conditional Access') + '</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine((New-CAInvReportPalette -Surface 'Panel' -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine(@'
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{font-family:Aileron,'Helvetica Neue',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
input,button,select,textarea{font-family:inherit}
.wrap{display:flex;flex-direction:column;height:100%}
.top{background:var(--ink);color:#fff;padding:12px 22px;display:flex;align-items:baseline;gap:14px;flex:0 0 auto}
.top .arrow{color:var(--yellow);font-weight:700}
.top .nm{font-weight:700;letter-spacing:-.01em}
.top .ctx{margin-inline-start:auto;font-size:12px;opacity:.75}
.prog{flex:0 0 auto;padding:14px 22px 10px;border-bottom:1px solid var(--line);background:var(--panel)}
.prog h1{margin:0 0 3px;font-size:17px;letter-spacing:-.01em}
.prog .sub{color:var(--muted);font-size:12.5px;margin-bottom:9px}
.bar{height:7px;border-radius:4px;background:var(--line);overflow:hidden;display:flex}
.bar i{display:block;height:100%}
.bar .b-open{background:var(--coral)}
.bar .b-conf{background:var(--yellow)}
.bar .b-dism{background:var(--grey)}
.bar .b-res{background:var(--ok)}
.legend{display:flex;gap:16px;margin-top:7px;font-size:12px;color:var(--muted);flex-wrap:wrap}
.legend b{color:var(--text);font-weight:600}
.dot{width:8px;height:8px;border-radius:2px;display:inline-block;margin-right:5px;vertical-align:middle}
.tools{flex:0 0 auto;display:flex;gap:8px;align-items:center;padding:10px 22px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.search{flex:1 1 260px;min-width:200px;position:relative}
.search input{width:100%;padding:7px 11px 7px 30px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--text);font:inherit;font-size:13px}
.search input:focus{outline:2px solid var(--yellow);outline-offset:-1px}
.search .ic{position:absolute;left:9px;top:7px;color:var(--muted);font-size:13px}
.chip{border:1px solid var(--line);background:var(--bg);color:var(--text);border-radius:20px;padding:5px 11px;font:inherit;font-size:12px;cursor:pointer;white-space:nowrap}
.chip:hover{border-color:var(--ink)}
.chip.on{background:var(--ink);color:#fff;border-color:var(--ink)}
.chip .n{opacity:.65;margin-left:4px}
.sel{border:1px solid var(--line);border-radius:6px;padding:6px 8px;font:inherit;font-size:12.5px;background:var(--bg);color:var(--text)}
.tools label{font-size:12.5px;color:var(--muted)}
.tools .sp{flex:1}
.dbtn{border:1px solid var(--line);background:var(--bg);color:var(--ink);border-radius:6px;padding:5px 11px;font:inherit;font-size:12px;cursor:pointer}
.dbtn:hover{border-color:var(--ink)}
.main{flex:1 1 auto;display:flex;min-height:0}
.list{flex:1 1 auto;overflow:auto;padding:0 0 90px}
.grp{border-bottom:1px solid var(--line)}
.gh{display:flex;align-items:center;gap:9px;padding:11px 22px;background:var(--panel);cursor:pointer;position:sticky;top:0;z-index:2}
.gh:hover{background:var(--line)}
.gh .tw{color:var(--muted);font-size:11px;width:11px}
.sw{width:9px;height:9px;border-radius:2px;display:inline-block;flex:0 0 auto}
.gh .gt{font-weight:600}
.gh .gc{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:var(--muted);background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:1px 6px}
.gh .cat{font-size:11.5px;color:var(--muted)}
.gh .cnt{margin-left:auto;font-size:12px;color:var(--muted)}
.gh .bulkbtn{font-size:11.5px;border:1px solid var(--line);background:var(--bg);color:var(--ink);border-radius:5px;padding:3px 9px;cursor:pointer;font-family:inherit}
.gh .bulkbtn:hover{border-color:var(--ink);background:var(--yellow);color:var(--ink)}
.q{padding:9px 22px 11px 46px;background:var(--panel);border-bottom:1px solid var(--line);font-size:13px;color:var(--text)}
.q b{color:var(--ink)}
.row{display:grid;grid-template-columns:26px 1fr auto auto;gap:11px;align-items:center;padding:9px 22px;border-bottom:1px solid var(--line);cursor:pointer}
.row:hover{background:var(--panel)}
.row.open{background:var(--panel);box-shadow:inset 3px 0 0 var(--yellow)}
.row .obj{font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .ov{color:var(--muted);font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .ov.noval{font-style:italic;opacity:.85}
.row .st{font-size:11.5px;padding:2px 8px;border-radius:11px;border:1px solid var(--line);color:var(--muted);white-space:nowrap}
.row .st.confirmed{background:var(--yellow);color:#3a2c00;border-color:transparent}
.row .st.dismissed{background:var(--grey);color:#fff;border-color:transparent}
.row .st.resolved{background:var(--ok);color:#fff;border-color:transparent}
.row input[type=checkbox]{width:15px;height:15px;accent-color:var(--ink)}
.row.done{opacity:.55}
.chg{font-size:10.5px;color:var(--coral);border:1px solid var(--coral);border-radius:9px;padding:0 6px;white-space:nowrap}
.card{border-bottom:1px solid var(--line);padding:14px 22px}
.card h4{margin:0 0 3px;font-size:14px}
.card .cm{font-size:11.5px;color:var(--muted);margin-bottom:6px}
.card p{margin:0 0 7px;font-size:13px}
.side{flex:0 0 420px;border-left:1px solid var(--line);background:var(--panel);overflow:auto;display:flex;flex-direction:column}
.side.empty{align-items:center;justify-content:center;color:var(--muted);font-size:13px;text-align:center;padding:30px}
.sh{padding:16px 20px;border-bottom:1px solid var(--line);background:var(--bg)}
.sh .meta{display:flex;align-items:center;gap:8px;font-size:11.5px;color:var(--muted);margin-bottom:7px;flex-wrap:wrap}
.sh h2{margin:0 0 4px;font-size:16px;letter-spacing:-.01em}
.sh .obj{font-size:13px;color:var(--muted)}
.sbody{padding:16px 20px;flex:1 1 auto}
.ask{background:var(--yellow);color:#3a2c00;border-radius:7px;padding:11px 13px;font-size:13.5px;font-weight:600;margin-bottom:13px}
.blk{margin-bottom:13px}
.blk h3{margin:0 0 5px;font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);font-weight:700}
.blk p{margin:0;font-size:13px}
.pills{display:flex;flex-wrap:wrap;gap:5px}
.pill{background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:2px 7px;font-size:11.5px;font-family:ui-monospace,Consolas,monospace}
.src{font-size:11.5px;color:var(--muted);font-family:ui-monospace,Consolas,monospace;word-break:break-all}
.sfoot{position:sticky;bottom:0;background:var(--bg);border-top:1px solid var(--line);padding:12px 20px}
.acts{display:grid;grid-template-columns:1fr 1fr 1fr;gap:7px;margin-bottom:9px}
.act{border:1px solid var(--line);background:var(--bg);color:var(--text);border-radius:6px;padding:9px 4px;cursor:pointer;font:inherit;font-size:12.5px;text-align:center;line-height:1.25}
.act small{display:block;font-size:10.5px;color:var(--muted);margin-top:2px}
.act:hover{border-color:var(--ink)}
.act.on-confirmed{background:var(--yellow);border-color:transparent;color:#3a2c00}
.act.on-dismissed{background:var(--grey);border-color:transparent;color:#fff}
.act.on-resolved{background:var(--ok);border-color:transparent;color:#fff}
.act.on-confirmed small,.act.on-dismissed small,.act.on-resolved small{color:inherit;opacity:.8}
.note{width:100%;border:1px solid var(--line);border-radius:6px;padding:7px 9px;font:inherit;font-size:12.5px;background:var(--bg);color:var(--text);resize:vertical;min-height:34px}
.nav{display:flex;gap:7px;align-items:center;margin-top:9px;font-size:11.5px;color:var(--muted)}
.nav button{border:1px solid var(--line);background:var(--bg);color:var(--text);border-radius:5px;padding:3px 9px;cursor:pointer;font:inherit}
.nav button:disabled{opacity:.4;cursor:default}
kbd{border:1px solid var(--line);border-bottom-width:2px;border-radius:4px;padding:0 4px;font-size:10.5px;background:var(--bg);font-family:ui-monospace,Consolas,monospace}
.bulk{position:fixed;bottom:0;left:0;right:420px;background:var(--ink);color:#fff;padding:11px 22px;display:none;align-items:center;gap:11px;z-index:5;flex-wrap:wrap}
.bulk.on{display:flex}
.bulk .bc{font-weight:700}
.bulk .bm{opacity:.75;font-size:12.5px}
.bulk button{border:1px solid rgba(255,255,255,.3);background:transparent;color:#fff;border-radius:5px;padding:5px 11px;cursor:pointer;font:inherit;font-size:12.5px}
.bulk button:hover{background:rgba(255,255,255,.14)}
.bulk .x{margin-left:auto;border:0;font-size:17px;line-height:1;padding:2px 7px}
.hint{padding:22px;color:var(--muted);font-size:13px}
@media (max-width:1000px){ .side{display:none} .bulk{right:0} }
</style>
'@)

    [void]$sb.AppendLine('</head><body><div class="wrap">')
    [void]$sb.AppendLine((New-CAInvReportTopbar -Variant 'Compact' -RunId $ctx.RunId -Brand (Get-CAInvProp $ctx 'Brand')))

    [void]$sb.AppendLine('<div class="prog"><h1>' + ('Assess review needed') + '</h1><div class="sub" id="sub"></div><div class="bar" id="bar"></div><div class="legend" id="legend"></div></div>')

    [void]$sb.AppendLine('<div class="tools">' +
        '<div class="search"><span class="ic">&#9906;</span><input id="dfilter" type="search" placeholder="' + ('Search by name, group, app, or observation&hellip; (press /)') + '" autocomplete="off"></div>' +
        '<span id="dfacets"></span>' +
        '<span id="sfacets" style="display:flex;gap:6px;flex-wrap:wrap"></span>' +
        '<select class="sel" id="grpby" aria-label="' + ('Group by') + '"><option value="check">' + ('Group by check') + '</option><option value="cat">' + ('Group by category') + '</option><option value="sev">' + ('Group by severity') + '</option></select>' +
        '<select class="sel" id="catf" aria-label="' + ('Filter by category') + '"><option value="">' + ('All categories') + '</option></select>' +
        '<label><input type="checkbox" id="hidedecided">' + (' hide reviewed') + '</label>' +
        '<label><input type="checkbox" id="hidemanual" title="' + ('Hide findings that can only be assessed by human judgment') + '"> hide &quot;' + ('human judgment only') + '&quot;</label>' +
        '<span class="sp"></span>' +
        '<button class="chip" id="viewtoggle" type="button">' + ('Cards') + '</button>' +
        '<button class="dbtn" id="btnexport" type="button">' + ('Export') + '</button>' +
        '<button class="dbtn" id="btnimport" type="button">' + ('Import') + '</button>' +
        '<input id="fileimport" type="file" accept="application/json,.json" style="display:none">' +
        '</div>')

    [void]$sb.AppendLine('<div class="main"><div class="list" id="dlist"></div><div class="side empty" id="side">' + $emptySideState + '</div></div>')
    [void]$sb.AppendLine('<div class="bulk" id="bulk" role="toolbar" aria-label="' + ('Bulk review') + '"></div>')
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine("<script>window.__CAINV_TENANT=""$(E $ctx.TenantId)"";</script>")
    [void]$sb.AppendLine('<script id="findings-data" type="application/json">')
    [void]$sb.AppendLine($json)
    [void]$sb.AppendLine('</script>')
    [void]$sb.AppendLine('<script>')
    [void]$sb.AppendLine('(function(){')
    [void]$sb.AppendLine((New-CAInvReportPalette -As 'Script' -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine(@'
  var DATA = JSON.parse(document.getElementById('findings-data').textContent);
  var SEV_COLOR={High:CORAL,Medium:YELLOW,Low:GREY,Info:GREY};
  var SEV_ORDER={High:0,Medium:1,Low:2,Info:3};
  // Zero is falsy: without the explicit null check, High (0) would end up as unknown. There's
  // a regression test for that.
  function sevOrder(s){ var v=SEV_ORDER[s]; return (v==null)?9:v; }
  function sevColor(s){ return SEV_COLOR[s]||GREY; }
  // The stored key stays 'dismissed'; only the label changed to Accepted, otherwise previously
  // exported decisions could no longer be read back.
  var LBL={confirmed:'Confirmed',dismissed:'Accepted',resolved:'Resolved'};
  var ACTS=[['confirmed',LBL.confirmed,'keeps blocking'],['dismissed',LBL.dismissed,'risk accepted'],['resolved',LBL.resolved,'counts as done']];
  // Status filter (29-08-2026): the same three decisions plus 'open', as separately toggleable
  // chips next to the severity chips — so after a review round you can specifically find the
  // Accepted items again to resolve them, instead of only "hide everything reviewed".
  var STATE_ORDER=['open','confirmed','dismissed','resolved'];
  function stateLabel(s){ return s==='open' ? 'Open' : (LBL[s]||s); }

  var TENANT = window.__CAINV_TENANT || '';
  var STORE_KEY = 'cainv-decisions:' + TENANT;
  var decisions = {};
  try { decisions = JSON.parse(localStorage.getItem(STORE_KEY) || '{}') || {}; } catch(e){ decisions = {}; }
  function persist(){ try { localStorage.setItem(STORE_KEY, JSON.stringify(decisions)); } catch(e){} }
  function getDecision(k){ return decisions[k] || null; }
  function isChanged(r,d){ return !!(d && d.observedAtDecision!=null && String(d.observedAtDecision)!==String(r.ObservedValue==null?'':r.ObservedValue)); }

  var q='', fSev=new Set(), fState=new Set(), fCat='', hideDecided=false, hideManual=false;
  var grpBy='check', openKey=null, selected=new Set(), collapsed=new Set(), flat=[], viewMode='table';

  var $=function(i){ return document.getElementById(i); };
  var list=$('dlist'), side=$('side'), bulk=$('bulk'), dfilter=$('dfilter'), dfacets=$('dfacets'), sfacets=$('sfacets');

  function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }
  function title(r){ return r.Title||r.CheckId; }
  function askOf(r){ return r.ReviewQuestion||''; }
  function recByKey(k){ for(var i=0;i<DATA.length;i++){ if(DATA[i].key===k) return DATA[i]; } return null; }
  function groupKey(r){ return grpBy==='cat' ? (r.Category||'unknown') : grpBy==='sev' ? r.Severity : r.CheckId; }
  function stateOf(r){ var d=getDecision(r.key); return d?d.state:'open'; }

  function decide(keys,state){
    keys.forEach(function(k){
      var r=recByKey(k); if(!r) return;
      var prev=decisions[k];
      decisions[k]={ state:state, at:new Date().toISOString(),
                     observedAtDecision:(r.ObservedValue==null?'':String(r.ObservedValue)),
                     note:(prev&&prev.note)||'' };
    });
    persist(); paint();
  }

  function paintProg(){
    var n=DATA.length, c=0,d=0,rs=0;
    DATA.forEach(function(r){ var s=decisions[r.key]; if(!s||!s.state) return;
      if(s.state==='confirmed')c++; else if(s.state==='dismissed')d++; else rs++; });
    var openN=n-c-d-rs;
    $('sub').innerHTML = n===0 ? 'No findings requiring human judgment.'
      : (openN===0 ? '<b>'+'All '+n+' reviewed.'+'</b>'+' The wave gate has been updated.'
                   : openN+' '+'of'+' '+n+' still to review &middot; '+(n-openN)+' handled');
    var pct=function(x){ return (n?(x/n*100):0).toFixed(2)+'%'; };
    $('bar').innerHTML='<i class="b-open" style="width:'+pct(openN)+'"></i><i class="b-conf" style="width:'+pct(c)+'"></i><i class="b-dism" style="width:'+pct(d)+'"></i><i class="b-res" style="width:'+pct(rs)+'"></i>';
    $('legend').innerHTML='<span><span class="dot" style="background:'+CORAL+'"></span>'+'To review'+' <b>'+openN+'</b></span>'
      +'<span><span class="dot" style="background:'+YELLOW+'"></span>'+'Confirmed, blocks the wave'+' <b>'+c+'</b></span>'
      +'<span><span class="dot" style="background:'+GREY+'"></span>'+'Accepted risk'+' <b>'+d+'</b></span>'
      +'<span><span class="dot" style="background:'+OK+'"></span>'+'Resolved'+' <b>'+rs+'</b></span>';
  }

  function buildFilters(){
    var sev={}; DATA.forEach(function(r){ sev[r.Severity]=(sev[r.Severity]||0)+1; });
    var keys=Object.keys(sev).sort(function(a,b){ return sevOrder(a)-sevOrder(b); });
    dfacets.innerHTML = keys.length<2 ? '' : keys.map(function(k){
      return '<button class="chip'+(fSev.has(k)?' on':'')+'" data-sev="'+esc(k)+'"><span class="sw" style="background:'+sevColor(k)+'"></span> '+esc(k)+'<span class="n">'+sev[k]+'</span></button>';
    }).join(' ');
    var cats={}; DATA.forEach(function(r){ if(r.Category) cats[r.Category]=(cats[r.Category]||0)+1; });
    var cur=$('catf').value;
    $('catf').innerHTML='<option value="">'+'All categories'+'</option>'+Object.keys(cats).sort().map(function(c){
      return '<option value="'+esc(c)+'">'+esc(c)+' ('+cats[c]+')</option>';
    }).join('');
    $('catf').value=cur;
  }

  // Counts over the full DATA set, not over what the other filters already let through — same
  // semantics as the severity chips in buildFilters above.
  function buildStateFacets(){
    var counts={open:0,confirmed:0,dismissed:0,resolved:0};
    DATA.forEach(function(r){ counts[stateOf(r)]++; });
    sfacets.innerHTML = STATE_ORDER.map(function(s){
      return '<button class="chip'+(fState.has(s)?' on':'')+'" data-state="'+s+'">'+stateLabel(s)+'<span class="n">'+counts[s]+'</span></button>';
    }).join(' ');
  }

  function visible(){
    return DATA.filter(function(r){
      if(fSev.size && !fSev.has(r.Severity)) return false;
      if(fState.size && !fState.has(stateOf(r))) return false;
      if(fCat && r.Category!==fCat) return false;
      if(hideDecided && getDecision(r.key)) return false;
      if(hideManual && r.ManualReview) return false;
      if(!q) return true;
      var h=[r.ObjectName,r.ObservedValue,r.CheckId,r.Category,r.Property,title(r),r.Recommendation].join(' ').toLowerCase();
      return h.indexOf(q)>=0;
    });
  }

  // Heaviest severity first, then the largest group, then alphabetically. Unchanged behavior.
  function groupsOf(rows){
    var by={},ord=[];
    rows.forEach(function(r){ var k=groupKey(r); if(!by[k]){by[k]=[];ord.push(k);} by[k].push(r); });
    ord.sort(function(a,b){
      var sa=Math.min.apply(null,by[a].map(function(r){return sevOrder(r.Severity);}));
      var sb=Math.min.apply(null,by[b].map(function(r){return sevOrder(r.Severity);}));
      if(sa!==sb) return sa-sb;
      if(by[b].length!==by[a].length) return by[b].length-by[a].length;
      return a<b?-1:1;
    });
    return ord.map(function(k){ return {k:k,items:by[k]}; });
  }

  function cardHtml(r){
    var d=getDecision(r.key);
    var h='<div class="card" data-k="'+esc(r.key)+'">';
    h+='<div class="cm"><span class="sw" style="background:'+sevColor(r.Severity)+'"></span> '+esc(r.Severity)+' &middot; '+esc(r.CheckId)+' &middot; '+esc(r.Category||'')+(d?' &middot; '+esc(LBL[d.state]):'')+'</div>';
    h+='<h4>'+esc(title(r))+'</h4>';
    if(askOf(r)){ h+='<p><b>'+esc(askOf(r))+'</b></p>'; }
    h+='<div class="cm">'+esc(r.ObjectName||'tenant-wide')+'</div>';
    if(r.ObservedValue){ h+='<p>'+esc(r.ObservedValue)+'</p>'; }
    if(r.Recommendation){ h+='<p>'+esc(r.Recommendation)+'</p>'; }
    h+='</div>';
    return h;
  }

  function paintList(){
    var rows=visible(); flat=[];
    if(!rows.length){ list.innerHTML='<div class="hint">'+'Nothing found with these filters.'+'</div>'; return; }
    if(viewMode==='cards'){
      var sorted=rows.slice().sort(function(a,b){ return sevOrder(a.Severity)-sevOrder(b.Severity); });
      sorted.forEach(function(r){ flat.push(r); });
      list.innerHTML=sorted.map(cardHtml).join('');
      return;
    }
    var gs=groupsOf(rows), h='';
    gs.forEach(function(g){
      var first=g.items[0];
      var worst=g.items.reduce(function(a,b){ return sevOrder(a.Severity)<=sevOrder(b.Severity)?a:b; });
      var openN=g.items.filter(function(r){ return !getDecision(r.key); }).length;
      var isColl=collapsed.has(g.k);
      var label = grpBy==='check' ? title(first) : g.k;
      h+='<div class="grp"><div class="gh" data-g="'+esc(g.k)+'">';
      h+='<span class="tw">'+(isColl?'&#9656;':'&#9662;')+'</span>';
      h+='<span class="sw" style="background:'+sevColor(worst.Severity)+'"></span>';
      h+='<span class="gt">'+esc(label)+'</span>';
      if(grpBy==='check'){ h+='<span class="gc">'+esc(g.k)+'</span><span class="cat">'+'to resolve in '+esc(first.Category||'')+'</span>'; }
      h+='<span class="cnt">'+g.items.length+' &middot; '+(openN?openN+' to do':'done')+'</span>';
      // Only with two or more open findings: for a single one, the button is noise.
      if(openN>1){ h+='<button class="bulkbtn" data-bulk="'+esc(g.k)+'">'+'decide all '+openN+' at once'+'</button>'; }
      h+='</div>';
      if(!isColl){
        if(grpBy==='check' && askOf(first)){ h+='<div class="q"><b>'+'Question:'+'</b> '+esc(askOf(first))+'</div>'; }
        g.items.forEach(function(r){
          flat.push(r);
          var d=getDecision(r.key);
          h+='<div class="row'+(openKey===r.key?' open':'')+(d?' done':'')+'" data-k="'+esc(r.key)+'">';
          h+='<input type="checkbox" data-cb="'+esc(r.key)+'"'+(selected.has(r.key)?' checked':'')+'>';
          h+='<span class="obj">'+esc(r.ObjectName||'tenant-wide')+'</span>';
          // An empty observation would be a gap in the column; fall back to the recommendation
          // and mark it as such, so the reader sees this isn't a measured value.
          var ovTxt=(r.ObservedValue==null?'':String(r.ObservedValue));
          var ovCls='ov';
          if(!ovTxt){ ovTxt=(r.Recommendation||r.NotAssessedReason||''); ovCls='ov noval'; }
          h+='<span class="'+ovCls+'">'+esc(ovTxt.slice(0,150))+'</span>';
          h+='<span class="sw" style="background:'+sevColor(r.Severity)+'" title="'+esc(r.Severity)+'"></span>';
          h+=isChanged(r,d)?'<span class="chg">'+'value changed'+'</span>':'';
          h+='<span class="st'+(d?' '+d.state:'')+'">'+(d?esc(LBL[d.state]):'open')+'</span>';
          h+='</div>';
        });
      }
      h+='</div>';
    });
    list.innerHTML=h;
  }

  // A list of objects reads better as separate chips than as a comma string. Deliberately done
  // here and not in the collector: ObservedValue is part of the public findings record.
  function splitNames(ov){
    var m=ov.match(/(?:Accounts|Gebruikers|Groepen|Apps|Applicaties|Devices|Apparaten):\s*(.+)$/);
    if(m && m[1].indexOf(',')>0){
      return { text: ov.slice(0,m.index).trim(), names: m[1].split(',').map(function(s){return s.trim();}).filter(Boolean) };
    }
    if(ov.indexOf('@')>0 && ov.split(',').length>3 && ov.length<900){
      return { text:'', names: ov.split(',').map(function(s){return s.trim();}).filter(Boolean) };
    }
    return { text: ov, names: null };
  }

  function paintSide(){
    var r=recByKey(openKey);
    if(!r){ side.className='side empty'; side.innerHTML='Choose a finding on the left.<br>Or press <kbd>j</kbd> to jump to the first one.'; return; }
    side.className='side';
    var d=getDecision(r.key);
    var pos=flat.map(function(x){return x.key;}).indexOf(openKey);
    var sp=splitNames(r.ObservedValue||'');

    var h='<div class="sh"><div class="meta"><span class="sw" style="background:'+sevColor(r.Severity)+'"></span> '+esc(r.Severity);
    h+='<span class="pill">'+esc(r.CheckId)+'</span>';
    if(r.ManualReview){ h+='<span class="pill">'+'human judgment only'+'</span>'; }
    if(isChanged(r,d)){ h+='<span class="chg">'+'value changed since your decision'+'</span>'; }
    h+='</div><h2>'+esc(title(r))+'</h2><div class="obj">'+esc(r.ObjectName||'tenant-wide')+'</div></div>';

    h+='<div class="sbody">';
    if(askOf(r)){ h+='<div class="ask">'+esc(askOf(r))+'</div>'; }
    if(sp.text){ h+='<div class="blk"><h3>'+'What we saw'+'</h3><p>'+esc(sp.text)+'</p></div>'; }
    if(sp.names && sp.names.length){
      h+='<div class="blk"><h3>'+sp.names.length+' '+(sp.names.length===1?'object':'objects')+'</h3><div class="pills">';
      sp.names.slice(0,40).forEach(function(n){ h+='<span class="pill">'+esc(n)+'</span>'; });
      if(sp.names.length>40){ h+='<span class="pill">+'+(sp.names.length-40)+'</span>'; }
      h+='</div></div>';
    }
    var advies=r.Recommendation||r.NotAssessedReason||'';
    if(advies){ h+='<div class="blk"><h3>'+'What to do about it'+'</h3><p>'+esc(advies)+'</p></div>'; }
    h+='<div class="blk"><h3>'+'Resolved in'+'</h3><p>'+esc(r.Category||'not determined')+'</p></div>';
    h+='<div class="blk"><h3>'+'Evidence'+'</h3><div class="src">'+esc((r.GraphSource||'n/a')+(r.RawPath?('  ·  '+r.RawPath):''))+'</div></div>';
    h+='</div>';

    h+='<div class="sfoot"><div class="acts">';
    ACTS.forEach(function(a){
      var on=d&&d.state===a[0];
      h+='<button class="act'+(on?' on-'+a[0]:'')+'" data-act="'+a[0]+'">'+a[1]+'<small>'+a[2]+'</small></button>';
    });
    h+='</div>';
    h+='<textarea class="note" id="note" placeholder="'+'Why? (included in the export)'+'">'+esc(d&&d.note?d.note:'')+'</textarea>';
    h+='<div class="nav"><button data-nav="-1"'+(pos<=0?' disabled':'')+'>&#9650;</button>';
    h+='<button data-nav="1"'+(pos<0||pos>=flat.length-1?' disabled':'')+'>&#9660;</button>';
    h+='<span>'+(pos+1)+' '+'of'+' '+flat.length+'</span>';
    h+='<span style="margin-left:auto">'+'<kbd>j</kbd><kbd>k</kbd> move &middot; <kbd>1</kbd><kbd>2</kbd><kbd>3</kbd> decide &middot; <kbd>/</kbd> search'+'</span></div></div>';
    side.innerHTML=h;
  }

  function paintBulk(){
    if(!selected.size){ bulk.className='bulk'; bulk.innerHTML=''; return; }
    bulk.className='bulk on';
    bulk.innerHTML='<span class="bc">'+selected.size+' selected'+'</span><span class="bm">'+'decide all at once'+'</span>'
      +ACTS.map(function(a){ return '<button data-b="'+a[0]+'">'+a[1]+'</button>'; }).join('')
      +'<button class="x" data-b="clear">&times;</button>';
  }

  function paint(){
    // What falls out of view must not silently stay part of a bulk action or stay open.
    var vis={}; visible().forEach(function(r){ vis[r.key]=true; });
    Array.from(selected).forEach(function(k){ if(!vis[k]) selected.delete(k); });
    if(openKey && !vis[openKey]) openKey=null;
    buildStateFacets(); paintProg(); paintList(); paintSide(); paintBulk();
  }

  function step(n){
    if(!flat.length) return;
    var p=flat.map(function(x){return x.key;}).indexOf(openKey);
    var t=p<0?0:p+n;
    if(t<0||t>=flat.length) return;
    openKey=flat[t].key; paint();
    var el=list.querySelector('.row.open'); if(el&&el.scrollIntoView) el.scrollIntoView({block:'nearest'});
  }

  list.addEventListener('click', function(e){
    var b=e.target.closest('[data-bulk]');
    if(b){ e.stopPropagation();
      var gk=b.getAttribute('data-bulk');
      visible().filter(function(r){ return groupKey(r)===gk && !getDecision(r.key); }).forEach(function(r){ selected.add(r.key); });
      paint(); return; }
    var cb=e.target.closest('[data-cb]');
    if(cb){ e.stopPropagation(); var k=cb.getAttribute('data-cb');
      if(cb.checked) selected.add(k); else selected.delete(k); paintBulk(); return; }
    var gh=e.target.closest('.gh');
    if(gh){ var g=gh.getAttribute('data-g'); if(collapsed.has(g)) collapsed.delete(g); else collapsed.add(g); paint(); return; }
    var row=e.target.closest('[data-k]');
    if(row){ openKey=row.getAttribute('data-k'); paint(); }
  });

  side.addEventListener('click', function(e){
    var a=e.target.closest('[data-act]');
    if(a){ decide([openKey], a.getAttribute('data-act')); return; }
    var n=e.target.closest('[data-nav]');
    if(n){ step(parseInt(n.getAttribute('data-nav'),10)); }
  });
  side.addEventListener('input', function(e){
    if(e.target.id==='note' && openKey){
      var cur=decisions[openKey]||{ state:null, at:new Date().toISOString() };
      cur.note=e.target.value; decisions[openKey]=cur; persist();
    }
  });

  bulk.addEventListener('click', function(e){
    var b=e.target.closest('[data-b]'); if(!b) return;
    var v=b.getAttribute('data-b');
    if(v==='clear'){ selected.clear(); paint(); return; }
    decide(Array.from(selected), v); selected.clear(); paint();
  });

  dfilter.addEventListener('input', function(e){ q=(e.target.value||'').toLowerCase().trim(); paint(); });
  dfacets.addEventListener('click', function(e){
    var c=e.target.closest('[data-sev]'); if(!c) return;
    var s=c.getAttribute('data-sev'); if(fSev.has(s)) fSev.delete(s); else fSev.add(s);
    buildFilters(); paint();
  });
  sfacets.addEventListener('click', function(e){
    var c=e.target.closest('[data-state]'); if(!c) return;
    var s=c.getAttribute('data-state'); if(fState.has(s)) fState.delete(s); else fState.add(s);
    paint();
  });
  $('catf').addEventListener('change', function(e){ fCat=e.target.value; paint(); });
  $('grpby').addEventListener('change', function(e){ grpBy=e.target.value; collapsed.clear(); paint(); });
  $('hidedecided').addEventListener('change', function(e){ hideDecided=e.target.checked; paint(); });
  $('hidemanual').addEventListener('change', function(e){ hideManual=e.target.checked; paint(); });
  $('viewtoggle').addEventListener('click', function(e){
    viewMode = viewMode==='table' ? 'cards' : 'table';
    e.target.textContent = viewMode==='table' ? 'Cards' : 'Table';
    selected.clear(); paint();
  });

  document.addEventListener('keydown', function(e){
    var t=e.target.tagName;
    if(t==='INPUT'||t==='TEXTAREA'||t==='SELECT'){ if(e.key==='Escape'){ e.target.blur(); } return; }
    if(e.key==='/'){ e.preventDefault(); dfilter.focus(); return; }
    if(e.key==='j'||e.key==='ArrowDown'){ e.preventDefault(); step(1); return; }
    if(e.key==='k'||e.key==='ArrowUp'){ e.preventDefault(); step(-1); return; }
    if(e.key==='Escape'){ if(selected.size){ selected.clear(); paint(); } else { openKey=null; paint(); } return; }
    if(!openKey) return;
    if(e.key==='1'){ decide([openKey],'confirmed'); step(1); }
    if(e.key==='2'){ decide([openKey],'dismissed'); step(1); }
    if(e.key==='3'){ decide([openKey],'resolved'); step(1); }
  });

  var btnExport=$('btnexport');
  if(btnExport){ btnExport.addEventListener('click',function(){
    var payload={ tenantId:TENANT, exportedAt:new Date().toISOString(), decisions:decisions };
    var blob=new Blob([JSON.stringify(payload,null,2)],{type:'application/json'});
    var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='review-decisions.json';
    document.body.appendChild(a); a.click(); setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); },0);
  }); }

  var fileImport=$('fileimport'), btnImport=$('btnimport');
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
            if(!mine || !mine.at || (theirs.at && theirs.at>mine.at)){ decisions[k]=theirs; }
          });
          persist(); paint();
        }catch(err){ alert('Could not read this file as decisions JSON.'); }
        fileImport.value='';
      };
      rd.readAsText(f);
    });
  }

  // Live sharing between report pages: when mounted in
  // report.html, localStorage.getItem/setItem runs through a proxy to shared in-memory state on
  // the parent page; this listener makes sure a decision made ELSEWHERE (Scorecard, Rollout
  // plan, Open work) repaints here immediately. Opened standalone (no parent, real
  // localStorage) this only fires on a 'storage' event from an ANOTHER tab on the same
  // origin — never in the tab that wrote it itself, that's normal browser behavior.
  window.addEventListener('storage', function(e){
    if (e.key !== STORE_KEY) return;
    try { decisions = JSON.parse(localStorage.getItem(STORE_KEY) || '{}') || {}; } catch(err){ decisions = {}; }
    paint();
  });

  buildFilters();
  paint();
})();
</script>
'@)
    [void]$sb.AppendLine('</body></html>')
    Write-CAInvLog -Level 'INFO' -Message 'Review-required HTML built.'
    return $sb.ToString()
}
