function New-CAInvOpenWork {
    <#
    .SYNOPSIS
        Cross-section work list: everything that still actually needs resolving, across both Gap AND Review
        required, mixed across all report sections.
    .DESCRIPTION
        A Gap finding is by definition already technically demonstrably wrong (§2b of the same
        roadmap: "not confirmed is not trusted" already applies at the measurement level) and so
        doesn't need a separate confirmation first to appear here; a Review required finding DOES
        need a human judgment first — that's exactly the difference between the two statuses —
        and so only joins this list after clicking "Confirmed" in the Review Queue. Concretely,
        client-side (the decision can still change after this report is generated, so this
        criterion is NEVER pre-filtered server-side):
          - Status Gap: shown unless the decision is 'dismissed' or 'resolved'.
          - Status Review required: shown only when the decision is 'confirmed'.
        Not assessed stays out of scope, as everywhere else.

        Reuses the list/side panel/decision buttons/note field/shortcuts/export-import machinery
        from New-CAInvReviewQueue.ps1 almost unchanged — same localStorage key
        (cainv-decisions:{tenantId}) and the same finding-key format
        (TenantId|CheckId|ObjectId-or-Name|Property), so a decision here also carries through to
        the other report pages. Added relative to the Review Queue: a Status facet
        (Deviation/Review), since this page spans two statuses; omitted: "hide reviewed" (the
        inclusion criterion above already does that job) and the four-segment progress bar
        (dismissed/resolved never occur here by definition, since those leave the list).

        Deliberately NO fifth numbered stepper step: like the Reference page, it has no navigation
        of its own, it relies on New-CAInvCombinedReport's tab bar. Like the other flow pages, the
        report still produces its own standalone HTML text and is tested on its own; only inside
        New-CAInvCombinedReport (§7) is it mounted as a same-origin srcdoc iframe so decisions
        genuinely share live between pages, offline too and in Firefox too.
    .OUTPUTS
        String: the HTML content of the page.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ctx = $script:CAInvContext
    $lang = 'en'
    $records = @($ctx.Records | Where-Object { $_.Status -eq 'Gap' -or $_.Status -eq 'Review required' })

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
    [void]$sb.AppendLine('<!doctype html><html lang="' + $lang + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>' + ('Open work &middot; Conditional Access') + '</title>')
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
.row{display:grid;grid-template-columns:1fr auto auto auto;gap:11px;align-items:center;padding:9px 22px;border-bottom:1px solid var(--line);cursor:pointer}
.row:hover{background:var(--panel)}
.row.open{background:var(--panel);box-shadow:inset 3px 0 0 var(--yellow)}
.row .obj{font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .ov{color:var(--muted);font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .ov.noval{font-style:italic;opacity:.85}
.row .stp{font-size:11px;padding:2px 7px;border-radius:9px;font-weight:700;white-space:nowrap}
.row .stp.gap{background:var(--coral);color:#fff}
.row .stp.review{background:var(--yellow);color:#3a2c00}
.row .st{font-size:11.5px;padding:2px 8px;border-radius:11px;border:1px solid var(--line);color:var(--muted);white-space:nowrap}
.row .st.confirmed{background:var(--yellow);color:#3a2c00;border-color:transparent}
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

    [void]$sb.AppendLine('<div class="prog"><h1>' + ('Open work') + '</h1><div class="sub" id="sub"></div><div class="bar" id="bar"></div><div class="legend" id="legend"></div></div>')

    [void]$sb.AppendLine('<div class="tools">' +
        '<div class="search"><span class="ic">&#9906;</span><input id="dfilter" type="search" placeholder="' + ('Search by name, group, app, or observation&hellip; (press /)') + '" autocomplete="off"></div>' +
        '<span id="stfacets" style="display:flex;gap:6px;flex-wrap:wrap"></span>' +
        '<span id="dfacets"></span>' +
        '<select class="sel" id="grpby" aria-label="' + ('Group by') + '"><option value="check">' + ('Group by check') + '</option><option value="status">' + ('Group by status') + '</option><option value="cat">' + ('Group by category') + '</option><option value="sev">' + ('Group by severity') + '</option></select>' +
        '<select class="sel" id="catf" aria-label="' + ('Filter by category') + '"><option value="">' + ('All categories') + '</option></select>' +
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
  function sevOrder(s){ var v=SEV_ORDER[s]; return (v==null)?9:v; }
  function sevColor(s){ return SEV_COLOR[s]||GREY; }
  var STATUS_LABEL={'Gap':'Gap','Review required':'Review'};
  var STATUS_CLS={'Gap':'gap','Review required':'review'};
  var LBL={confirmed:'Confirmed',dismissed:'Accepted',resolved:'Resolved'};
  var ACTS=[['confirmed',LBL.confirmed,'acknowledged, still to do'],['dismissed',LBL.dismissed,'risk accepted'],['resolved',LBL.resolved,'disappears from the list']];
  var STATUS_ORDER=['Gap','Review required'];

  var TENANT = window.__CAINV_TENANT || '';
  var STORE_KEY = 'cainv-decisions:' + TENANT;
  var decisions = {};
  try { decisions = JSON.parse(localStorage.getItem(STORE_KEY) || '{}') || {}; } catch(e){ decisions = {}; }
  function persist(){ try { localStorage.setItem(STORE_KEY, JSON.stringify(decisions)); } catch(e){} }
  function getDecision(k){ return decisions[k] || null; }
  function isChanged(r,d){ return !!(d && d.observedAtDecision!=null && String(d.observedAtDecision)!==String(r.ObservedValue==null?'':r.ObservedValue)); }

  // The inclusion criterion itself: a Gap doesn't need
  // to be confirmed first, a Review required does. Always runs client-side, never server-side
  // pre-filtered, because the decision can still change after this report is generated.
  function included(r){
    var d=getDecision(r.key), st=d?d.state:'open';
    if (r.Status==='Gap') return st!=='dismissed' && st!=='resolved';
    if (r.Status==='Review required') return st==='confirmed';
    return false;
  }

  var q='', fSev=new Set(), fStatus=new Set(), fCat='', hideManual=false;
  var grpBy='check', openKey=null, selected=new Set(), collapsed=new Set(), flat=[], viewMode='table';

  var $=function(i){ return document.getElementById(i); };
  var list=$('dlist'), side=$('side'), bulk=$('bulk'), dfilter=$('dfilter'), dfacets=$('dfacets'), stfacets=$('stfacets');

  function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }
  function title(r){ return r.Title||r.CheckId; }
  function askOf(r){ return r.ReviewQuestion||''; }
  function recByKey(k){ for(var i=0;i<DATA.length;i++){ if(DATA[i].key===k) return DATA[i]; } return null; }
  function groupKey(r){ return grpBy==='cat' ? (r.Category||'unknown') : grpBy==='sev' ? r.Severity : grpBy==='status' ? r.Status : r.CheckId; }
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
    var incl=DATA.filter(included);
    var n=incl.length, c=0;
    incl.forEach(function(r){ if(stateOf(r)==='confirmed') c++; });
    var openN=n-c;
    $('sub').innerHTML = n===0 ? 'Nothing open — every gap and confirmed review has been resolved or accepted.'
      : (n+' '+(n===1?'item':'items')+' to resolve &middot; '+openN+' not yet confirmed, '+c+' already acknowledged');
    var pct=function(x){ return (n?(x/n*100):0).toFixed(2)+'%'; };
    $('bar').innerHTML='<i class="b-open" style="width:'+pct(openN)+'"></i><i class="b-conf" style="width:'+pct(c)+'"></i>';
    $('legend').innerHTML='<span><span class="dot" style="background:'+CORAL+'"></span>'+'Not yet confirmed'+' <b>'+openN+'</b></span>'
      +'<span><span class="dot" style="background:'+YELLOW+'"></span>'+'Confirmed, still to resolve'+' <b>'+c+'</b></span>';
  }

  function buildFilters(){
    var incl=DATA.filter(included);
    var sev={}; incl.forEach(function(r){ sev[r.Severity]=(sev[r.Severity]||0)+1; });
    var keys=Object.keys(sev).sort(function(a,b){ return sevOrder(a)-sevOrder(b); });
    dfacets.innerHTML = keys.length<2 ? '' : keys.map(function(k){
      return '<button class="chip'+(fSev.has(k)?' on':'')+'" data-sev="'+esc(k)+'"><span class="sw" style="background:'+sevColor(k)+'"></span> '+esc(k)+'<span class="n">'+sev[k]+'</span></button>';
    }).join(' ');
    var cats={}; incl.forEach(function(r){ if(r.Category) cats[r.Category]=(cats[r.Category]||0)+1; });
    var cur=$('catf').value;
    $('catf').innerHTML='<option value="">'+'All categories'+'</option>'+Object.keys(cats).sort().map(function(c){
      return '<option value="'+esc(c)+'">'+esc(c)+' ('+cats[c]+')</option>';
    }).join('');
    $('catf').value=cur;
  }

  // Counts over the full included set, not over what the other filters already let through —
  // same semantics as the severity chips above.
  function buildStatusFacets(){
    var incl=DATA.filter(included);
    var counts={}; STATUS_ORDER.forEach(function(s){ counts[s]=0; });
    incl.forEach(function(r){ counts[r.Status]=(counts[r.Status]||0)+1; });
    stfacets.innerHTML = STATUS_ORDER.filter(function(s){ return counts[s]>0; }).map(function(s){
      return '<button class="chip'+(fStatus.has(s)?' on':'')+'" data-status="'+s+'">'+STATUS_LABEL[s]+'<span class="n">'+counts[s]+'</span></button>';
    }).join(' ');
  }

  function visible(){
    return DATA.filter(function(r){
      if(!included(r)) return false;
      if(fSev.size && !fSev.has(r.Severity)) return false;
      if(fStatus.size && !fStatus.has(r.Status)) return false;
      if(fCat && r.Category!==fCat) return false;
      if(hideManual && r.ManualReview) return false;
      if(!q) return true;
      var h=[r.ObjectName,r.ObservedValue,r.CheckId,r.Category,r.Property,title(r),r.Recommendation].join(' ').toLowerCase();
      return h.indexOf(q)>=0;
    });
  }

  // Heaviest severity first, then the largest group, then alphabetically. Unchanged vs. Review Queue.
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
      var openN=g.items.filter(function(r){ return stateOf(r)!=='confirmed'; }).length;
      var isColl=collapsed.has(g.k);
      var label = grpBy==='check' ? title(first) : grpBy==='status' ? (STATUS_LABEL[g.k]||g.k) : g.k;
      h+='<div class="grp"><div class="gh" data-g="'+esc(g.k)+'">';
      h+='<span class="tw">'+(isColl?'&#9656;':'&#9662;')+'</span>';
      h+='<span class="sw" style="background:'+sevColor(worst.Severity)+'"></span>';
      h+='<span class="gt">'+esc(label)+'</span>';
      if(grpBy==='check'){ h+='<span class="gc">'+esc(g.k)+'</span><span class="cat">'+'to resolve in '+esc(first.Category||'')+'</span>'; }
      h+='<span class="cnt">'+g.items.length+' &middot; '+(openN?openN+' not yet confirmed':'all confirmed')+'</span>';
      if(openN>1){ h+='<button class="bulkbtn" data-bulk="'+esc(g.k)+'">'+'confirm all '+openN+' at once'+'</button>'; }
      h+='</div>';
      if(!isColl){
        if(grpBy==='check' && askOf(first)){ h+='<div class="q"><b>'+'Question:'+'</b> '+esc(askOf(first))+'</div>'; }
        g.items.forEach(function(r){
          flat.push(r);
          var d=getDecision(r.key);
          h+='<div class="row'+(openKey===r.key?' open':'')+'" data-k="'+esc(r.key)+'">';
          h+='<span class="obj">'+esc(r.ObjectName||'tenant-wide')+'</span>';
          var ovTxt=(r.ObservedValue==null?'':String(r.ObservedValue));
          var ovCls='ov';
          if(!ovTxt){ ovTxt=(r.Recommendation||r.NotAssessedReason||''); ovCls='ov noval'; }
          h+='<span class="'+ovCls+'">'+esc(ovTxt.slice(0,150))+'</span>';
          h+='<span class="stp '+(STATUS_CLS[r.Status]||'')+'">'+esc(STATUS_LABEL[r.Status]||r.Status)+'</span>';
          h+=isChanged(r,d)?'<span class="chg">'+'value changed'+'</span>':'<span class="st'+(d?' '+d.state:'')+'">'+(d?esc(LBL[d.state]):'open')+'</span>';
          h+='</div>';
        });
      }
      h+='</div>';
    });
    list.innerHTML=h;
  }

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
    h+='<span class="pill">'+esc(STATUS_LABEL[r.Status]||r.Status)+'</span>';
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
    var vis={}; visible().forEach(function(r){ vis[r.key]=true; });
    Array.from(selected).forEach(function(k){ if(!vis[k]) selected.delete(k); });
    if(openKey && !vis[openKey]) openKey=null;
    buildStatusFacets(); buildFilters(); paintProg(); paintList(); paintSide(); paintBulk();
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
      visible().filter(function(r){ return groupKey(r)===gk && stateOf(r)!=='confirmed'; }).forEach(function(r){ selected.add(r.key); });
      paint(); return; }
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
    paint();
  });
  stfacets.addEventListener('click', function(e){
    var c=e.target.closest('[data-status]'); if(!c) return;
    var s=c.getAttribute('data-status'); if(fStatus.has(s)) fStatus.delete(s); else fStatus.add(s);
    paint();
  });
  $('catf').addEventListener('change', function(e){ fCat=e.target.value; paint(); });
  $('grpby').addEventListener('change', function(e){ grpBy=e.target.value; collapsed.clear(); paint(); });
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
    var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='open-work-decisions.json';
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
  // the parent page; this listener makes sure a decision made ELSEWHERE (Scorecard, Review Queue,
  // Rollout Plan) repaints here immediately. Opened standalone (no parent, real
  // localStorage), this only fires on a 'storage' event from ANOTHER tab on the same
  // origin — never in the tab that wrote it itself, that's normal browser behavior.
  window.addEventListener('storage', function(e){
    if (e.key !== STORE_KEY) return;
    try { decisions = JSON.parse(localStorage.getItem(STORE_KEY) || '{}') || {}; } catch(err){ decisions = {}; }
    paint();
  });

  buildStatusFacets();
  buildFilters();
  paint();
})();
</script>
'@)
    [void]$sb.AppendLine('</body></html>')
    Write-CAInvLog -Level 'INFO' -Message 'Open work HTML built.'
    return $sb.ToString()
}
