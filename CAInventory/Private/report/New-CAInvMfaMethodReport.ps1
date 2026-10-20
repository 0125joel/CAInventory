function New-CAInvMfaMethodReport {
    <#
    .SYNOPSIS
        Step 3 of the guided flow — MFA methods per user (Auth-13), Member users only.
    .DESCRIPTION
        Shows every Member user (guests are already structurally excluded by
        Get-CAInvUserRegistrationDetail) with their strongest registered method, admin status, and
        whether that method meets the configured minimum (config/method-strength-map.json), in the style of the
        interactive Entra auth methods report.
        Shows ALL Member users by default; filterable by "below minimum", admin-only, per method, sign-in
        recency, and free text; columns are click-sortable. "Export to CSV" downloads the
        currently filtered rows client-side (Blob + &lt;a download&gt;, same idiom as the existing
        decisions-export-as-JSON button in the scorecard) — no new server-side CSV, to avoid a
        second, potentially staling source alongside this report.

        Last sign-in comes from $ctx.Users[].signInActivity (already fetched by Get-CAInvUser,
        layer 1, 6.11 — no new Graph call), joined on UserId. Requires Entra ID P1 to be
        populated; when signInActivity is missing for a user, the page explicitly shows
        "unknown" instead of an empty cell that could be read as "never signed in".

        LastSuccessfulSignIn uses `signInActivity.lastSuccessfulSignInDateTime`
        (users with demonstrable interactive activity still showed
        "unknown" for non-interactive) instead of the older
        `lastNonInteractiveSignInDateTime` — that older field turned out to be a documented
        unreliable Graph field (reported multiple times: returns `null`/the sentinel value
        `0001-01-01T00:00:00Z` while the non-interactive sign-ins ARE visible in the Entra portal
        itself). `lastSuccessfulSignInDateTime` (since December 2023) is Microsoft's own, more
        reliable replacement — covers interactive and non-interactive together, no separate
        non-interactive-only figure anymore (not backfilled retroactively by Microsoft, so
        historical data from before its introduction may be missing).

        Explicitly distinguishes "not measured" (Auth-11 could not perform the Graph call, e.g.
        due to a missing scope/consent) from "measured, 0 users" — otherwise a permission problem
        would silently look like "everyone compliant", which goes against this report's
        zero-trust status model like the rest of it (an unmeasured control is never the same as
        an approved control).

        DefaultMfaMethod reads userPreferredMethodForSecondaryAuthentication (confirmed via a
        live-tenant run, 2026-08-19: the older field 'defaultMfaMethod' does not exist in Graph
        v1.0, only in beta — see Get-CAInvUserRegistrationDetail.ps1).
    .OUTPUTS
        String: the HTML content of the MFA method report.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ctx = $script:CAInvContext
    $lang = 'en'

    function E([string]$s) { ConvertTo-CAInvHtmlSafe -Text $s }

    function ConvertTo-IsoDateString($v) {
        if ($null -eq $v) { return $null }
        if ($v -is [datetime]) { return $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
        return [string]$v
    }

    $allUsers = @()
    if ($ctx.PSObject.Properties['UserRegistrationDetails'] -and $ctx.UserRegistrationDetails) {
        $allUsers = @($ctx.UserRegistrationDetails)
    }

    $urd001 = @($ctx.Records | Where-Object { $_.CheckId -eq 'Auth-11' -and $_.ObjectType -eq 'Report' }) | Select-Object -First 1
    $notAssessed = $urd001 -and $urd001.Status -eq 'Not assessed'
    $notAssessedReason = if ($notAssessed) { [string]$urd001.NotAssessedReason } else { '' }

    $usersById = @{}
    if ($ctx.PSObject.Properties['Users'] -and $ctx.Users) {
        foreach ($u in $ctx.Users) {
            $uid = Get-CAInvProp $u 'id'
            if ($uid) { $usersById[$uid] = $u }
        }
    }

    $export = [System.Collections.Generic.List[object]]::new()
    foreach ($u in $allUsers) {
        $uid = Get-CAInvProp $u 'UserId' $null
        $gu = if ($uid -and $usersById.ContainsKey([string]$uid)) { $usersById[[string]$uid] } else { $null }
        $lastInteractive = if ($gu) { Get-CAInvProp $gu 'signInActivity.lastSignInDateTime' $null } else { $null }

        $lastSuccessful = if ($gu) { Get-CAInvProp $gu 'signInActivity.lastSuccessfulSignInDateTime' $null } else { $null }
        [void]$export.Add([ordered]@{
                UserPrincipalName = [string]$u.UserPrincipalName
                UserType          = [string]$u.UserType
                InAdminScope      = [bool]$u.InAdminScope
                StrongestMethodLabel = [string]$u.StrongestMethodLabel
                StrongestMethodWeight = [int]$u.StrongestMethodWeight
                DefaultMfaMethod  = [string]$u.DefaultMfaMethod
                IsMfaRegistered   = [bool]$u.IsMfaRegistered
                BelowMinimumStrength = [bool]$u.BelowMinimumStrength

                MethodsRegistered    = @(Get-CAInvProp $u 'MethodsRegistered' @())
                SatisfiedStrengths   = @(Get-CAInvProp $u 'SatisfiedStrengths' @())
                UncertainStrengths   = @(Get-CAInvProp $u 'UncertainStrengths' @())
                LastInteractiveSignIn = ConvertTo-IsoDateString $lastInteractive
                LastSuccessfulSignIn = ConvertTo-IsoDateString $lastSuccessful
            })
    }

    function ConvertTo-CAInvJsonArray($Items) {
        $arr = @($Items)
        $out = if ($arr.Count -eq 0) { '[]' }
               elseif ($arr.Count -eq 1) { '[' + ($arr[0] | ConvertTo-Json -Depth 3 -Compress) + ']' }
               else { $arr | ConvertTo-Json -Depth 3 -Compress }
        return ($out -replace '</', '<\/')
    }

    $json = ConvertTo-CAInvJsonArray $export

    $strengthCoverageKnown = [bool](Get-CAInvProp $ctx 'StrengthCoverageKnown' $false)
    $strengthLookup = [System.Collections.Generic.List[object]]::new()
    foreach ($st in @(Get-CAInvProp $ctx 'AuthStrengths' @())) {
        $stId = Get-CAInvProp $st 'id'
        if (-not $stId) { continue }
        [void]$strengthLookup.Add([ordered]@{
                Id         = [string]$stId
                Name       = [string](Get-CAInvProp $st 'displayName' $stId)
                PolicyType = [string](Get-CAInvProp $st 'policyType' ('unknown'))
            })
    }
    $strengthJson = ConvertTo-CAInvJsonArray $strengthLookup

    $methodLabels = [ordered]@{}
    $strengthMapCfg = Get-CAInvProp $ctx 'Config.MethodStrengthMap'
    if ($strengthMapCfg -and $strengthMapCfg.methods) {
        foreach ($prop in $strengthMapCfg.methods.PSObject.Properties) {
            $lbl = Get-CAInvProp $prop.Value 'label'
            if ($lbl) { $methodLabels[$prop.Name] = [string]$lbl }
        }
    }
    $methodLabelJson = if ($methodLabels.Count -eq 0) { '{}' } else { ($methodLabels | ConvertTo-Json -Depth 3 -Compress) }
    $methodLabelJson = $methodLabelJson -replace '</', '<\/'

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!doctype html><html lang="' + $lang + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>' + ('MFA methods · Conditional Access') + '</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine((New-CAInvReportPalette -Surface 'Card' -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine(@'
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--body);font-family:Aileron,'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased;padding:0 0 80px}
a{color:var(--ink);text-decoration:underline;text-underline-offset:2px}a:hover{color:var(--coral)}
input,button,select{font-family:inherit}
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
/* This page is deliberately NOT capped at the 1400px of the other report pages: the table is the main subject here and has eight columns, so that cap forced horizontal scrolling while screen space remained. The body text stays bounded via .lead/.notassessed, so the line length stays readable on a wide screen. */
.page{max-width:none;width:100%;margin:0;background:var(--card)}
.sec{padding:40px clamp(24px,3vw,64px)}
.eyebrow{font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:var(--coral);font-weight:700;margin-bottom:18px}
h1{font-size:36px;line-height:1.1;font-weight:700;color:var(--ink);margin:0 0 10px;letter-spacing:-.02em}
.lead{margin:0 0 28px;max-width:44em;font-size:17px;color:var(--body)}
.notassessed{border-left:3px solid var(--coral);background:var(--tint);padding:14px 18px;margin:0 0 24px;font-size:14px;max-width:56em}
.minnote{border-left:3px solid var(--grey);background:var(--tint);padding:12px 18px;margin:0 0 24px;font-size:13px;max-width:64em;color:var(--body)}
.minnote strong{color:var(--ink)}
.notassessed strong{color:var(--ink)}
.filterbar{padding:14px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line);margin-bottom:20px;display:flex;flex-direction:column;gap:10px}
.filterbar input{width:100%;padding:9px 12px;border:1px solid var(--grey);background:#fff;color:var(--body);font-size:14px}
/* Five filter groups on their own rows: OR within a group, AND between groups. Without this grouping the bar became an indistinguishable wall of chips as soon as a filter per method and per strength was added. */
.frow{display:grid;grid-template-columns:minmax(9em,11em) 1fr;gap:10px;align-items:baseline}
.frow>.chips{display:flex;gap:8px;flex-wrap:wrap}
.frow .facetlabel{padding-top:6px}
.chip.custom{border-style:dashed}
.chip.untranslated{border-color:var(--grey);color:var(--muted);font-family:ui-monospace,Consolas,monospace;font-size:12px}
.chip.uncertain{border-color:var(--yellow);color:#8a6300}
.chip.uncertain.active{background:var(--yellow);color:var(--ink);border-color:var(--yellow)}
.morebtn{background:transparent;border:0;border-bottom:1px dotted var(--muted);color:var(--muted);font-size:12px;cursor:pointer;padding:0}
.morebtn:hover{color:var(--ink);border-bottom-color:var(--ink)}
@media (max-width:760px){ .frow{grid-template-columns:1fr} }
.chip{border:1px solid var(--ink);padding:7px 13px;font-size:13px;cursor:pointer;background:#fff;color:var(--ink)}
.facetgroup{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.facetlabel{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:700}
.chip.active{background:var(--ink);color:#fff}
.chip.warn.active{background:var(--coral);border-color:var(--coral)}
.actionrow{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:12px}
#sub{font-size:13px;color:var(--muted)}
.dbtn{background:transparent;border:0;border-bottom:1px solid var(--ink);color:var(--ink);padding:0 0 1px;font-size:13px;cursor:pointer}
.dbtn:hover{color:var(--coral);border-bottom-color:var(--coral)}
/* overflow-x stays as a safety net for truly narrow screens, but the table no longer enforces a fixed minimum width: columns that may wrap (UPN, method names) now do so, instead of making the whole page wider than the window. */
#tablewrap{overflow-x:auto;max-height:min(70vh,900px);overflow-y:auto;border:1px solid var(--line)}
table{width:100%;border-collapse:collapse;table-layout:auto}
th{text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:700;padding:10px 16px;border-bottom:2px solid var(--ink);white-space:nowrap;position:sticky;top:0;background:var(--card);cursor:pointer;user-select:none}
th:hover{color:var(--ink)}
th .arrow{margin-left:4px;color:var(--grey)}
th.sorted .arrow{color:var(--ink)}
td{padding:13px 16px;border-bottom:1px solid var(--line);white-space:nowrap}
td.name,td.method{white-space:normal;overflow-wrap:anywhere}
td.name{min-width:14em}
tr:hover td{background:var(--tint)}
td.name{font-weight:700;color:var(--ink)}
.badge{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 8px;border:1px solid var(--coral);color:var(--coral)}
.badge.admin{border-color:var(--ink);color:var(--ink)}
.unknown{color:var(--muted);font-style:italic}
.empty{color:var(--muted);padding:40px 0}
@media (max-width:760px){
  .topbar,.footbar{padding-left:24px;padding-right:24px}
  .sec{padding:28px 24px}
  h1{font-size:28px}
}
</style></head><body>
'@)

    [void]$sb.AppendLine((New-CAInvReportTopbar -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine('<div class="page">')
    [void]$sb.AppendLine('<div class="sec">')
    [void]$sb.AppendLine("<div class=""eyebrow"">$('Step 3 &middot; MFA methods')</div>")
    [void]$sb.AppendLine("<h1>$('MFA methods per user')</h1>")
    [void]$sb.AppendLine("<p class=""lead"">$('Every Member user with their strongest registered method and last sign-in. Filter on "below minimum" to see only the users who don''t meet the floor, or filter by method, admin status, and sign-in recency (multiple periods at once possible). Click a column header to sort. Export the filtered list to CSV to let the customer configure their users.')</p>")

    $urd003 = @($ctx.Records | Where-Object { $_.CheckId -eq 'Auth-13' -and $_.ObjectType -eq 'Report' }) | Select-Object -First 1
    if ($urd003 -and $urd003.Recommendation) {
        [void]$sb.AppendLine("<div class=""minnote""><strong>$('Floor applied.')</strong> $(E ([string]$urd003.Recommendation))</div>")
    }
    if ($notAssessed) {
        [void]$sb.AppendLine("<div class=""notassessed""><strong>$('Not measured, no confirmation that everyone complies.')</strong> $(E $notAssessedReason)$(' Repeat the run with the right Graph access (Reports.Read.All / AuditLog.Read.All) to populate this page.')</div>")
    }
    $strengthFacetLabel = 'Authentication strength'
    $strengthRow = if ($strengthCoverageKnown) {
        "<div class=""frow""><span class=""facetlabel"">$strengthFacetLabel</span><div class=""chips"" id=""strengthfacets""></div></div>"
    }
    else {
        "<div class=""frow""><span class=""facetlabel"">$strengthFacetLabel</span><div class=""chips""><span class=""unknown"">$('Not measured: the authentication strengths weren''t fetched in this run (layer 2 not run, or Auth-04 couldn''t read). That''s different from "no strengths present".')</span></div></div>"
    }

    if ($strengthCoverageKnown) {
        [void]$sb.AppendLine('<div class="minnote"><strong>' + ('How to read "satisfies a strength".</strong> A user satisfies a strength as soon as their registered methods fully cover at least one of the allowed combinations. A password counts as present here, exactly as Microsoft''s own description of the MFA strength puts it ("such as a password + SMS"); federation isn''t counted, because that isn''t in the registration data, so in a federated tenant this is more likely an underestimate than an overestimate. A "possible" chip means: coverage found but not provable (the strength restricts which key or certificate counts), or coverage that can''t be ruled out because the user has a method that can''t be translated yet. Source: <a href="https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths" target="_blank" rel="noopener">Microsoft Learn, authentication strengths</a>.') + '</div>')
    }

    [void]$sb.AppendLine('<div class="filterbar">')
    [void]$sb.AppendLine('<input id="dfilter" type="search" placeholder="' + ('Filter by UPN or method') + '">')
    [void]$sb.AppendLine('<div class="frow"><span class="facetlabel">' + ('Status') + '</span><div class="chips"><button class="chip warn" id="belowmin" type="button">' + ('Below minimum') + '</button><button class="chip" id="adminonly" type="button">' + ('Admins only') + '</button></div></div>')
    [void]$sb.AppendLine('<div class="frow"><span class="facetlabel">' + ('Last sign-in') + '</span><div class="chips" id="recencyfacets"></div></div>')
    [void]$sb.AppendLine('<div class="frow"><span class="facetlabel">' + ('Strongest level') + '</span><div class="chips" id="methodfacets"></div></div>')
    [void]$sb.AppendLine('<div class="frow"><span class="facetlabel">' + ('Registered method') + '</span><div class="chips" id="regmethodfacets"></div></div>')
    [void]$sb.AppendLine($strengthRow)
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('<div class="actionrow"><div id="sub"></div><span style="flex:1"></span><button class="dbtn" id="btnexport" type="button">' + ('Export to CSV') + '</button></div>')
    [void]$sb.AppendLine('<div id="tablewrap"></div>')
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine((New-CAInvReportFooter -RunId $ctx.RunId -Brand (Get-CAInvProp $ctx 'Brand')))
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<script id="strength-data" type="application/json">')
    [void]$sb.AppendLine($strengthJson)
    [void]$sb.AppendLine('</script>')
    [void]$sb.AppendLine('<script id="methodlabel-data" type="application/json">')
    [void]$sb.AppendLine($methodLabelJson)
    [void]$sb.AppendLine('</script>')
    [void]$sb.AppendLine('<script id="mfa-data" type="application/json">')
    [void]$sb.AppendLine($json)
    [void]$sb.AppendLine('</script>')
    [void]$sb.AppendLine(@'
<script>
(function(){
  var DATA = JSON.parse(document.getElementById('mfa-data').textContent);
  var STRENGTHS = JSON.parse(document.getElementById('strength-data').textContent);
  var METHODLABELS = JSON.parse(document.getElementById('methodlabel-data').textContent);
  var methodfacets=document.getElementById('methodfacets'), dfilter=document.getElementById('dfilter'), sub=document.getElementById('sub'), tablewrap=document.getElementById('tablewrap'), recencyfacets=document.getElementById('recencyfacets');
  var regmethodfacets=document.getElementById('regmethodfacets'), strengthfacets=document.getElementById('strengthfacets');
  // Registered method and strength are separate filter groups: OR within the group, AND across
  // groups. fStrengths holds strength IDs; 'uncertain' gets its own chip per strength so a
  // 'possible' verdict never counts as 'meets'.
  var fRegMethods=new Set(), fStrengths=new Set(), fStrengthsUncertain=new Set();
  var MAX_CHIPS=8;
  // Recency is multi-select: multiple buckets at once, OR semantics,
  // same as the method facets below. Empty = no filter, so everything.
  var RECENCY_BUCKETS=[
    {val:'30',    label:'< 30 days'},
    {val:'60',    label:'30–60 days'},
    {val:'90',    label:'60–90 days'},
    {val:'90plus',label:'> 90 days'},
    {val:'never', label:'Never/unknown'}
  ];
  var fMethods=new Set(), fRecency=new Set(), adminOnly=false, belowMinOnly=false;
  var sortKey=null, sortDir=1;

  var COLS=[
    {key:'UserPrincipalName',label:'UPN'},
    {key:'UserType',label:'Type'},
    {key:null,label:''},
    {key:'StrongestMethodLabel',label:'Strongest method'},
    {key:null,label:'Registered methods'},
    {key:'DefaultMfaMethod',label:'Default method'},
    {key:'IsMfaRegistered',label:'MFA registered'},
    {key:'LastInteractiveSignIn',label:'Last interactive sign-in'},
    {key:'LastSuccessfulSignIn',label:'Last successful sign-in (interactive or not)'}
  ];

  function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}

  function daysAgo(iso){ if(!iso) return null; var d=new Date(iso); if(isNaN(d.getTime())) return null; return (Date.now()-d.getTime())/86400000; }
  function mostRecentDays(r){
    var a=daysAgo(r.LastInteractiveSignIn), b=daysAgo(r.LastSuccessfulSignIn);
    if(a==null && b==null) return null;
    if(a==null) return b; if(b==null) return a;
    return Math.min(a,b);
  }
  function fmtDate(iso){
    if(!iso) return '<span class="unknown">'+'unknown'+'</span>';
    var d=new Date(iso); if(isNaN(d.getTime())) return '<span class="unknown">'+'unknown'+'</span>';
    var months=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return d.getDate()+' '+months[d.getMonth()]+' '+d.getFullYear();
  }

  // Shared renderer for a chip group with a count and a "+N more" expander. Without that
  // expander, the filter bar gets taller than the table below it once there are dozens of methods.
  function renderChips(host, items, selected, onToggle){
    if(!host) return;
    var expanded=host.dataset.expanded==='1';
    var shown=expanded?items:items.slice(0,MAX_CHIPS);
    var html=shown.map(function(it){
      var cls='chip'+(selected.has(it.val)?' active':'')+(it.cls?' '+it.cls:'');
      return '<button class="'+cls+'" type="button" data-val="'+esc(it.val)+'"'+(it.title?' title="'+esc(it.title)+'"':'')+'>'+esc(it.label)+' ('+it.count+')</button>';
    }).join('');
    if(items.length>MAX_CHIPS){
      html+='<button class="morebtn" type="button" data-more="1">'+(expanded?'show less':'+'+(items.length-MAX_CHIPS)+' '+'more')+'</button>';
    }
    host.innerHTML=html;
    host.querySelectorAll('.chip').forEach(function(ch){
      ch.addEventListener('click',function(){ onToggle(ch.dataset.val); });
    });
    host.querySelectorAll('.morebtn').forEach(function(b){
      b.addEventListener('click',function(){ host.dataset.expanded=expanded?'0':'1'; paint(); });
    });
  }

  // Counts are a property of the dataset, not of the current filter state: compute once
  // and only re-render after that. Otherwise every keystroke in the search field would loop
  // over all users again.
  var REG_ITEMS=null, STRENGTH_ITEMS=null;

  function buildRegMethodFacets(){
    // Chips come from what users ACTUALLY have registered, not from the config: a method
    // that method-strength-map.json doesn't yet know stays filterable this way and shows its
    // raw Graph value.
    var counts={};
    DATA.forEach(function(r){
      (r.MethodsRegistered||[]).forEach(function(m){ counts[m]=(counts[m]||0)+1; });
    });
    var items=Object.keys(counts).sort(function(a,b){ return counts[b]-counts[a] || a.localeCompare(b); }).map(function(m){
      var known=Object.prototype.hasOwnProperty.call(METHODLABELS,m);
      return {
        val:m,
        label:known?METHODLABELS[m]:m,
        count:counts[m],
        cls:known?'':'untranslated',
        title:known?m:(m+' — not yet translated in method-strength-map.json; raw Graph value shown.')
      };
    });
    REG_ITEMS=items;
  }

  function renderRegMethodFacets(){
    if(!regmethodfacets) return;
    if(!REG_ITEMS || !REG_ITEMS.length){ regmethodfacets.innerHTML='<span class="unknown">'+'No registered methods in this run.'+'</span>'; return; }
    renderChips(regmethodfacets, REG_ITEMS, fRegMethods, function(v){
      if(fRegMethods.has(v)) fRegMethods.delete(v); else fRegMethods.add(v);
      paint();
    });
  }

  function buildStrengthFacets(){
    if(!strengthfacets) return;
    var items=[];
    STRENGTHS.forEach(function(st){
      var ok=0, maybe=0;
      DATA.forEach(function(r){
        if((r.SatisfiedStrengths||[]).indexOf(st.Id)>=0) ok++;
        else if((r.UncertainStrengths||[]).indexOf(st.Id)>=0) maybe++;
      });
      var custom=(st.PolicyType||'')==='custom';
      items.push({ val:st.Id, label:st.Name+(custom?' (custom)':''), count:ok, cls:custom?'custom':'',
                   title:'Satisfies '+st.Name+(custom?' (custom strength from this tenant)':' (built-in strength)') });
      if(maybe>0){
        items.push({ val:'~'+st.Id, label:st.Name+': possible', count:maybe, cls:'uncertain',
                     title:'Coverage found or cannot be ruled out, but cannot be proven: the strength restricts which key/certificate counts, or the user has a method that can\'t be translated.' });
      }
    });
    STRENGTH_ITEMS=items;
  }

  function renderStrengthFacets(){
    if(!strengthfacets) return;
    if(!STRENGTH_ITEMS || !STRENGTH_ITEMS.length){ strengthfacets.innerHTML='<span class="unknown">'+'No authentication strengths found in this tenant.'+'</span>'; return; }
    var selected=new Set();
    fStrengths.forEach(function(x){ selected.add(x); });
    fStrengthsUncertain.forEach(function(x){ selected.add('~'+x); });
    renderChips(strengthfacets, STRENGTH_ITEMS, selected, function(v){
      if(v.charAt(0)==='~'){
        var id=v.slice(1);
        if(fStrengthsUncertain.has(id)) fStrengthsUncertain.delete(id); else fStrengthsUncertain.add(id);
      } else {
        if(fStrengths.has(v)) fStrengths.delete(v); else fStrengths.add(v);
      }
      paint();
    });
  }

  function matchesStrength(r){
    if(!fStrengths.size && !fStrengthsUncertain.size) return true;
    var hit=false;
    fStrengths.forEach(function(id){ if((r.SatisfiedStrengths||[]).indexOf(id)>=0) hit=true; });
    fStrengthsUncertain.forEach(function(id){ if((r.UncertainStrengths||[]).indexOf(id)>=0) hit=true; });
    return hit;
  }

  function matchesRegMethod(r){
    if(!fRegMethods.size) return true;
    var methods=r.MethodsRegistered||[];
    var hit=false;
    fRegMethods.forEach(function(m){ if(methods.indexOf(m)>=0) hit=true; });
    return hit;
  }

  function methodLabel(m){ return Object.prototype.hasOwnProperty.call(METHODLABELS,m)?METHODLABELS[m]:m; }

  function buildFacets(){
    var m={}; DATA.forEach(function(r){ m[r.StrongestMethodLabel]=(m[r.StrongestMethodLabel]||0)+1; });
    var keys=Object.keys(m).sort();
    if(keys.length<2){ methodfacets.innerHTML=''; return; }
    methodfacets.innerHTML=keys.map(function(k){ return '<button class="chip'+(fMethods.has(k)?' active':'')+'" data-val="'+esc(k)+'">'+esc(k)+' ('+m[k]+')</button>'; }).join('');
    methodfacets.querySelectorAll('.chip').forEach(function(ch){
      ch.addEventListener('click',function(){ var v=ch.dataset.val; if(fMethods.has(v))fMethods.delete(v); else fMethods.add(v); ch.classList.toggle('active'); paint(); });
    });
  }

  function inBucket(d,bucket){
    if(bucket==='never') return d==null;
    if(d==null) return false;
    if(bucket==='30') return d<30;
    if(bucket==='60') return d>=30 && d<60;
    if(bucket==='90') return d>=60 && d<90;
    if(bucket==='90plus') return d>=90;
    return false;   // an unknown bucket never counts; silently returning 'true' would hide a bug
  }
  function matchesRecency(r){
    if(!fRecency.size) return true;
    var d=mostRecentDays(r);
    var hit=false;
    fRecency.forEach(function(b){ if(inBucket(d,b)) hit=true; });
    return hit;
  }

  function buildRecencyFacets(){
    var counts={};
    RECENCY_BUCKETS.forEach(function(b){ counts[b.val]=0; });
    DATA.forEach(function(r){
      var d=mostRecentDays(r);
      RECENCY_BUCKETS.forEach(function(b){ if(inBucket(d,b.val)) counts[b.val]++; });
    });
    recencyfacets.innerHTML=RECENCY_BUCKETS.map(function(b){
      return '<button class="chip'+(fRecency.has(b.val)?' active':'')+'" data-val="'+b.val+'" type="button">'+esc(b.label)+' ('+counts[b.val]+')</button>';
    }).join('');
    recencyfacets.querySelectorAll('.chip').forEach(function(ch){
      ch.addEventListener('click',function(){
        var v=ch.dataset.val;
        if(fRecency.has(v)) fRecency.delete(v); else fRecency.add(v);
        ch.classList.toggle('active');
        paint();
      });
    });
  }

  function currentList(){
    var q=(dfilter.value||'').toLowerCase();
    var list=DATA.filter(function(r){
      if(belowMinOnly && !r.BelowMinimumStrength) return false;
      if(fMethods.size && !fMethods.has(r.StrongestMethodLabel)) return false;
      if(adminOnly && !r.InAdminScope) return false;
      if(!matchesRecency(r)) return false;
      if(!matchesRegMethod(r)) return false;
      if(!matchesStrength(r)) return false;
      if(!q) return true;
      return [r.UserPrincipalName,r.StrongestMethodLabel,r.DefaultMfaMethod].concat((r.MethodsRegistered||[]).map(methodLabel)).concat(r.MethodsRegistered||[]).join(' ').toLowerCase().indexOf(q)>=0;
    });
    if(sortKey){
      list=list.slice().sort(function(a,b){
        var av=a[sortKey], bv=b[sortKey];
        if(av==null && bv==null) return 0;
        if(av==null) return 1; if(bv==null) return -1;
        if(typeof av==='boolean'){ av=av?1:0; bv=bv?1:0; }
        if(av<bv) return -1*sortDir; if(av>bv) return 1*sortDir; return 0;
      });
    }
    return list;
  }

  function rowHtml(r){
    var badges=(r.InAdminScope?'<span class="badge admin">'+'admin'+'</span> ':'')+(r.BelowMinimumStrength?'<span class="badge">'+'below minimum'+'</span>':'');
    var regm=(r.MethodsRegistered||[]);
    var regHtml=regm.length?regm.map(function(m){ return esc(methodLabel(m)); }).join(', '):'<span class="unknown">'+'none'+'</span>';
    return '<tr><td class="name">'+esc(r.UserPrincipalName)+'</td><td>'+esc(r.UserType)+'</td><td>'+badges+'</td><td class="method">'+esc(r.StrongestMethodLabel)+'</td><td class="method">'+regHtml+'</td><td class="method">'+esc(r.DefaultMfaMethod)+'</td><td>'+(r.IsMfaRegistered?'yes':'no')+'</td><td>'+fmtDate(r.LastInteractiveSignIn)+'</td><td>'+fmtDate(r.LastSuccessfulSignIn)+'</td></tr>';
  }

  function headerHtml(){
    return '<tr>'+COLS.map(function(c){
      if(!c.key) return '<th>'+esc(c.label)+'</th>';
      var cls='sortable'+(sortKey===c.key?' sorted':'');
      var arrow=sortKey===c.key?(sortDir===1?'&#9650;':'&#9660;'):'';
      return '<th class="'+cls+'" data-key="'+c.key+'">'+esc(c.label)+' <span class="arrow">'+arrow+'</span></th>';
    }).join('')+'</tr>';
  }

  function paint(){
    // The two new groups draw their active state from the filter sets, so they must be redrawn
    // on every repaint; the older groups toggle their own class and are left alone.
    renderRegMethodFacets();
    renderStrengthFacets();
    var list=currentList();
    sub.textContent=list.length+' '+'of'+' '+DATA.length+' '+(DATA.length===1?'user':'users');
    if(!list.length){
      tablewrap.innerHTML='<div class="empty">'+(DATA.length===0?'No Member users available in this run.':'No users match this filter.')+'</div>';
      return;
    }
    var html='<table>'+headerHtml();
    html+=list.map(rowHtml).join('');
    html+='</table>';
    tablewrap.innerHTML=html;
    tablewrap.querySelectorAll('th.sortable').forEach(function(th){
      th.addEventListener('click',function(){
        var k=th.dataset.key;
        if(sortKey===k){ sortDir=-sortDir; } else { sortKey=k; sortDir=1; }
        paint();
      });
    });
  }

  dfilter.addEventListener('input',paint);
  var adminBtn=document.getElementById('adminonly');
  adminBtn.addEventListener('click',function(){ adminOnly=!adminOnly; adminBtn.classList.toggle('active',adminOnly); paint(); });
  var belowMinBtn=document.getElementById('belowmin');
  belowMinBtn.addEventListener('click',function(){ belowMinOnly=!belowMinOnly; belowMinBtn.classList.toggle('active',belowMinOnly); paint(); });

  function csvEscape(v){ v=(v==null?'':String(v)); if(/[",\n]/.test(v)){ v='"'+v.replace(/"/g,'""')+'"'; } return v; }
  document.getElementById('btnexport').addEventListener('click',function(){
    var list=currentList();
    var header=['UserPrincipalName','UserType','InAdminScope','StrongestMethodLabel','MethodsRegistered','DefaultMfaMethod','IsMfaRegistered','BelowMinimumStrength','SatisfiedStrengths','UncertainStrengths','LastInteractiveSignIn','LastSuccessfulSignIn'];
    // Arrays are semicolon-separated: a comma would collide with the CSV's own column separator.
    var strengthName={}; STRENGTHS.forEach(function(st){ strengthName[st.Id]=st.Name; });
    function cell(r,h){
      if(h==='MethodsRegistered') return (r.MethodsRegistered||[]).join('; ');
      if(h==='SatisfiedStrengths'||h==='UncertainStrengths') return (r[h]||[]).map(function(id){ return strengthName[id]||id; }).join('; ');
      return r[h];
    }
    var lines=[header.join(',')];
    list.forEach(function(r){
      lines.push(header.map(function(h){ return csvEscape(cell(r,h)); }).join(','));
    });
    var blob=new Blob([lines.join('\r\n')],{type:'text/csv'});
    var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='mfa-methoden.csv';
    document.body.appendChild(a); a.click(); setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); },0);
  });

  buildRecencyFacets();
  buildFacets();
  buildRegMethodFacets();
  buildStrengthFacets();
  paint();   // paint() draws the two new groups itself
})();
</script>
'@)
    [void]$sb.AppendLine('</body></html>')
    Write-CAInvLog -Level 'INFO' -Message 'MFA methods HTML built.'
    return $sb.ToString()
}
