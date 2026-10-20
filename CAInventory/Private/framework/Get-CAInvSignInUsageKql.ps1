function Get-CAInvSignInUsageKql {
    <#
    .SYNOPSIS
        LAW/KQL adapter for the method matrix usage axis.
    .DESCRIPTION
        Fills what Get-CAInvSignInData structurally cannot deliver: per-method usage counts.
        Queries SigninLogs + AADNonInteractiveUserSignInLogs (the only two sign-in tables with an
        AuthenticationDetails column — AADServicePrincipalSignInLogs/AADManagedIdentitySignInLogs
        don't have one, because service principals/managed identities authenticate with
        secrets/certificates, not with MFA methods) via the Log Analytics query REST API,
        aggregated (summarize per method) so a large, unaggregated result never comes back — the
        exact performance trap that already broke Get-CAInvSignInData earlier on the Graph
        sign-in API.

        Requires an Azure context (on by default; can be turned off with -SkipAzure) AND a
        workspace that Resolve-CAInvLogWindow has already found ($ctx.PrimaryLogWorkspace, incl.
        CustomerId). Therefore only runs after Resolve-CAInvLogWindow has executed. If Azure
        context or workspace is missing, nothing happens (no record, no crash) — the method
        matrix's existing Not-assessed degradation then simply stands; this is an addition on top
        of it, not a replacement for the error handling.

        Every raw method string from Log Analytics is looked up in
        config/kql-auth-method-map.json (into the MethodId vocabulary of
        authenticationMethodsPolicy, the same one Get-CAInvMethodUsageMatrix iterates per method).
        An unmapped string is NEVER silently ignored: it doesn't count toward a specific method,
        but is collected and logged as a single WARN with all unknown values + their counts —
        without that warning, a method that's actually in use under an unmapped name could
        wrongly appear as a "retirement candidate" (Auth-06). The mapping is a first attempt based
        on community KQL examples (Microsoft doesn't formally document the exact runtime values)
        and needs to be verified against a real tenant run.

        On success, sets $ctx.SignInData.HasAuthDetails = $true and adds MethodUsage (hashtable:
        MethodId -> @{ Count; LastUse }). Always leaves $ctx.SignInData.SignIns (the lean Graph
        array for Foundation-03/Evidence-01) untouched.

        UserType comparison is deliberately case-insensitive (=~, not ==): live-tenant verification
        (2026-08-19) showed that KQL's == is case-sensitive and that the actual value in
        SigninLogs is not guaranteed to be lowercase 'member' as Microsoft's documentation text
        suggests — the same inconsistent casing between Microsoft sources that also came up with
        Get-CAInvUserRegistrationDetail (/users gives 'Member', the registration details API gives
        'member'). Diagnosis via the fallback query below showed 0 of 135,500 rows matching on
        == "member" while all other filters (ResultType, AuthenticationDetails) did hit — exactly
        this type of silent mismatch.
    .OUTPUTS
        None. Works purely via side effect on $script:CAInvContext.SignInData.
    #>
    [CmdletBinding()]
    param()

    $ctx = $script:CAInvContext
    $domain = '6.23'

    if (-not ($ctx.PSObject.Properties['Connections'] -and $ctx.Connections -and $ctx.Connections.Azure)) {
        return
    }
    if (-not ($ctx.PSObject.Properties['PrimaryLogWorkspace'] -and $ctx.PrimaryLogWorkspace)) {
        Write-CAInvLog -Level 'DEBUG' -Domain $domain -Message ("No primary Log Analytics workspace; method matrix usage axis remains Not assessed. {0}" -f (Get-CAInvAzureUnavailableReason)).Trim()
        return
    }

    $ws = $ctx.PrimaryLogWorkspace
    $customerId = $ws.CustomerId
    if (-not $customerId) {
        Write-CAInvLog -Level 'WARN' -Domain $domain -Message "Workspace $($ws.WorkspaceId) found but customerId not readable; method matrix usage axis remains Not assessed."
        return
    }

    if (-not ($ctx.PSObject.Properties['SignInData'] -and $ctx.SignInData)) {
        Get-CAInvSignInData | Out-Null
    }
    if (-not ($ctx.PSObject.Properties['SignInData'] -and $ctx.SignInData)) { return }

    $window = Get-CAInvEffectiveLookbackWindow

    $token = Get-CAInvLogAnalyticsToken -Domain $domain
    if (-not $token) { return }

    $kql = @"
let win = ${window}d;
union isfuzzy=true
  (SigninLogs
   | where TimeGenerated >= ago(win)
   | where ResultType == "0"
   | where UserType =~ "member"
   | project TimeGenerated, AuthenticationDetails),
  (AADNonInteractiveUserSignInLogs
   | where TimeGenerated >= ago(win)
   | where ResultType == "0"
   | where UserType =~ "member"
   | project TimeGenerated, AuthenticationDetails)
| mv-expand parsed = todynamic(AuthenticationDetails)
| where tostring(parsed.succeeded) == "true"
| extend AuthMethod = tostring(parsed.authenticationMethod)
| where isnotempty(AuthMethod)
| summarize Count = count(), LastUse = max(TimeGenerated) by AuthMethod
"@

    $rows = $null
    $queryResult = Invoke-CAInvLogAnalyticsQuery -CustomerId $customerId -Token $token -Kql $kql -Domain $domain
    if (-not $queryResult.Success) {
        Write-CAInvLog -Level 'WARN' -Domain $domain -Message "KQL query on workspace $customerId failed; method matrix usage axis remains Not assessed: $($queryResult.ErrorMessage)"
        return
    }
    $resp = $queryResult.Response
    $rows = @($resp.tables | Select-Object -First 1 | ForEach-Object { $_.rows })

    if ($null -eq $rows) { $rows = @() }

    $rawPath = Write-CAInvRaw -Domain $domain -Endpoint 'signInUsageKql' -Data $resp
    Write-CAInvLog -Level 'DEBUG' -Domain $domain -Message "KQL query on workspace $customerId returned $($rows.Count) row(s) (window $window d)."

    if ($rows.Count -eq 0) {
        $diagKql = @"
let win = ${window}d;
union isfuzzy=true
  (SigninLogs
   | where TimeGenerated >= ago(win)
   | summarize Total=count(), MetResultType0=countif(ResultType == "0"), MetUserTypeMember=countif(UserType =~ "member"), MetBeide=countif(ResultType == "0" and UserType =~ "member"), MetAuthDetails=countif(isnotempty(AuthenticationDetails))
   | extend Bron="SigninLogs"),
  (AADNonInteractiveUserSignInLogs
   | where TimeGenerated >= ago(win)
   | summarize Total=count(), MetResultType0=countif(ResultType == "0"), MetUserTypeMember=countif(UserType =~ "member"), MetBeide=countif(ResultType == "0" and UserType =~ "member"), MetAuthDetails=countif(isnotempty(AuthenticationDetails))
   | extend Bron="AADNonInteractiveUserSignInLogs")
"@
        $diagResult = Invoke-CAInvLogAnalyticsQuery -CustomerId $customerId -Token $token -Kql $diagKql -Domain $domain
        if ($diagResult.Success) {
            $diagResp = $diagResult.Response
            Write-CAInvRaw -Domain $domain -Endpoint 'signInUsageKqlDiagnostiek' -Data $diagResp | Out-Null
            $diagRows = @($diagResp.tables | Select-Object -First 1 | ForEach-Object { $_.rows })
            $diagCols = @($diagResp.tables | Select-Object -First 1 | ForEach-Object { $_.columns.name })
            $diagLines = foreach ($dr in $diagRows) {
                $pairs = for ($i = 0; $i -lt $diagCols.Count; $i++) { "$($diagCols[$i])=$($dr[$i])" }
                $pairs -join ' '
            }
            Write-CAInvLog -Level 'WARN' -Domain $domain -Message "Main query returned 0 methods; diagnosis per source table (window $window d): $($diagLines -join ' | ')"
        }
        else {
            Write-CAInvLog -Level 'DEBUG' -Domain $domain -Message "Diagnostic follow-up query also failed: $($diagResult.ErrorMessage)"
        }
    }

    $methodMap = $null
    if ($ctx.PSObject.Properties['Config'] -and $ctx.Config -and $ctx.Config.KqlAuthMethodMap) {
        $methodMap = $ctx.Config.KqlAuthMethodMap
    }
    else {
        try { $methodMap = (Get-CAInvConfig).KqlAuthMethodMap } catch { $methodMap = $null }
    }
    $mapTable = @{}
    if ($methodMap -and $methodMap.map) {
        foreach ($p in $methodMap.map.PSObject.Properties) { $mapTable[$p.Name] = $p.Value }
    }

    $methodUsage = @{}
    $unmapped = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $rows) {

        $rawMethod = [string]$row[0]
        $count = [int]$row[1]
        $lastUse = [string]$row[2]
        if ([string]::IsNullOrWhiteSpace($rawMethod)) { continue }

        if ($mapTable.ContainsKey($rawMethod)) {
            $mappedId = [string]$mapTable[$rawMethod]
            if ($methodUsage.ContainsKey($mappedId)) {
                $methodUsage[$mappedId].Count += $count
                if ($lastUse -gt $methodUsage[$mappedId].LastUse) { $methodUsage[$mappedId].LastUse = $lastUse }
            }
            else {
                $methodUsage[$mappedId] = @{ Count = $count; LastUse = $lastUse }
            }
        }
        else {
            [void]$unmapped.Add("$rawMethod (count=$count)")
        }
    }

    if ($unmapped.Count -gt 0) {
        Write-CAInvLog -Level 'WARN' -Domain $domain -Message "Unknown method string(s) from Log Analytics, not counted in the method matrix usage axis (add to config/kql-auth-method-map.json): $($unmapped -join '; ')"
    }

    $ctx.SignInData.HasAuthDetails = $true
    $ctx.SignInData | Add-Member -NotePropertyName 'MethodUsage' -NotePropertyValue $methodUsage -Force

    $realMethodCount = @($methodUsage.Keys | Where-Object { $_ }).Count
    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Method matrix usage axis populated via Log Analytics: $($rows.Count) raw row(s) -> $realMethodCount method(s) with observed usage in a $window-day window. Evidence: $rawPath."
}
