function New-CAInvFindingsRegister {
    <#
    .SYNOPSIS
        Report B — findings register. An Excel workbook.
    .DESCRIPTION
        Writes each finding as a row, split across fixed tabs so consecutive runs and tenants
        are comparable: Findings, Review, Exceptions, NotAssessed, RunInfo.
        Uses ImportExcel when available; otherwise the function falls back to separate CSVs per
        tab (so the output is still usable without that module).
    .OUTPUTS
        String: path to the register (xlsx or the folder with the CSV fallback).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $ctx = $script:CAInvContext
    $records = @($ctx.Records)

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
    foreach ($sec in @($sectionsCfg.sections)) { $sectionByPrefix[[string]$sec.prefix] = [string]$sec.title }
    $sectionCol = @{ Name = 'Section'; Expression = {
            $prefix = ([string]$_.CheckId -split '-')[0]
            if ($sectionByPrefix.ContainsKey($prefix)) { $sectionByPrefix[$prefix] } else { 'Other' }
        } }

    $findings = $records | Where-Object { $_.Status -in @('Gap') -or ($_.Severity -in @('High','Medium') -and $_.Status -ne 'Not assessed') } |
        Sort-Object @{ E = { switch ($_.Severity) { 'High' {0} 'Medium' {1} 'Low' {2} default {3} } } }, Layer |
        Select-Object *, $sectionCol
    $review     = $records | Where-Object { $_.Status -eq 'Review required' } | Select-Object *, $sectionCol
    $exceptions = $records | Where-Object { $_.CheckId -in @('Identity-06','Identity-10','Foundation-12','Foundation-07') } | Select-Object *, $sectionCol
    $notAssessed = $records | Where-Object { $_.Status -eq 'Not assessed' } | Select-Object *, $sectionCol

    $betaUsed = @($records | Where-Object { $_.ApiVersion -eq 'beta' } | Select-Object -Expand GraphSource -Unique)
    $runInfo = [PSCustomObject]@{
        TenantId            = $ctx.TenantId
        RunId               = $ctx.RunId
        CollectedAt         = $ctx.CollectedAt
        LookbackDays        = $ctx.LookbackDays
        AuthMode            = $ctx.AuthMode
        Scopes              = ($(if ($ctx.Preflight) { $ctx.Preflight.Scopes -join '; ' } else { '' }))

        OverbodigeSchrijfScopes = ($(if ($ctx.Preflight -and $ctx.Preflight.WriteScopes) { $ctx.Preflight.WriteScopes -join '; ' } else { '' }))
        BetaEndpointsUsed   = ($betaUsed -join '; ')
        RecordCount         = $records.Count
    }

    $hasImportExcel = [bool](Get-Module -ListAvailable -Name 'ImportExcel')

    if ($hasImportExcel) {
        Import-Module ImportExcel -ErrorAction SilentlyContinue
        $xlsx = Join-Path $ctx.Paths.Reports 'findings-register.xlsx'
        if (Test-Path -LiteralPath $xlsx) { Remove-Item -LiteralPath $xlsx -Force }

        $findings    | Export-Excel -Path $xlsx -WorksheetName 'Findings'   -AutoSize -FreezeTopRow -BoldTopRow -TableName 'Findings'
        $review      | Export-Excel -Path $xlsx -WorksheetName 'Review'     -AutoSize -FreezeTopRow -BoldTopRow -TableName 'Review'
        $exceptions  | Export-Excel -Path $xlsx -WorksheetName 'Exceptions' -AutoSize -FreezeTopRow -BoldTopRow -TableName 'Exceptions'
        $notAssessed | Export-Excel -Path $xlsx -WorksheetName 'NotAssessed'-AutoSize -FreezeTopRow -BoldTopRow -TableName 'NotAssessed'
        $runInfo     | Export-Excel -Path $xlsx -WorksheetName 'RunInfo'    -AutoSize
        Write-CAInvLog -Level 'INFO' -Message "Findings register (xlsx) written: $xlsx"
        return $xlsx
    }
    else {

        $dir = Join-Path $ctx.Paths.Reports 'findings-register'
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $findings    | Export-Csv -LiteralPath (Join-Path $dir 'Findings.csv')    -NoTypeInformation -Encoding utf8
        $review      | Export-Csv -LiteralPath (Join-Path $dir 'Review.csv')      -NoTypeInformation -Encoding utf8
        $exceptions  | Export-Csv -LiteralPath (Join-Path $dir 'Exceptions.csv')  -NoTypeInformation -Encoding utf8
        $notAssessed | Export-Csv -LiteralPath (Join-Path $dir 'NotAssessed.csv') -NoTypeInformation -Encoding utf8
        $runInfo     | Export-Csv -LiteralPath (Join-Path $dir 'RunInfo.csv')     -NoTypeInformation -Encoding utf8
        Write-CAInvLog -Level 'WARN' -Message "ImportExcel not present; findings register written as CSV: $dir"
        return $dir
    }
}
