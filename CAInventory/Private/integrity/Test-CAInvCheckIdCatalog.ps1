function Test-CAInvCheckIdCatalog {
    <#
    .SYNOPSIS
        Govern-05 — every finding record carries a CheckId that exists in the catalog.
    .DESCRIPTION
        Integrity check. Compares the CheckIds in the collected records against
        config/checkids.json and flags it when a record carries an id the catalog doesn't know.

        Background: the reference run of 21-08-2026 contained records with CheckId SIL-002, while
        that check had been removed from the catalog that same day due to end-of-life. The
        reference page couldn't explain those findings, because without a catalog entry the
        display falls back to the raw id: no title, no description, no source. To the reader of a
        customer report that's a line without meaning, and nothing in the chain raised an alarm
        about it.

        This check is deliberately NOT in Test-CAInvReferentialIntegrity. That function returns
        early when there are no CA policies, and exactly that kind of run can still produce records
        with an orphaned CheckId.

        It runs as the LAST step of the collection chain, after layer 7 and after the method
        matrix. Running earlier would miss the records that arise afterward, and the check would
        then give precisely the kind of false confidence it's meant to prevent. Its own record is
        the only one that still comes after it, and that one is in the catalog by definition.

        Since the renumbering of 25-08-2026 it also guards the taxonomy itself, as a second record:
        every prefix exists in config/sections.json and every category in config/categories.json.
        A prefix without a section makes a check disappear from the report, and a category outside
        the closed list silently turns a typo into a new category.
    .OUTPUTS
        None. Writes one record via New-CAInvRecord.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $domain = '6.33'
    $src    = 'Aggregation: records x config/checkids.json'

    $ctx = $script:CAInvContext

    $ctxConfig = Get-CAInvProp $ctx 'Config'
    $catalog = if ($ctxConfig -is [System.Collections.IDictionary]) { $ctxConfig['CheckIds'] } else { Get-CAInvProp $ctxConfig 'CheckIds' }
    if (-not $catalog) {
        try { $catalog = (Get-CAInvConfig).CheckIds } catch { $catalog = $null }
    }

    $known = @(Get-CAInvProp $catalog 'checks' @() | ForEach-Object { [string](Get-CAInvProp $_ 'checkId' '') } | Where-Object { $_ })

    if ($known.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Govern-05' -ObjectType 'Tenant' `
            -Property 'checkIdCatalog' -Status 'Not assessed' `
            -NotAssessedReason ('config/checkids.json could not be read or contains no checks, so the CheckIds from this run cannot be compared against the catalog.') `
            -ApiVersion 'n/a' -GraphSource $src | Out-Null
        return
    }

    $knownSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$known, [System.StringComparer]::OrdinalIgnoreCase)

    $records = @(Get-CAInvProp $ctx 'Records' @())
    $orphans = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $orphanCount = 0
    $blankCount = 0
    foreach ($r in $records) {
        $cid = [string](Get-CAInvProp $r 'CheckId' '')

        if ([string]::IsNullOrWhiteSpace($cid)) { $blankCount++; continue }
        if (-not $knownSet.Contains($cid)) {
            [void]$orphans.Add($cid)
            $orphanCount++
        }
    }

    if ($orphans.Count -eq 0 -and $blankCount -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Govern-05' -ObjectType 'Tenant' `
            -Property 'checkIdCatalog' `
            -ObservedValue "All $($records.Count) findings carry a CheckId that appears in the catalog of $($known.Count) checks." `
            -Status 'Ready' -ApiVersion 'n/a' -GraphSource $src | Out-Null
    }
    else {
        $list = @($orphans) -join ', '
        $observed = if ($orphans.Count -gt 0) {
            "$orphanCount finding(s) carry a CheckId that is not in config/checkids.json: $list"
        } else { '' }
        if ($blankCount -gt 0) {
            $blankTxt = "$blankCount finding(s) carry no CheckId at all."
            $observed = if ($observed) { "$observed $blankTxt" } else { $blankTxt }
        }
        New-CAInvRecord -Domain $domain -CheckId 'Govern-05' -ObjectType 'Tenant' `
            -Property 'checkIdCatalog' `
            -ObservedValue $observed `
            -Status 'Gap' -ApiVersion 'n/a' -GraphSource $src `
            -Recommendation ('These findings appear in the report without a title, description, or source, and are unexplainable to the reader. Add the named CheckId(s) to config/checkids.json and regenerate the checks reference, or remove the collector that writes them. This is a bug in the module, not in the tenant.') | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($records.Count) findings checked against $($known.Count) catalog items; $($orphans.Count) unknown CheckId(s), $blankCount without CheckId."

    Test-CAInvCheckIdTaxonomy -Catalog $catalog -CtxConfig $ctxConfig -Domain $domain
}

function Test-CAInvCheckIdTaxonomy {
    <#
    .SYNOPSIS
        Second record of Govern-05: the taxonomy behind the CheckId matches its config.
    .DESCRIPTION
        Checks three things that can silently drift without a run failing: a prefix without a
        section (the check disappears from the report), a category not in the closed list (a typo
        otherwise silently becomes a new category), and a missing or unknown 'layer' (since 0.38.0
        that field determines the layer label on every record; if it's missing, the check lands on
        'Unknown' instead of in one of the eight layers).
    .OUTPUTS
        None. Writes one record via New-CAInvRecord.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)] $Catalog,
        $CtxConfig,
        [Parameter(Mandatory)] [string] $Domain
    )

    $src = 'Aggregation: config/checkids.json x sections.json x categories.json x layers.json'

    function Get-CfgPart {
        param($Config, [string] $Name)
        $value = if ($Config -is [System.Collections.IDictionary]) { $Config[$Name] } else { Get-CAInvProp $Config $Name }
        if (-not $value) {
            try { $value = (Get-CAInvConfig).$Name } catch { $value = $null }
        }
        return $value
    }

    $sectionsCfg   = Get-CfgPart -Config $CtxConfig -Name 'Sections'
    $categoriesCfg = Get-CfgPart -Config $CtxConfig -Name 'Categories'
    $layersCfg     = Get-CfgPart -Config $CtxConfig -Name 'Layers'

    $missing = @()
    if (-not $sectionsCfg)   { $missing += 'config/sections.json' }
    if (-not $categoriesCfg) { $missing += 'config/categories.json' }
    if (-not $layersCfg)     { $missing += 'config/layers.json' }
    if ($missing.Count -gt 0) {
        New-CAInvRecord -Domain $Domain -CheckId 'Govern-05' -ObjectType 'Tenant' `
            -Property 'checkIdTaxonomy' -Status 'Not assessed' `
            -NotAssessedReason ('Cannot be checked: {0} could not be read.' -f @($missing -join ', ')) `
            -ApiVersion 'n/a' -GraphSource $src | Out-Null
        return
    }

    $prefixes = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@(Get-CAInvProp $sectionsCfg 'sections' @() | ForEach-Object { [string](Get-CAInvProp $_ 'prefix' '') }),
        [System.StringComparer]::Ordinal)
    $allowedCats = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@(Get-CAInvProp $categoriesCfg 'groups' @() | ForEach-Object { @(Get-CAInvProp $_ 'values' @()) } | ForEach-Object { [string]$_ }),
        [System.StringComparer]::Ordinal)

    $layerIndexes = [System.Collections.Generic.HashSet[int]]::new(
        [int[]]@(Get-CAInvProp $layersCfg 'layers' @() | ForEach-Object { [int](Get-CAInvProp $_ 'index' -1) }))

    $checks = @(Get-CAInvProp $Catalog 'checks' @())

    $problems = [System.Collections.Generic.List[string]]::new()

    foreach ($c in $checks) {
        $cid = [string](Get-CAInvProp $c 'checkId' '')
        if (-not $cid) { continue }
        $prefix = ($cid -split '-')[0]
        if (-not $prefixes.Contains($prefix)) {
            $problems.Add("$cid has prefix '$prefix' that is not in sections.json")
        }
        $cat = [string](Get-CAInvProp $c 'category' '')
        if ([string]::IsNullOrWhiteSpace($cat)) {
            $problems.Add("$cid has no category")
        }
        elseif (-not $allowedCats.Contains($cat)) {
            $problems.Add("$cid has category '$cat' that is not in categories.json")
        }

        $lay = Get-CAInvProp $c 'layer'
        if ($null -eq $lay) {
            $problems.Add("$cid has no layer; records from this check land on 'Unknown'")
        }
        elseif (-not $layerIndexes.Contains([int]$lay)) {
            $problems.Add("$cid has layer '$lay' that is not in layers.json")
        }
    }

    if ($problems.Count -eq 0) {
        New-CAInvRecord -Domain $Domain -CheckId 'Govern-05' -ObjectType 'Tenant' `
            -Property 'checkIdTaxonomy' `
            -ObservedValue "$($checks.Count) checks fall into $($prefixes.Count) sections, each with a category from the closed list." `
            -Status 'Ready' -ApiVersion 'n/a' -GraphSource $src | Out-Null
    }
    else {
        New-CAInvRecord -Domain $Domain -CheckId 'Govern-05' -ObjectType 'Tenant' `
            -Property 'checkIdTaxonomy' `
            -ObservedValue (@($problems) -join '; ') `
            -Status 'Gap' -ApiVersion 'n/a' -GraphSource $src `
            -Recommendation ('Fix config/checkids.json, sections.json, or categories.json so they line up again. This is a bug in the module, not in the tenant.') | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $Domain -Message "Taxonomy checked: $($checks.Count) checks, $($problems.Count) problem(s)."
}
