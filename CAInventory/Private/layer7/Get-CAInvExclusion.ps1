function Get-CAInvExclusion {
    <#
    .SYNOPSIS
        Domain 6.31 — Exclusions and exceptions.
    .DESCRIPTION
        Last technical collector. Collects NO new data but
        aggregates the exceptions the earlier layers have already fetched: CA policies with
        exclusions, exclusion groups without an owner, privileged users in exclusion groups, and
        service accounts in scope. Exceptions are the biggest hidden risk carrier
        in CA standardization: the technical scope is readable, the legitimacy usually isn't.
        Owner, reason, end date, and approval should come from a manual register (see
        Get-CAInvGovernanceEvidence); an exception without that metadata is by definition a
        finding.

        Which CheckIds count as an exception signal lives in config/checkids.json (field
        isExclusionSignal), not hardcoded here: otherwise a new exception-related
        check wouldn't count toward this without something flagging that.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.31'
    $src    = 'Aggregation over already-collected records (CA, groups, PIM, campaign)'

    $ctx = $script:CAInvContext
    $records = @(if ($ctx.PSObject.Properties.Name -contains 'Records') { @($ctx.Records) } else { @() })

    $caPolicies = @(Get-CAInvCaPolicy)
    $withExclusions = @($caPolicies | Where-Object {
        $u = Get-CAInvProp $_ 'conditions.users'
        (@(Get-CAInvProp $u 'excludeUsers' @()).Count -gt 0) -or
        (@(Get-CAInvProp $u 'excludeGroups' @()).Count -gt 0) -or
        (@(Get-CAInvProp $u 'excludeRoles' @()).Count -gt 0)
    })

    $catalog = Get-CAInvProp $ctx 'Config.CheckIds'
    $exclusionFindingIds = @(if ($catalog) {
        @($catalog.checks) | Where-Object { [bool](Get-CAInvProp $_ 'isExclusionSignal' $false) } | ForEach-Object { [string]$_.checkId }
    } else { @() })
    $relatedFindings = @($records | Where-Object {
        $exclusionFindingIds -contains $_.CheckId -and $_.Status -in @('Gap', 'Review required')
    })

    New-CAInvRecord -Domain $domain -CheckId 'Govern-01' -ObjectType 'Exclusion' `
        -Property 'exclusionSurface' `
        -ObservedValue "$($withExclusions.Count) CA policies with exclusions; $($relatedFindings.Count) open exclusion-related finding(s) from earlier layers." `
        -Status ($(if ($withExclusions.Count -gt 0 -or $relatedFindings.Count -gt 0) { 'Review required' } else { 'Ready' })) `
        -ManualReview:($withExclusions.Count -gt 0 -or $relatedFindings.Count -gt 0) `
        -ApiVersion 'n/a' -GraphSource $src `
        -Recommendation ('The technical exception scope is known, its legitimacy is not. Record owner, reason, end date, and approval per exception in a register; an exception without that metadata is a finding.') | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($withExclusions.Count) CA policies with exclusions; $($relatedFindings.Count) related findings."
}
