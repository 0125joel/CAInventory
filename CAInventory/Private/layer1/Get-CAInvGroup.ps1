function Get-CAInvGroup {
    <#
    .SYNOPSIS
        Domain 6.12 — Groups and scoping.
    .DESCRIPTION
        Reads groups with owners and dynamic-rule processing status. Objectively flags: ownerless
        groups (candidate exclusion groups without an owner = high risk) and dynamic groups with a
        processing error. Whether a specific ownerless group is actually a CA exclusion group is
        determined by the integrity check; here we record the objective property. Keeps groups
        (incl. owner count) in the context object.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.12'

    $select = 'id,displayName,securityEnabled,groupTypes,isAssignableToRole,membershipRule,membershipRuleProcessingState,onPremisesSyncEnabled'
    $src    = 'GET /groups'

    $resp = Invoke-CAInvGraphOrNotAssessed -Uri "groups?`$select=$select" -ApiVersion 'v1.0' -MaxPages 100 `
        -Domain $domain -CheckId 'Identity-06' -ObjectType 'Group' -Property 'groups' `
        -GraphSource $src -NotAssessedReasonPrefix ('Could not read /groups')
    if ($resp.Failed) { return }

    $groups = @($resp.Value)
    $raw = Write-CAInvRaw -Domain $domain -Endpoint 'groups' -Data $groups

    $caGroupIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in @(Get-CAInvCaPolicy)) {
        $condUsers = Get-CAInvProp $p 'conditions.users'
        foreach ($gid in @(Get-CAInvProp $condUsers 'includeGroups' @()) + @(Get-CAInvProp $condUsers 'excludeGroups' @())) {
            if (-not [string]::IsNullOrWhiteSpace([string]$gid)) { [void]$caGroupIds.Add([string]$gid) }
        }
    }

    $ownerMap = @{}
    $ownerLookups = 0
    foreach ($g in $groups) {
        if ($caGroupIds.Contains([string]$g.id)) {
            $ownersResp = Invoke-CAInvGraph -Uri "groups/$($g.id)/owners?`$select=id" -ApiVersion 'v1.0'
            $ownerMap[$g.id] = if ($ownersResp.Failed) { -1 } else { @($ownersResp.Value).Count }
            $ownerLookups++
        }
        else {
            $ownerMap[$g.id] = $null
        }

        if ($g.membershipRuleProcessingState -and $g.membershipRuleProcessingState -ne 'On' -and $g.membershipRule) {
            New-CAInvRecord -Domain $domain -CheckId 'Identity-07' -ObjectType 'Group' `
                -ObjectId $g.id -ObjectName $g.displayName -Property 'membershipRuleProcessingState' `
                -ObservedValue $g.membershipRuleProcessingState -Status 'Gap' `
                -GraphSource $src -Recommendation ('Restore dynamic group processing; membership may be stale.') `
                -RawPath $raw | Out-Null
        }
    }

    $enriched = foreach ($g in $groups) {
        [PSCustomObject]@{
            id = $g.id; displayName = $g.displayName; securityEnabled = $g.securityEnabled
            groupTypes = $g.groupTypes; isAssignableToRole = $g.isAssignableToRole
            membershipRule = (Get-CAInvProp $g 'membershipRule' '')
            onPremisesSyncEnabled = (Get-CAInvProp $g 'onPremisesSyncEnabled' $false)
            ownerCount = $ownerMap[$g.id]
        }
    }
    Add-CAInvContextData -Context $script:CAInvContext -Name 'Groups' -Value @($enriched)

    New-CAInvRecord -Domain $domain -CheckId 'Identity-01' -ObjectType 'Tenant' `
        -Property 'groupCount' -ObservedValue $groups.Count -Status 'Ready' `
        -GraphSource $src -RawPath $raw | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($groups.Count) groups inventoried; owners fetched for $ownerLookups CA-referenced group(s)."
}
