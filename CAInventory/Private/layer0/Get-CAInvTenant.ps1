function Get-CAInvTenant {
    <#
    .SYNOPSIS
        Domain 6.1 — Tenant foundation and licenses.
    .DESCRIPTION
        Reads /organization, /subscribedSkus and builds the licenseCapabilityMap. Determines the
        hard precondition from the scorecard: is there P1/P2/Intune coverage for the planned
        controls? Records verifiedDomains. Separates configuration (present SKUs) from
        interpretation (adequate coverage remains context-dependent).
    #>
    [CmdletBinding()]
    param()

    $domain = '6.1'
    $src    = 'GET /organization; GET /subscribedSkus'

    $orgResp = Invoke-CAInvGraph -Uri 'organization?$select=id,displayName,verifiedDomains,tenantType,createdDateTime' -ApiVersion 'v1.0'
    if ($orgResp.Failed) {
        New-CAInvRecord -Domain $domain -CheckId 'Foundation-02' -ObjectType 'Tenant' `
            -ObjectId $script:CAInvContext.TenantId -Property 'organization' `
            -ObservedValue $orgResp.ErrorMessage -Status 'Not assessed' `
            -NotAssessedReason ('Could not read /organization: {0}' -f @($orgResp.ErrorMessage)) `
            -GraphSource $src | Out-Null
    }
    else {
        $org = $orgResp.Value | Select-Object -First 1
        $rawOrg = Write-CAInvRaw -Domain $domain -Endpoint 'organization' -Data $org
        $verified = @($org.verifiedDomains)
        $primary = ($verified | Where-Object { $_.isDefault }) | Select-Object -First 1

        New-CAInvRecord -Domain $domain -CheckId 'Foundation-02' -ObjectType 'Tenant' `
            -ObjectId $org.id -ObjectName $org.displayName -Property 'verifiedDomains' `
            -ObservedValue ("$($verified.Count) domain(s); primary: $($primary.name)") `
            -Status 'Ready' -GraphSource $src `
            -Recommendation ('Check federated/onmicrosoft domains against the break-glass design.') `
            -RawPath $rawOrg | Out-Null
    }

    $skuResp = Invoke-CAInvGraphOrNotAssessed -Uri 'subscribedSkus' -ApiVersion 'v1.0' `
        -Domain $domain -CheckId 'Foundation-01' -ObjectType 'Tenant' `
        -ObjectId $script:CAInvContext.TenantId -Property 'subscribedSkus' `
        -GraphSource $src -NotAssessedReasonPrefix ('Could not read /subscribedSkus')
    if ($skuResp.Failed) { return }

    $rawSku = Write-CAInvRaw -Domain $domain -Endpoint 'subscribedSkus' -Data $skuResp.Value

    $licensesKnown = [bool](Get-CAInvProp $script:CAInvContext 'Preflight.LicensesKnown' $false)

    if (-not $licensesKnown) {
        foreach ($capName in @('EntraIdP1', 'EntraIdP2', 'IntunePlan1')) {
            $req = if ($capName -eq 'EntraIdP1') { 'Entra ID P1' } else { $capName }
            New-CAInvRecord -Domain $domain -CheckId 'Foundation-01' -ObjectType 'Tenant' `
                -ObjectId $script:CAInvContext.TenantId -Property $capName -Status 'Not assessed' `
                -NotAssessedReason ('License context unknown (preflight failed or not yet run); no license verdict possible.') `
                -GraphSource $src -LicenseRequirement $req -RawPath $rawSku | Out-Null
        }
        return
    }

    $lic = $script:CAInvContext.Preflight.Licenses

    $p1 = $lic.EntraIdP1
    New-CAInvRecord -Domain $domain -CheckId 'Foundation-01' -ObjectType 'Tenant' `
        -ObjectId $script:CAInvContext.TenantId -Property 'EntraIdP1' `
        -ObservedValue $p1 -Status ($(if ($p1) { 'Ready' } else { 'Gap' })) `
        -GraphSource $src `
        -LicenseRequirement 'Entra ID P1' `
        -Recommendation ($(if ($p1) { 'P1 present; CA controls are licensable.' } else { 'No P1 detected: Conditional Access cannot be licensed compliantly.' })) `
        -RawPath $rawSku | Out-Null

    foreach ($capName in @('EntraIdP2', 'IntunePlan1')) {
        $has = $lic.$capName
        New-CAInvRecord -Domain $domain -CheckId 'Foundation-01' -ObjectType 'Tenant' `
            -ObjectId $script:CAInvContext.TenantId -Property $capName `
            -ObservedValue $has -Status ($(if ($has) { 'Ready' } else { 'Review required' })) `
            -GraphSource $src `
            -LicenseRequirement $capName -ManualReview:(-not $has) `
            -Recommendation ('Confirm whether controls requiring {0} are in scope.' -f @($capName)) `
            -RawPath $rawSku | Out-Null
    }
}
