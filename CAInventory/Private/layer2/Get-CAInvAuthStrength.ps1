function Get-CAInvAuthStrength {
    <#
    .SYNOPSIS
        Domain 6.6 — Authentication strengths.
    .DESCRIPTION
        Layer 2 collector. Reads the authentication strength policies (built-in and custom) and
        their allowedCombinations, and records which strengths are actually referenced from CA
        policies. This is the 'eligible' axis of the method matrix: a
        method is only strength-eligible if it appears in the allowedCombinations of the used or
        planned strength.

        The strengths are kept in the context object (AuthStrengths) so Get-CAInvMethodUsageMatrix
        can combine them at the end of the chain. CA references are counted from the
        already-fetched CAPolicies (layer 0) when available.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.6'
    $src    = 'GET /identity/conditionalAccess/authenticationStrength/policies'

    $resp = Invoke-CAInvGraphOrNotAssessed -Uri 'identity/conditionalAccess/authenticationStrength/policies' -ApiVersion 'v1.0' `
        -Domain $domain -CheckId 'Auth-04' -ObjectType 'Policy' -Property 'authenticationStrengthPolicies' `
        -GraphSource $src -NotAssessedReasonPrefix ('Could not read authenticationStrength/policies')
    if ($resp.Failed) { return }

    $strengths = @($resp.Value)
    $raw = Write-CAInvRaw -Domain $domain -Endpoint 'authenticationStrengthPolicies' -Data $strengths

    $caPolicies = @(Get-CAInvCaPolicy)
    $referencedIds = @()
    foreach ($p in $caPolicies) {
        $ref = Get-CAInvProp $p 'grantControls.authenticationStrength.id'
        if ($ref) { $referencedIds += $ref }
    }
    $referencedIds = @($referencedIds | Select-Object -Unique)

    Add-CAInvContextData -Context $script:CAInvContext -Name 'AuthStrengths' -Value $strengths

    foreach ($s in $strengths) {
        $combos = @(Get-CAInvProp $s 'allowedCombinations' @())
        $isReferenced = ($referencedIds -contains $s.id)

        New-CAInvRecord -Domain $domain -CheckId 'Auth-04' -ObjectType 'AuthenticationStrength' `
            -ObjectId $s.id -ObjectName (Get-CAInvProp $s 'displayName' $s.id) -Property 'allowedCombinations' `
            -ObservedValue ("$($combos.Count) combinations; type=$(Get-CAInvProp $s 'policyType' 'unknown'); referenced by CA=$isReferenced") `
            -Status 'Ready' -GraphSource $src -RawPath $raw `
            -Recommendation ($(if (-not $isReferenced) { 'This strength is referenced by no CA policy at all; purely informational or unused.' } else { $null })) | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($strengths.Count) authentication strengths read ($($referencedIds.Count) referenced by CA)."
}
