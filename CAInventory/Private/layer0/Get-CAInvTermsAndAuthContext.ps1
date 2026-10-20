function Get-CAInvTermsAndAuthContext {
    <#
    .SYNOPSIS
        Domain 6.30 — Terms of Use and authentication context.
    .DESCRIPTION
        Reads ToU agreements and authenticationContextClassReferences. These objects are
        referenced in CA and privileged access; missing objects break the intent. The collector
        records the present objects in $ctx.TermsOfUse/$ctx.AuthContexts; the actual matching
        against CA policies that point to a non-existent reference happens in the cross-check
        Foundation-15 in Test-CAInvReferentialIntegrity.ps1.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.30'

    $touResp = Invoke-CAInvGraphOrNotAssessed -Uri 'identityGovernance/termsOfUse/agreements' -ApiVersion 'v1.0' `
        -Domain $domain -CheckId 'Foundation-15' -ObjectType 'Agreement' -Property 'termsOfUse' `
        -GraphSource 'GET /identityGovernance/termsOfUse/agreements' `
        -NotAssessedReasonPrefix ('Could not read Terms of Use (possibly license/permission)')
    if (-not $touResp.Failed) {
        $tou = @($touResp.Value)
        $raw = Write-CAInvRaw -Domain $domain -Endpoint 'termsOfUse' -Data $tou
        Add-CAInvContextData -Context $script:CAInvContext -Name 'TermsOfUse' -Value $tou
        New-CAInvRecord -Domain $domain -CheckId 'Foundation-15' -ObjectType 'Agreement' `
            -Property 'count' -ObservedValue $tou.Count -Status 'Ready' `
            -GraphSource 'GET /identityGovernance/termsOfUse/agreements' -RawPath $raw | Out-Null
    }

    $acResp = Invoke-CAInvGraphOrNotAssessed -Uri 'identity/conditionalAccess/authenticationContextClassReferences' -ApiVersion 'v1.0' `
        -Domain $domain -CheckId 'Foundation-15' -ObjectType 'AuthenticationContext' -Property 'authContext' `
        -GraphSource 'GET /identity/conditionalAccess/authenticationContextClassReferences' `
        -NotAssessedReasonPrefix ('Could not read authentication context')
    if (-not $acResp.Failed) {
        $ac = @($acResp.Value)
        $raw = Write-CAInvRaw -Domain $domain -Endpoint 'authenticationContext' -Data $ac
        Add-CAInvContextData -Context $script:CAInvContext -Name 'AuthContexts' -Value $ac
        foreach ($c in $ac) {

            $published = Get-CAInvProp $c 'isAvailableToAllApps' $false
            New-CAInvRecord -Domain $domain -CheckId 'Foundation-15' -ObjectType 'AuthenticationContext' `
                -ObjectId (Get-CAInvProp $c 'id') -ObjectName (Get-CAInvProp $c 'displayName') -Property 'isAvailableToAllApps' `
                -ObservedValue $published -Status 'Ready' `
                -GraphSource 'GET /identity/conditionalAccess/authenticationContextClassReferences' -RawPath $raw | Out-Null
        }
    }
}
