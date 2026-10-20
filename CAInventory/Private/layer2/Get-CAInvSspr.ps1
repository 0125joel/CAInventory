function Get-CAInvSspr {
    <#
    .SYNOPSIS
        Domain 6.10 — Self-service password reset (SSPR).
    .DESCRIPTION
        Layer 2 collector. Modern Graph only partially covers SSPR: the authenticationMethodsPolicy
        determines which methods are usable for reset, but the SSPR enablement status (None/Selected/
        All), target audience, and password writeback remain largely portal- or Connect-dependent.
        This collector records what's readable and explicitly marks the rest as Review required,
        instead of a falsely hard verdict on a half-available source.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.10'

    $campaign = Get-CAInvRegistrationCampaign
    if ($campaign.Failed) {
        New-CAInvRecord -Domain $domain -CheckId 'Auth-15' -ObjectType 'Policy' `
            -Property 'ssprConfiguration' -Status 'Not assessed' `
            -NotAssessedReason ('authenticationMethodsPolicy not readable: {0}' -f @($campaign.ErrorMessage)) `
            -GraphSource 'GET /policies/authenticationMethodsPolicy' | Out-Null
        return
    }

    New-CAInvRecord -Domain $domain -CheckId 'Auth-15' -ObjectType 'Policy' `
        -Property 'ssprEnablementAndWriteback' `
        -ObservedValue 'SSPR enablement status (None/Selected/All), target audience, and password writeback are not fully readable via Graph.' `
        -Status 'Review required' -ManualReview -ApiVersion 'n/a' `
        -GraphSource 'Portal: Entra > Password reset' `
        -Recommendation ('Manually check the SSPR target audience and whether password writeback is on. SSPR registration and MFA registration share the same methods; combined registration avoids duplicate nudges during the CA migration.') | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message 'SSPR context recorded (largely portal-dependent).'
}
