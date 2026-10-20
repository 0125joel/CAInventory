function Invoke-CAInvAuthenticationLayer {
    <#
    .SYNOPSIS
        Layer function 2 — Authentication. Calls this layer's collectors.
    .DESCRIPTION
        Domains: 6.3 security defaults/legacy MFA, 6.5 authentication methods policy, 6.6
        authentication strengths, 6.7 registration campaign, 6.8 user registration details, 6.9
        individual registrations (sensitive), 6.10 SSPR.

        The method usage matrix (Get-CAInvMethodUsageMatrix) belongs to this layer content-wise
        but depends on the sign-in logs from layer 6. Invoke-CAInventory therefore only calls it
        AT THE END of the chain, not here.
    #>
    [CmdletBinding()]
    param()

    Get-CAInvLegacyMfaConfig
    Get-CAInvPasswordProtection
    Get-CAInvAuthMethodPolicy
    Get-CAInvAuthStrength
    Get-CAInvRegistrationCampaignCheck
    Get-CAInvUserRegistrationDetail
    Get-CAInvUserAuthMethod
    Get-CAInvSspr
    Get-CAInvFederatedDomain
}
