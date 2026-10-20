function Invoke-CAInvFoundationLayer {
    <#
    .SYNOPSIS
        Layer function 0 — Foundation and CA basics. Calls this layer's collectors.
    .DESCRIPTION
        This layer ALWAYS runs (even when another layer is selected), because tenant and license
        context determines which later checks are meaningful. Domains:
        6.1 tenant foundation/licenses, 6.2 existing CA configuration, 6.30 ToU/auth context.
    #>
    [CmdletBinding()]
    param()

    Get-CAInvTenant
    Get-CAInvConditionalAccessPolicy

    Get-CAInvManagedPolicy
    Get-CAInvPolicyLimit
    Get-CAInvTermsAndAuthContext
}
