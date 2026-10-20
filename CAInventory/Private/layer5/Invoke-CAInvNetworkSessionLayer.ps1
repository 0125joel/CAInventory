function Invoke-CAInvNetworkSessionLayer {
    <#
    .SYNOPSIS
        Layer function 5 — Network and session. Calls this layer's collectors.
    .DESCRIPTION
        Domains: 6.20 named locations/network configuration, 6.26 session controls/token
        management, 6.28 Global Secure Access/compliant network. All
        three rely on the already-fetched CA policies (layer 0).
    #>
    [CmdletBinding()]
    param()

    Get-CAInvNamedLocation
    Get-CAInvSessionControl
    Get-CAInvGlobalSecureAccess
}
