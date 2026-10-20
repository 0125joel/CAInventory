function Invoke-CAInvApplicationLayer {
    <#
    .SYNOPSIS
        Layer function 3 — Applications. Calls this layer's collectors.
    .DESCRIPTION
        Domains: 6.14 enterprise apps/app registrations, 6.15 workload identities, 6.16 legacy
        authentication (usage), 6.27 authentication flows.
        Applications first, so the workload identity collector reuses the fetched service
        principals.
    #>
    [CmdletBinding()]
    param()

    Get-CAInvApplication
    Get-CAInvWorkloadIdentity
    Get-CAInvLegacyAuthUsage
    Get-CAInvAuthFlow
}
