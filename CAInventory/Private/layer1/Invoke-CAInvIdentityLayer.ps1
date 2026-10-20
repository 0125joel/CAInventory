function Invoke-CAInvIdentityLayer {
    <#
    .SYNOPSIS
        Layer function 1 — Identity. Calls this layer's collectors in dependency order: users and
        groups first (needed for scope calculation), then privileged access, then emergency access
        (deliberately reads across layer boundaries) and external identities.
    .DESCRIPTION
        Domains: 6.11 users, 6.12 groups, 6.13 directory roles/PIM, 6.4 emergency access, 6.21
        cross-tenant/external identities.
    #>
    [CmdletBinding()]
    param()

    Get-CAInvUser
    Get-CAInvGroup
    Get-CAInvPrivilegedAccess

    Get-CAInvDirectorySyncAccount
    Get-CAInvEmergencyAccess
    Get-CAInvExternalIdentity

    Get-CAInvProtectedAction
}
