function Invoke-CAInvGovernanceLayer {
    <#
    .SYNOPSIS
        Layer function 7 — Governance. Calls this layer's collectors.
    .DESCRIPTION
        Domains: 6.4 emergency access cross-check, 6.13 privileged-count cross-check, 6.31
        exclusions/exceptions, 6.32 governance/manageability, 6.34 expiring functionality. This layer collects almost no new data but aggregates what
        the earlier layers have fetched; it therefore runs late in the chain.
    #>
    [CmdletBinding()]
    param()

    Get-CAInvExclusion

    Get-CAInvDailyAdmin

    Get-CAInvEmergencyRolePermanence
    Get-CAInvGovernanceEvidence

    Get-CAInvLifecycleDate
}
