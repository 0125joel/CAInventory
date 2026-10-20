function Invoke-CAInvEvidenceLayer {
    <#
    .SYNOPSIS
        Layer function 6 — Usage and evidence. Calls this layer's collectors.
    .DESCRIPTION
        Domains: 6.25 insights/readiness, 6.23 sign-in logs, 6.24 audit logs, 6.22 Identity
        Protection. The readiness collector runs FIRST and determines
        whether the log-dependent checks are meaningful; then the sign-in logs (which feed the
        matrix and the legacy auth usage check), the audit logs, and Identity Protection.
    #>
    [CmdletBinding()]
    param()

    Get-CAInvInsightsReadiness
    Get-CAInvSignInLog

    Get-CAInvCaCoverage
    Get-CAInvAuditLog
    Get-CAInvIdentityProtection
}
