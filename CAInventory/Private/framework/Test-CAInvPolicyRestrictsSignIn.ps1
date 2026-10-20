function Test-CAInvPolicyRestrictsSignIn {
    <#
    .SYNOPSIS
        Can this CA policy block or restrict a user at sign-in?
    .DESCRIPTION
        Microsoft's break-glass guidance applies to policies "that block or restrict sign-in"
        (Learn, role-based-access-control/security-emergency-access, verified 21-08-2026). Not
        every enabled policy falls under that, and the distinction is exactly the difference
        between a legitimate finding and bad advice.

        Out of scope:
          - **Report-only** ('enabledForReportingButNotEnforced') and disabled policies. Microsoft
            explicitly: "Report-only policies don't block access and don't need to exclude
            emergency accounts."
          - **Step-up-only policies**: policies with no includeApplications, scoped solely to an
            authentication context (ACRS) or a user action. Those don't run at sign-in, only when
            a resource requests the context or action (for example, PIM role activation). Per
            Microsoft, a break-glass account should have a permanently active role assignment and
            therefore never activates a role; a policy like that can't lock the account out.

        This function is the ONLY place that distinction is made. The rule previously lived only
        in Foundation-07; Emergency-03 (break-glass excluded from CA) checked against all enabled
        policies and could therefore flag a step-up-only policy as a lockout risk, even though by
        Microsoft's own definition it isn't one.
    .PARAMETER Policy
        The Conditional Access policy object from Graph.
    .OUTPUTS
        Boolean.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowNull()][object] $Policy
    )

    if (-not $Policy) { return $false }
    if ((Get-CAInvProp $Policy 'state' '') -ne 'enabled') { return $false }

    $apps = Get-CAInvProp $Policy 'conditions.applications'
    $stepUpOnly = (
        (@(Get-CAInvProp $apps 'includeApplications' @()).Count -eq 0) -and
        (
            (@(Get-CAInvProp $apps 'includeAuthenticationContextClassReferences' @()).Count -gt 0) -or
            (@(Get-CAInvProp $apps 'includeUserActions' @()).Count -gt 0)
        )
    )

    return (-not $stepUpOnly)
}
