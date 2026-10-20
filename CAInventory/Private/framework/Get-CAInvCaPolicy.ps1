function Get-CAInvCaPolicy {
    <#
    .SYNOPSIS
        The already-fetched CA policies from the context, or an empty array.
    .DESCRIPTION
        Replaces the guarded read that was literally scattered across fifteen files (in two
        slightly different forms — with and without the outer `@()` wrap) plus two files that
        already used the shorter `Get-CAInvProp` form. `layer0/Get-CAInvConditionalAccessPolicy.ps1`
        is the only writer; this function is read-only.

        No parameter for the context object: same design as `Get-CAInvEffectiveLookbackWindow` —
        there is exactly one run context.
    .OUTPUTS
        [object[]]
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    return @(Get-CAInvProp $script:CAInvContext 'CAPolicies' @())
}
