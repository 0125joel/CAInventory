function Get-CAInvEffectiveLookbackWindow {
    <#
    .SYNOPSIS
        Reads the effective log window (days) from the run context, with the default fallback.
    .DESCRIPTION
        This exact expression was literally repeated in five files
        (Get-CAInvSignInData, Get-CAInvSignInUsageKql, Get-CAInvLegacyAuthUsageKql,
        Get-CAInvAuditLog, Get-CAInvIdentityProtection) and in two near-identical variants
        (Get-CAInvEmergencyAccess read $ctx.LookbackDays directly, without the 30 fallback if that
        property was also missing; Get-CAInvMethodUsageMatrix used a third idiom for the same
        existence check). All seven are functionally equivalent for any realistic value; checked
        before consolidating to make sure neither of the two deviating idioms
        was aiming for a deliberately different outcome.

        $ctx.EffectiveLookbackDays is the window as determined by Resolve-CAInvLogWindow (can
        stretch up to the Log Analytics workspace retention, up to -MaxLookbackDays). If that's
        missing — Resolve-CAInvLogWindow hasn't run yet, or a layer runs in isolation without the
        full Invoke-CAInventory orchestration — this function falls back to $ctx.LookbackDays, and
        to 30 for a completely empty/missing context. Both are purely defensive: in a real run,
        Invoke-CAInventory.ps1 already sets both LookbackDays and EffectiveLookbackDays at the
        start of the context object, so the fallback to 30 is never reached in production.
    .OUTPUTS
        Int.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $ctx = $script:CAInvContext
    return [int](Get-CAInvProp $ctx 'EffectiveLookbackDays' ([int](Get-CAInvProp $ctx 'LookbackDays' 30)))
}
