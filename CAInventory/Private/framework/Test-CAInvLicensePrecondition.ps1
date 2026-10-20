function Test-CAInvLicensePrecondition {
    <#
    .SYNOPSIS
        DRY helper: central license gate for checks that can't be measured without a specific
        license.
    .DESCRIPTION
        Before this helper, the pattern "check $ctx.Preflight.Licenses; if the license is missing,
        write a Not assessed record and return" was repeated inline in every collector
        (Evidence-07, Identity-18, Identity-12, Evidence-05). That wasn't DRY and, more
        importantly, wasn't visible anywhere as a single policy: which check needs which license
        was scattered across collector code and description text.

        The requirement now lives as `licenseRequirement` on the check in `config/checkids.json`
        (a list; ANY named capability is sufficient, so "P2 or Governance" is expressible), and
        this helper is the only place that enforces it.

        Returns $true when the check may simply run. Returns $false when the required license is
        demonstrably missing; in that case this function has ITSELF already written the Not
        assessed record (with -LicenseRequirement filled in), the same way
        Invoke-CAInvGraphOrNotAssessed does on a failed Graph call. The caller then only needs to
        `return`. The Graph call is thereby never even attempted: that avoids a guaranteed
        401/403 per check.

        Never guess (CLAUDE.md): gating happens ONLY when the license context was actually
        measured. If `subscribedSkus` couldn't be read (`$ctx.Preflight.LicensesKnown` = $false),
        or there's no preflight/no requirement, this helper returns $true and nothing about
        existing behavior changes: the check runs and real error handling determines the outcome.
        An unknown license context is not evidence of absence.
    .OUTPUTS
        [bool] $true = check mag draaien; $false = licentie ontbreekt, record is al geschreven.
    .EXAMPLE
        if (-not (Test-CAInvLicensePrecondition -CheckId 'Evidence-07' -Domain $domain `
                -ObjectType 'RiskyUser' -Property 'identityProtection' -GraphSource $src)) { return }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $CheckId,

        [Parameter(Mandatory)]
        [string] $Domain,

        [string] $ObjectType,
        [string] $Property,
        [string] $GraphSource,

        [string] $Consequence
    )

    $ctx = $script:CAInvContext

    $required = @(Get-CAInvCheckLicenseRequirement -CheckId $CheckId)
    if ($required.Count -eq 0) { return $true }

    if (-not [bool](Get-CAInvProp $ctx 'Preflight.LicensesKnown' $false)) {
        Write-CAInvLog -Level 'DEBUG' -Domain $Domain -Message "CheckId $CheckId : license gate skipped, license context unknown."
        return $true
    }

    $licenses = Get-CAInvProp $ctx 'Preflight.Licenses'
    if (-not $licenses) { return $true }

    $capabilities = Get-CAInvProp $ctx 'Config.SkuMap.capabilities'
    $displayNames = @(foreach ($cap in $required) {
        $display = Get-CAInvProp $capabilities "$cap.displayName"
        if ($display) { $display } else { $cap }
    })

    foreach ($cap in $required) {

        if (-not (Get-CAInvProp $capabilities $cap)) {
            Write-CAInvLog -Level 'WARN' -Domain $Domain -Message "CheckId $CheckId : licenseRequirement '$cap' is unknown in the SKU map; gate skipped."
            return $true
        }
        if ([bool](Get-CAInvProp $licenses $cap $false)) { return $true }
    }

    $needed = $displayNames -join ' or '
    $reason = 'Requires {0}; not detected in this tenant''s licenses.' -f @($needed)
    if ($Consequence) { $reason = "$reason $Consequence" }

    New-CAInvRecord -Domain $Domain -CheckId $CheckId -ObjectType $ObjectType `
        -Property $Property -Status 'Not assessed' -NotAssessedReason $reason `
        -LicenseRequirement $needed -GraphSource $GraphSource -ApiVersion 'n/a' | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $Domain -Message "CheckId $CheckId skipped: $needed not present."
    return $false
}
