function Get-CAInvCheckLicenseRequirement {
    <#
    .SYNOPSIS
        Reads a check's `licenseRequirement` from config/checkids.json.
    .DESCRIPTION
        One place that queries the check catalog on this field, so both the license gate
        (Test-CAInvLicensePrecondition) and the reporting layer use the same source.

        `licenseRequirement` is a list of capability names as they appear in
        `config/sku-license-map.json` (`EntraIdP2`, `EntraIdGovernance`, `IntunePlan1`, ...). The
        semantics are OR: any one of the named capabilities is sufficient on its own. That's
        needed because Microsoft ships PIM and access reviews under both Entra ID P2 and Entra ID
        Governance; a tenant with only P1 plus a Governance subscription does have that
        functionality.

        A check without the field yields an empty array: no requirement, so never a gate.
    .OUTPUTS
        [object[]] Capability names as an array; empty when the check has no license requirement.
        (Deliberately object[] and not string[]: the values come from ConvertFrom-Json and are
        untyped; a string[] declaration only produces a PSScriptAnalyzer finding.)
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string] $CheckId
    )

    $ctx = $script:CAInvContext
    $catalog = Get-CAInvProp $ctx 'Config.CheckIds'
    if (-not $catalog) { return @() }

    $check = $null
    foreach ($c in @($catalog.checks)) {
        if ((Get-CAInvProp $c 'checkId') -eq $CheckId) { $check = $c; break }
    }
    if (-not $check) { return @() }

    return @(Get-CAInvProp $check 'licenseRequirement' @())
}
