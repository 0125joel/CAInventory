function Add-CAInvContextData {
    <#
    .SYNOPSIS
        The only place where the run-context object gets a new property.
    .DESCRIPTION
        Replaces the bare `Add-Member -Force` on $script:CAInvContext. A second writer of the
        same property name now fails hard instead of silently overwriting the first — the
        collision that the design wants to make hard. A small number of
        properties are a deliberate, computed-once cache that already guards its own call with a
        guard clause at the top of that same function (e.g. CategoryMap, RegistrationCampaign,
        SignInData: "if the property already exists, return it instead of measuring again").
        Those call with -AllowOverwrite — not because overwriting is desirable there, but because
        the guard already makes the collision impossible, so this helper doesn't need to guard it
        a second time.

        Same kind of invariant as the POST block in Invoke-CAInvGraph.ps1: this isn't Graph
        unreliability that a collector gracefully handles, but a programming error in the module
        itself. A throw is therefore appropriate here (CLAUDE.md's "never hard throw" applies to
        the findings layer, not this kind of framework invariant).
    .PARAMETER Context
        The object the property is set on. Almost always $script:CAInvContext, but the helper
        isn't tied to it so it can also be used on a nested cache object.
    .PARAMETER Name
        The property name.
    .PARAMETER Value
        The value. $null is a valid value (e.g. LogAnalyticsToken after a failed sign-in).
    .PARAMETER AllowOverwrite
        Allow an existing property to be overwritten. Only for a deliberate cache with its own
        guard; see .DESCRIPTION.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [string] $Name,

        [AllowNull()]
        $Value,

        [switch] $AllowOverwrite
    )

    if (-not $AllowOverwrite -and $Context.PSObject.Properties[$Name]) {
        throw "Add-CAInvContextData: property '$Name' already exists on this context object. A second writer would silently overwrite the first -- use -AllowOverwrite if this is a deliberate cache with its own guard."
    }

    $Context | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
}
