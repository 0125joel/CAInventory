function Resolve-CAInvBrandIdentity {
    <#
    .SYNOPSIS
        Dynamically fills in $ctx.Brand with the tenant name and, optionally, the tenant's own
        Entra branding color.
    .DESCRIPTION
        Runs after Connect-CAInv (a Graph session is needed) and before layer 0. Does nothing when
        the caller has provided an explicit -BrandFile: that always wins over tenant data.

        Two independent, both soft steps: the brand bar otherwise shows "CAInventory -
        {tenant displayName}" instead of a bare "CAInventory", and the tenant's own Entra branding
        color (organizationalBranding.backgroundColor, when configured) colors only the accent
        role. The four status colors (gap/review/lowInfo/ready) are never touched here: they carry
        meaning and should mean the same thing from report to report — a coincidental tenant
        sign-in color there would be a gamble, not an improvement.

        Neither of these is a check: no CheckId, no findings record, purely presentational. No own
        branding (the vast majority of tenants) is the norm, not a deviation, and Invoke-
        CAInvGraph already fails soft itself (404/permission error -> Failed = $true, never a
        throw); the outer try/catch here is only a safety net for the surrounding logic itself
        (Get-CAInvProp/ConvertTo-CAInvHtmlSafe), so a cosmetic detail can never bring down the
        whole run.
    .OUTPUTS
        None. Mutates $script:CAInvContext.Brand.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()

    $ctx = $script:CAInvContext
    if (-not $ctx -or -not $ctx.Brand) { return }
    if ($ctx.PSObject.Properties['BrandFile'] -and $ctx.BrandFile) { return }

    try {
        $orgResp = Invoke-CAInvGraph -Uri 'organization?$select=id,displayName' -ApiVersion 'v1.0'
        if ($orgResp.Failed) { return }

        $org = $orgResp.Value | Select-Object -First 1
        $orgId = [string](Get-CAInvProp $org 'id')
        $displayName = [string](Get-CAInvProp $org 'displayName')

        if ($displayName) {
            $ctx.Brand.name = ConvertTo-CAInvHtmlSafe -Text "CAInventory - $displayName"
        }

        if (-not $orgId) { return }

        $brandingResp = Invoke-CAInvGraph -Uri "organization/$orgId/branding" -ApiVersion 'v1.0' -Headers @{ 'Accept-Language' = '0' }
        if ($brandingResp.Failed) { return }

        $backgroundColor = [string](Get-CAInvProp $brandingResp.Value 'backgroundColor')
        if ($backgroundColor -match '^#[0-9A-Fa-f]{6}$') {
            $ctx.Brand.colors.accent = $backgroundColor
        }
    }
    catch {
        Write-CAInvLog -Level 'DEBUG' -Message "Dynamic brand identity not fully resolved, falling back to defaults: $($_.Exception.Message)"
    }
}
