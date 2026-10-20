function Get-CAInvBrand {
    <#
    .SYNOPSIS
        Reads and validates the optional brand file for the report UI.
    .DESCRIPTION
        Without -BrandFile (or an unreadable file), this function returns CAInventory's own
        default identity, not a brandless placeholder palette: name "CAInventory" and a color set
        derived from PIM Monitor's severity system (red/amber/green/grey, which already maps
        nearly 1-to-1 onto this report's four status roles Gap/Review/LowInfo/Ready).
        Resolve-CAInvBrandIdentity later fills in .name with the tenant name and optionally
        .colors.accent with the tenant's own Entra branding color, but only when no -BrandFile was
        supplied — an explicitly supplied brand file always wins.

        Unknown keys and invalid hex colors are ignored with a WARN log, never an error: a broken
        brand file must never break a run. name/tagline/footerLine go through
        ConvertTo-CAInvHtmlSafe before they land (both the defaults and file values), so every
        caller of this function gets an already-safe string back.

        .custom is $true as soon as a brand file has actually been read (regardless of whether the
        file really overrides any of the keys), $false for the bare default. New-CAInvReportTopbar
        uses this to only show the ›› brand mark for an explicit brand file. The default identity has
        no brand mark, so a null check on $Brand itself isn't sufficient,
        because $ctx.Brand is never $null in the real pipeline: Get-CAInvBrand always returns a
        hashtable, default or not.
    .PARAMETER BrandFile
        Path to a JSON file with (optionally) name, tagline, footerLine and colors
        (ink/accent/gap/review/lowInfo/ready). All keys are optional.
    .OUTPUTS
        [hashtable] with keys name, tagline, footerLine, colors (nested hashtable), custom (bool).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string] $BrandFile
    )

    $defaultColors = @{
        ink     = '#171717'
        accent  = '#D97706'
        gap     = '#EF4444'
        review  = '#D97706'
        lowInfo = '#737373'
        ready   = '#22C55E'
    }

    $brand = @{
        name       = ConvertTo-CAInvHtmlSafe -Text 'CAInventory'
        tagline    = ''
        footerLine = ConvertTo-CAInvHtmlSafe -Text 'CAInventory - read-only inventory, zero changes to the tenant.'
        colors     = $defaultColors.Clone()
        custom     = $false
    }

    if (-not $BrandFile) { return $brand }

    if (-not (Test-Path -LiteralPath $BrandFile)) {
        Write-CAInvLog -Level 'WARN' -Message "Brand file not found: $BrandFile. Falling back to defaults."
        return $brand
    }

    $raw = $null
    try {
        $raw = Get-Content -LiteralPath $BrandFile -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
    }
    catch {
        Write-CAInvLog -Level 'WARN' -Message "Brand file $BrandFile is not valid JSON ($($_.Exception.Message)). Falling back to defaults."
        return $brand
    }

    $brand.custom = $true

    $knownKeys = @('name', 'tagline', 'footerLine', 'colors')
    foreach ($key in $raw.Keys) {
        if ($key -notin $knownKeys) {
            Write-CAInvLog -Level 'WARN' -Message "Unknown key '$key' in brand file $BrandFile, ignored."
        }
    }

    foreach ($textKey in @('name', 'tagline', 'footerLine')) {
        if ($raw.ContainsKey($textKey) -and $raw[$textKey]) {
            $brand[$textKey] = ConvertTo-CAInvHtmlSafe -Text ([string]$raw[$textKey])
        }
    }

    if ($raw.ContainsKey('colors') -and $raw['colors'] -is [System.Collections.IDictionary]) {
        foreach ($colorKey in $raw['colors'].Keys) {
            if ($colorKey -notin $defaultColors.Keys) {
                Write-CAInvLog -Level 'WARN' -Message "Unknown color key '$colorKey' in brand file $BrandFile, ignored."
                continue
            }
            $value = [string]$raw['colors'][$colorKey]
            if ($value -match '^#[0-9A-Fa-f]{6}$') {
                $brand.colors[$colorKey] = $value
            }
            else {
                Write-CAInvLog -Level 'WARN' -Message "Invalid hex color '$value' for '$colorKey' in brand file $BrandFile, falling back to default."
            }
        }
    }

    return $brand
}
