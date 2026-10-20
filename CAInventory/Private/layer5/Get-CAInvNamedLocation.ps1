function Get-CAInvNamedLocation {
    <#
    .SYNOPSIS
        Domain 6.20 — Named locations and network configuration.
    .DESCRIPTION
        Layer 5 collector. Inventories the named locations (IP ranges and countries) and whether
        they're marked as trusted, and counts how often they're referenced from CA policies. A
        named location that's used nowhere is dead configuration; a trusted location that's widely
        trusted lowers the bar for those users. Reuses the
        already-fetched NamedLocations and CAPolicies (layer 0) when available.

        Always writes its own evidence for $locations, even when the data was reused
        from layer 0 (which already writes evidence itself under the same domain and endpoint,
        namedLocations; on reuse this is a second, byte-identical write). Named locations
        are typically a small list, so that duplicate write is negligible; the alternative (working
        out whether layer 0 already wrote it) is more code for no measurable gain. Without this
        write, a run that skipped layer 0 (e.g. -Layer Condition) would have a Condition-01/
        Condition-02 verdict without evidence for it ever having existed.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.20'
    $src    = 'GET /identity/conditionalAccess/namedLocations'

    $ctx = $script:CAInvContext
    if ($ctx.PSObject.Properties.Name -contains 'NamedLocations') {
        $locations = @($ctx.NamedLocations)
    }
    else {
        $resp = Invoke-CAInvGraphOrNotAssessed -Uri 'identity/conditionalAccess/namedLocations' -ApiVersion 'v1.0' `
            -Domain $domain -CheckId 'Condition-01' -ObjectType 'NamedLocation' -Property 'namedLocations' `
            -GraphSource $src -NotAssessedReasonPrefix ('Could not read namedLocations')
        if ($resp.Failed) { return }
        $locations = @($resp.Value)
    }
    $rawPath = Write-CAInvRaw -Domain $domain -Endpoint 'namedLocations' -Data $locations

    $caPolicies = @(Get-CAInvCaPolicy)

    $referenced = @()
    foreach ($p in $caPolicies) {
        $referenced += @(Get-CAInvProp $p 'conditions.locations.includeLocations' @())
        $referenced += @(Get-CAInvProp $p 'conditions.locations.excludeLocations' @())
    }
    $referenced = @($referenced | Where-Object { $_ -and $_ -notin @('All', 'AllTrusted') } | Select-Object -Unique)

    if ($locations.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-01' -ObjectType 'NamedLocation' `
            -Property 'namedLocations' -ObservedValue 'No named locations configured.' `
            -Status 'Ready' -GraphSource $src -RawPath $rawPath | Out-Null
        New-CAInvRecord -Domain $domain -CheckId 'Condition-02' -ObjectType 'NamedLocation' `
            -Property 'geoRestriction' -ObservedValue 'No named locations, so no geographic access restriction either.' `
            -Status 'Review required' -ManualReview -GraphSource $src -RawPath $rawPath `
            -Recommendation ('Consider a country-based named location with a CA policy that restricts access from unexpected countries.') | Out-Null
        return
    }

    foreach ($loc in $locations) {
        $isTrusted = [bool](Get-CAInvProp $loc 'isTrusted' $false)
        $isReferenced = ($referenced -contains $loc.id)

        $status = if (-not $isReferenced) { 'Gap' } else { 'Ready' }
        New-CAInvRecord -Domain $domain -CheckId 'Condition-01' -ObjectType 'NamedLocation' `
            -ObjectId $loc.id -ObjectName (Get-CAInvProp $loc 'displayName' $loc.id) -Property 'namedLocation' `
            -ObservedValue "trusted=$isTrusted; referencedByCA=$isReferenced" `
            -Status $status `
            -GraphSource $src -RawPath $rawPath `
            -Recommendation ($(if (-not $isReferenced) { 'This named location is used by no CA policy. Clean it up or put it to use; unused trusted locations are a risk if they later get linked by accident.' } else { $null })) | Out-Null
    }

    $countryLocations = @($locations | Where-Object { (Get-CAInvProp $_ '@odata.type' '') -match 'countryNamedLocation' })
    $referencedCountryLocations = @($countryLocations | Where-Object { $referenced -contains $_.id })
    if ($referencedCountryLocations.Count -gt 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-02' -ObjectType 'NamedLocation' `
            -Property 'geoRestriction' `
            -ObservedValue "$($referencedCountryLocations.Count) country-based named location(s) are referenced by CA" `
            -Status 'Ready' -GraphSource $src -RawPath $rawPath | Out-Null
    }
    else {
        New-CAInvRecord -Domain $domain -CheckId 'Condition-02' -ObjectType 'NamedLocation' `
            -Property 'geoRestriction' `
            -ObservedValue "$($countryLocations.Count) country-based named location(s) configured, none referenced by CA" `
            -Status 'Review required' -ManualReview -GraphSource $src -RawPath $rawPath `
            -Recommendation ('Consider linking a country-based named location to a CA policy that restricts access from unexpected countries.') | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($locations.Count) named locations ($($referenced.Count) referenced by CA)."
}
