function New-CAInvReportTopbar {
    <#
    .SYNOPSIS
        The brand bar at the top of a report page.
    .DESCRIPTION
        The only place the brand name and tagline appear as text. The function already existed
        for the wide bar of four generators; the two worklist pages (review queue, open work)
        separately built their own compact variant with the same two brand strings copied into
        it. That variant now lives here, so brand changes stay a single edit.

        The two forms differ in markup and CSS classes, not in content: Bar puts the tagline on
        the right of the bar, Compact puts it after the run id on one line. They aren't
        interchangeable, because the pages each carry their own stylesheet for the classes they
        use.

        Default (no -Brand): "CAInventory", no tagline. Resolve-CAInvBrandIdentity usually fills in .name with the tenant
        name ("CAInventory - {tenant}") when there's no explicit brand file; that text then
        already comes in ready-made via -Brand.name, this function doesn't concatenate anything
        itself. An empty tagline drops the tagline markup entirely instead of showing an empty
        span.

        The ›› brand mark only shows with -Brand.custom: CAInventory's own
        identity therefore shows no brand mark; only an explicit brand file gets it.
    .PARAMETER Variant
        Bar (scorecard, rollout plan, reference, MFA methods), Compact (review queue, open work),
        or BrandOnly (the brand block without a bar, for the tab bar of the combined report,
        which brings its own wrapper and tab labels).
    .PARAMETER RunId
        The run id that Compact shows after the tagline. Ignored for Bar.
    .PARAMETER Brand
        Optional hashtable with .name/.tagline, as returned by Get-CAInvBrand (already HTML-safe).
    .OUTPUTS
        [string]
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [ValidateSet('Bar', 'Compact', 'BrandOnly')]
        [string] $Variant = 'Bar',

        [string] $RunId,

        [hashtable] $Brand
    )

    $name = 'CAInventory'
    $tagline = ''
    $showMark = $false
    if ($Brand) {
        if ($Brand.ContainsKey('name') -and $Brand.name) { $name = $Brand.name }
        if ($Brand.ContainsKey('tagline')) { $tagline = $Brand.tagline }
        if ($Brand.ContainsKey('custom')) { $showMark = [bool]$Brand.custom }
    }
    $arrow = if ($showMark) { '<span class="arrow">&#8250;&#8250;</span>' } else { '' }

    $brandMark = '<div class="brand">' + $arrow + '<span class="name">' + $name + '</span></div>'

    switch ($Variant) {
        'BrandOnly' {
            return $brandMark
        }
        'Compact' {
            $run = ConvertTo-CAInvHtmlSafe -Text $RunId
            $ctx = if ($tagline) { $tagline + ' &middot; run ' + $run } else { 'run ' + $run }
            return '<div class="top">' + $arrow + '<span class="nm">' +
                $name + '</span><span class="ctx">' + $ctx + '</span></div>'
        }
        default {
            $tag = if ($tagline) { '<span class="tag">' + $tagline + '</span>' } else { '' }
            return '<div class="topbar">' + $brandMark + $tag + '</div>'
        }
    }
}
