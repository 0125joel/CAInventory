function New-CAInvReportFooter {
    <#
    .SYNOPSIS
        The footer bar at the bottom of a report page.
    .DESCRIPTION
        The only place the closing service line appears. That line used to be literally copied
        across four generators, each with its own composition of the links after it; the scorecard
        had two of them, the MFA method report had none.

        The rollout plan also used a divergent markup without the l and r classes, with an
        inline-styled arrow instead of the arrow class. That page now follows the same structure as
        the other three and got the three missing CSS rules for it.

        Default (no -Brand): CAInventory's own, brandless line. The ›› brand
        mark only shows with -Brand.custom, same reason as New-CAInvReportTopbar.
    .PARAMETER RunId
        The run id, shown on the right of the bar. Gets escaped.
    .PARAMETER IncludePrintLink
        Adds the link to the printable report. report-print.html stays a real file next to
        report.html (never mounted as srcdoc, see New-CAInvCombinedReport), so this link keeps
        working regardless of whether the calling page itself is mounted as srcdoc: srcdoc
        documents inherit their parent document's base URL for relative links, and target="_blank"
        opens a new tab instead of leaving the current shell.
    .PARAMETER Brand
        Optional hashtable with .footerLine, as returned by Get-CAInvBrand (already HTML-safe).
    .OUTPUTS
        [string]
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string] $RunId,

        [switch] $IncludePrintLink,

        [hashtable] $Brand
    )

    $line = 'CAInventory — read-only inventory, zero changes to the tenant.'
    $showMark = $false
    if ($Brand) {
        if ($Brand.ContainsKey('footerLine') -and $Brand.footerLine) { $line = $Brand.footerLine }
        if ($Brand.ContainsKey('custom')) { $showMark = [bool]$Brand.custom }
    }
    $arrow = if ($showMark) { '<span class="arrow">&#8250;&#8250;</span>' } else { '' }

    $parts = @($line)
    if ($IncludePrintLink) {
        $parts += '<a href="report-print.html" target="_blank" style="color:#fff">' + ('Report as PDF') + '</a>'
    }

    $left = $parts -join ' &middot; '
    $run = ConvertTo-CAInvHtmlSafe -Text $RunId

    return '<div class="footbar"><div class="l">' + $arrow + '<span>' +
        $left + '</span></div><span class="r">CAInventory &middot; run ' + $run + '</span></div>'
}
