function New-CAInvReportPalette {
    <#
    .SYNOPSIS
        The shared :root color token block for all report pages.
    .DESCRIPTION
        The only place the brand colors appear as hex values. Before this function, each of the
        eight report generators carried its own :root block with the same four brand colors
        copied into it, which meant that changing one color cost eight edits.

        The status colors carry meaning, not taste: coral is Gap/High, yellow is
        'Review required'/Medium, grey is Low/Info, ok is Ready. Anyone replacing them must keep
        those four roles intact, not just pick a nice palette.

        The default values are CAInventory's own identity, derived from PIM
        Monitor's severity color system (red/amber/green/grey). -Brand (a hashtable as returned by
        Get-CAInvBrand) overrides ink/yellow/coral/review/grey/ok per key; tabMuted is a fixed
        layout token, not a brand color, and therefore always stays the same regardless of
        -Brand.

        Surface determines the layout tokens (background, card, line, text). Those genuinely
        differ per page family and aren't a brand matter: the card pages sit on a tinted
        background, the worklist pages on white, and the print report has its own line color.
        The three variants produce exactly the same tokens and values as the separate blocks
        they replace; Card additionally supplies --review to the two pages that didn't have it
        before, which is unused there and therefore has no effect.
        The colors also appear outside CSS: the pages color their charts and status dots from
        JavaScript, and three generators compute with the same values in PowerShell. Hence three
        output forms from the same source, instead of rewriting the same hex in three different
        ways.
    .PARAMETER Surface
        Card (scorecard, rollout plan, reference, MFA methods), Panel (review queue, open work),
        Print (print report), or Minimal (the tab shell of the combined report). Only applies to
        -As Css.
    .PARAMETER As
        Css (default) returns the ':root{...}' block. Script returns the JavaScript constants
        the pages use for coloring. Map returns a hashtable for PowerShell code that needs to
        pick a color itself.
    .PARAMETER Brand
        Optional hashtable with a nested .colors (ink/accent/gap/review/lowInfo/ready), as
        returned by Get-CAInvBrand. Missing keys fall back to the default.
    .OUTPUTS
        [string] for Css and Script, [hashtable] for Map.
    #>
    [CmdletBinding()]
    [OutputType([string], [hashtable])]
    param(
        [ValidateSet('Card', 'Panel', 'Print', 'Minimal')]
        [string] $Surface = 'Card',

        [ValidateSet('Css', 'Script', 'Map')]
        [string] $As = 'Css',

        [hashtable] $Brand
    )

    $ink = '#171717'
    $yellow = '#D97706'
    $coral = '#EF4444'
    $grey = '#737373'
    $ok = '#22C55E'
    $review = '#D97706'
    $tabMuted = '#D4D4D4'

    if ($Brand -and $Brand.colors -is [System.Collections.IDictionary]) {
        $bc = $Brand.colors
        if ($bc.ContainsKey('ink'))     { $ink = $bc.ink }
        if ($bc.ContainsKey('accent'))  { $yellow = $bc.accent }
        if ($bc.ContainsKey('gap'))     { $coral = $bc.gap }
        if ($bc.ContainsKey('review'))  { $review = $bc.review }
        if ($bc.ContainsKey('lowInfo')) { $grey = $bc.lowInfo }
        if ($bc.ContainsKey('ready'))   { $ok = $bc.ready }
    }

    if ($As -eq 'Map') {
        return @{
            Ink      = $ink
            Yellow   = $yellow
            Coral    = $coral
            Grey     = $grey
            Ok       = $ok
            Review   = $review
            TabMuted = $tabMuted
        }
    }

    if ($As -eq 'Script') {
        return "var INK='$ink',CORAL='$coral',YELLOW='$yellow',GREY='$grey',OK='$ok';"
    }

    $brandTokens = "--ink:$ink;--coral:$coral;--yellow:$yellow;--grey:$grey;--tabmuted:$tabMuted"

    $tokens = switch ($Surface) {
        'Card' {
            "$brandTokens;--body:#3A485A;--bg:#EFEDF2;--card:#FFFFFF;--line:#D8D5DE;--muted:#8A8595;--review:$review;--tint:#FBFAFC"
        }
        'Panel' {
            "$brandTokens;--ok:$ok;--bg:#FFFFFF;--panel:#FAFAFB;--line:#E6E3EC;--text:#1B1230;--muted:#6B6480"
        }
        'Print' {
            "$brandTokens;--ok:$ok;--line:#D8D5DE;--text:#1B1230;--muted:#6B6480;--panel:#FAFAFB"
        }
        'Minimal' {
            "--ink:$ink;--yellow:$yellow;--tabmuted:$tabMuted"
        }
    }

    return ":root{$tokens}"
}
