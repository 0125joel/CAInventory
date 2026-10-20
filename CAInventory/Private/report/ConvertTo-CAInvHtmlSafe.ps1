function ConvertTo-CAInvHtmlSafe {
    <#
    .SYNOPSIS
        Escapes text for use in HTML.
    .DESCRIPTION
        The one place where `&`, `<`, `>`, and `"` go to their HTML entity. This exact regex chain
        used to sit literally seven times in `Private/report/` (one per report generator); each
        generator keeps its own short local `E()` wrapper for the many interpolation calls in the
        template text, but that wrapper now delegates here instead of reimplementing the logic.

        No pushing a `$null` check onto the caller: `$null` is a normal, common value for an
        ObjectName/ObservedValue and produces an empty string here.
    .PARAMETER Text
        The text to escape. $null is allowed.
    .OUTPUTS
        [string]
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [string] $Text
    )
    process {
        if ($null -eq $Text) { return '' }
        return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
    }
}
