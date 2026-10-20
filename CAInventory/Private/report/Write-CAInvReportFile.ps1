function Write-CAInvReportFile {
    <#
    .SYNOPSIS
        Writes report content to disk, UTF-8.
    .DESCRIPTION
        `Set-Content -LiteralPath $Path -Value $Content -Encoding utf8` used to appear literally
        nine times scattered across `Private/report/` (HTML and JSON reports mixed together). One
        place, so a future encoding choice doesn't have to be made separately nine times.
    .PARAMETER Path
        Destination path. The caller resolves and validates the directory beforehand; this
        function doesn't create directories or change a path.
    .PARAMETER Content
        The full content (HTML string or `ConvertTo-Json` result). An empty string is valid;
        only `$null` is a programming error on the caller's part.
    .OUTPUTS
        None. Same as the underlying Set-Content.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Content
    )

    Set-Content -LiteralPath $Path -Value $Content -Encoding utf8
}
