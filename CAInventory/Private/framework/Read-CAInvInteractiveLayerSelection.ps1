function Read-CAInvInteractiveLayerSelection {
    <#
    .SYNOPSIS
        Interactive console menu for picking which optional layers Invoke-CAInventory runs, used
        when -Layer is omitted on a Delegated call.
    .DESCRIPTION
        Layer 0 (Foundation) always runs regardless of this selection and is shown as such, not as
        a pickable option. Pressing Enter or typing 'A' selects all seven optional layers,
        matching the non-interactive default (-Layer All). Typing '0' or 'none' selects zero
        optional layers (equivalent to today's -Layer Foundation) — a deliberate distinct choice
        from the default, not an error state, since a Foundation-only run is a valid existing use
        case. A multi-number answer always comes back in menu order, deduplicated, regardless of
        the order typed.
    .OUTPUTS
        String[]: the selected layer names, from the same set as -Layer's ValidateSet (excluding
        'All' and 'Foundation'). An empty array is a valid result.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $optionNames = @('Identity', 'Authentication', 'Application', 'Device', 'NetworkSession', 'Evidence', 'Governance')

    Write-Host ''
    Write-Host 'Which layers should this run include? (Foundation / layer 0 always runs)'
    for ($i = 0; $i -lt $optionNames.Count; $i++) { Write-Host ('  {0}) {1}' -f ($i + 1), $optionNames[$i]) }
    Write-Host ''

    while ($true) {
        $raw = Read-Host 'Layer numbers, comma-separated, A for all, or 0 for none [A]'
        $trimmed = $raw.Trim()

        if ($trimmed -eq '' -or $trimmed -ieq 'a') { return [string[]] @($optionNames) }
        if ($trimmed -eq '0' -or $trimmed -ieq 'none') { return [string[]] @() }

        $tokens = @($trimmed -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        $invalid = @($tokens | Where-Object { $_ -notmatch '^[1-7]$' })
        if ($tokens.Count -eq 0 -or $invalid.Count -gt 0) {
            Write-Host "Not a valid entry: '$raw'. Enter numbers 1-7 separated by commas, A, or 0." -ForegroundColor Yellow
            continue
        }

        $indices = @($tokens | ForEach-Object { [int]$_ } | Sort-Object -Unique)
        return [string[]] @($indices | ForEach-Object { $optionNames[$_ - 1] })
    }
}
