#Requires -Version 7.2
Set-StrictMode -Version Latest

$script:ModuleRoot = $PSScriptRoot

$script:CAInvContext = $null

$script:CAInvLogAnalyticsResource = 'https://api.loganalytics.io/'

$folders = @('Private', 'Public')

foreach ($folder in $folders) {
    $base = Join-Path $script:ModuleRoot $folder
    if (-not (Test-Path -LiteralPath $base)) { continue }

    $files = Get-ChildItem -LiteralPath $base -Recurse -Filter '*.ps1' -File |
        Sort-Object FullName

    foreach ($file in $files) {
        try {
            . $file.FullName
        }
        catch {
            throw "CAInventory: could not load '$($file.FullName)': $($_.Exception.Message)"
        }
    }
}

Export-ModuleMember -Function @('Invoke-CAInventory', 'Connect-CAInv')
