function Read-CAInvInteractiveFollowUpAnswer {
    <#
    .SYNOPSIS
        Interactive follow-up questions for the Invoke-CAInventory parameters that would
        otherwise silently keep their default, run right after
        Read-CAInvInteractiveLayerSelection.
    .DESCRIPTION
        Only prompts for a parameter the caller did not already pass explicitly (per
        -BoundParameters, Invoke-CAInventory's own $PSBoundParameters); every other parameter is
        passed through unchanged in the returned object, so an interactive run can still mix in
        explicit flags. IncludeSensitiveMethodDetails is only asked when Authentication is among
        -SelectedLayers, since it is the only follow-up parameter consumed by a single optional
        layer (layer 2) rather than by layer 0 or the framework's log-window resolution, both of
        which always run.

        -PrimaryWorkspaceId is deliberately NOT asked here: whether more than one Log Analytics
        workspace exists is only known after the preflight queries Azure, so asking up front would
        mean guessing. That stays a post-run 'Review required' pointing back at
        -PrimaryWorkspaceId, unchanged by this function.

        -BrandFile is deliberately NOT asked here either: it's a
        white-labeling detail for a polished client deliverable, not something an ad-hoc
        interactive run needs to be nudged about — pass -BrandFile explicitly when it matters.
        -OutputPath IS still asked; unlike branding, "where does this run's output land" is
        relevant to every run.
    .PARAMETER SelectedLayers
        Output of Read-CAInvInteractiveLayerSelection; gates the Authentication-only question.
    .PARAMETER BoundParameters
        The caller's own $PSBoundParameters, used to skip a question already answered on the
        command line.
    .PARAMETER EmergencyAccountUpn
        Invoke-CAInventory's current value for -EmergencyAccountUpn.
    .PARAMETER EmergencyAccountId
        Invoke-CAInventory's current value for -EmergencyAccountId.
    .PARAMETER SkipAzure
        Invoke-CAInventory's current value for -SkipAzure, as a plain bool.
    .PARAMETER LookbackDays
        Invoke-CAInventory's current value for -LookbackDays.
    .PARAMETER IncludeSensitiveMethodDetails
        Invoke-CAInventory's current value for -IncludeSensitiveMethodDetails, as a plain bool.
    .PARAMETER OutputPath
        Invoke-CAInventory's current value for -OutputPath.
    .PARAMETER BrandFile
        Invoke-CAInventory's current value for -BrandFile.
    .OUTPUTS
        PSCustomObject with one property per follow-up parameter (EmergencyAccountUpn,
        EmergencyAccountId, SkipAzure, LookbackDays, IncludeSensitiveMethodDetails, OutputPath,
        BrandFile): the caller's own value where already bound, the interactive answer otherwise.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string[]] $SelectedLayers,
        [Parameter(Mandatory)] [hashtable] $BoundParameters,

        [string[]] $EmergencyAccountUpn,
        [string[]] $EmergencyAccountId,
        [Parameter(Mandatory)] [bool] $SkipAzure,
        [Parameter(Mandatory)] [int] $LookbackDays,
        [Parameter(Mandatory)] [bool] $IncludeSensitiveMethodDetails,
        [Parameter(Mandatory)] [string] $OutputPath,
        [string] $BrandFile
    )

    if (-not $BoundParameters.ContainsKey('EmergencyAccountUpn')) {
        $answer = Read-Host 'Break-glass account UPNs, comma-separated (Enter to skip)'
        if (-not [string]::IsNullOrWhiteSpace($answer)) {
            $EmergencyAccountUpn = @($answer -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        }
    }

    if (-not $BoundParameters.ContainsKey('EmergencyAccountId')) {
        $answer = Read-Host 'Break-glass account object IDs, comma-separated (Enter to skip)'
        if (-not [string]::IsNullOrWhiteSpace($answer)) {
            $EmergencyAccountId = @($answer -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        }
    }

    if (-not $BoundParameters.ContainsKey('SkipAzure')) {
        $answer = Read-Host 'Build the Azure/Az context too? Needed for LAW retention, diagnostic settings and the method matrix usage axis. [Y/n]'
        $SkipAzure = ($answer.Trim() -imatch '^n')
    }

    if (-not $BoundParameters.ContainsKey('LookbackDays')) {
        while ($true) {
            $answer = (Read-Host 'Desired log window in days [90]').Trim()
            if ($answer -eq '') { $LookbackDays = 90; break }
            $parsed = 0
            if ([int]::TryParse($answer, [ref] $parsed) -and $parsed -gt 0) { $LookbackDays = $parsed; break }
            Write-Host 'Enter a positive whole number of days, or press Enter for the default.' -ForegroundColor Yellow
        }
    }

    if (($SelectedLayers -contains 'Authentication') -and -not $BoundParameters.ContainsKey('IncludeSensitiveMethodDetails')) {
        $answer = Read-Host 'Also look up which MFA method each individual user has registered (one extra Graph call per user; phone numbers masked to the last 4 digits)? Off by default: overall MFA readiness already comes from a lighter, tenant-wide source; this only adds per-user detail. [y/N]'
        $IncludeSensitiveMethodDetails = ($answer.Trim() -imatch '^y')
    }

    if (-not $BoundParameters.ContainsKey('OutputPath')) {
        $answer = Read-Host "Output directory [$OutputPath]"
        if (-not [string]::IsNullOrWhiteSpace($answer)) { $OutputPath = $answer.Trim() }
    }

    return [PSCustomObject]@{
        EmergencyAccountUpn           = $EmergencyAccountUpn
        EmergencyAccountId            = $EmergencyAccountId
        SkipAzure                     = $SkipAzure
        LookbackDays                  = $LookbackDays
        IncludeSensitiveMethodDetails = $IncludeSensitiveMethodDetails
        OutputPath                    = $OutputPath
        BrandFile                     = $BrandFile
    }
}
