function Get-CAInvHardPrecondition {
    <#
    .SYNOPSIS
        The five hard preconditions as a reusable, pure computation.
    .DESCRIPTION
        Extracted from New-CAInvScorecard.ps1 so
        Get-CAInvGoLiveStatus can reuse the same criteria for the ready-for-go-live gate, instead
        of defining the four thresholds a second time. Purely a
        computation over already-collected records — no new Graph call.
    .PARAMETER Records
        The full record set of the run ($ctx.Records).
    .OUTPUTS
        Array of 5 hashtables: @{ Label; Value; Ok }.
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array] $Records
    )

    $emgRec = @($Records | Where-Object { $_.CheckId -eq 'Emergency-01' -and $_.Property -like 'accountCount*' }) | Select-Object -First 1
    $p1Rec = @($Records | Where-Object { $_.CheckId -eq 'Foundation-01' -and $_.Property -eq 'EntraIdP1' }) | Select-Object -First 1
    $gaRec = @($Records | Where-Object { $_.CheckId -eq 'Identity-09' -and $_.Property -eq 'permanentGlobalAdminCount' }) | Select-Object -First 1

    $sdRec = @($Records | Where-Object { $_.CheckId -eq 'Foundation-03' -and $_.Property -eq 'isEnabled' }) | Select-Object -First 1

    $emgCount = if ($emgRec) { $emgRec.ObservedValue } else { $null }
    $gaCount = if ($gaRec) { $gaRec.ObservedValue } else { $null }

    function Test-CAInvIntInRange {
        param($Value, $Min, $Max)

        $n = 0
        $text = ([string]$Value).Trim()
        if ($text -match '^\s*(-?\d+)') { $text = $Matches[1] }
        if (-not [int]::TryParse($text, [ref]$n)) { return $false }
        return ($n -ge $Min -and $n -le $Max)
    }

    function Test-CAInvBooleanIsTrue {
        param($Value)
        $b = $false
        return ([bool]::TryParse([string]$Value, [ref]$b) -and $b)
    }

    $log1 = @($Records | Where-Object { $_.CheckId -eq 'Evidence-04' }) | Select-Object -First 1
    $log2 = @($Records | Where-Object { $_.CheckId -eq 'Evidence-05' }) | Select-Object -First 1
    $logValue = if ($log2) { [string]$log2.ObservedValue } elseif ($log1) { "$($log1.Status): $([string]$log1.ObservedValue)$([string]$log1.NotAssessedReason)" } else { 'not detected' }
    $logOk = ($log1 -and $log1.Status -eq 'Ready')

    return @(
        @{ Label = 'Break-glass accounts found'; Value = $(if ($null -ne $emgCount) { "$emgCount" } else { 'n/a (layer 1 not run)' }); Ok = (Test-CAInvIntInRange -Value $emgCount -Min 2 -Max ([int]::MaxValue)) }
        @{ Label = 'Entra ID P1 (CA licensable)'; Value = $(if ($p1Rec) { "$($p1Rec.ObservedValue)" } else { 'unknown' }); Ok = ($p1Rec -and $p1Rec.Status -eq 'Ready') }

        @{ Label = 'Permanent Global Admins'; Value = $(if ($null -ne $gaCount) { "$gaCount" } else { 'n/a (layer 1 not run)' }); Ok = (Test-CAInvIntInRange -Value $gaCount -Min 1 -Max 4) }
        @{ Label = 'Diagnostic settings / log window'; Value = $logValue; Ok = $logOk }

        @{
            Label = 'Security defaults off'
            Value = $(if ($sdRec) { "$($sdRec.ObservedValue)" } else { 'unknown' })
            Ok    = ($null -ne $sdRec -and -not (Test-CAInvBooleanIsTrue -Value $sdRec.ObservedValue))
        }
    )
}
