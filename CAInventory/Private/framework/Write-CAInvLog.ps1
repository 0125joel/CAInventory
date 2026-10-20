function Write-CAInvLog {
    <#
    .SYNOPSIS
        Writes a structured log line to the console and to /logs/collector.log.
    .DESCRIPTION
        Central logging function for the whole collection. Uses the run context path when
        available (set by Invoke-CAInventory); otherwise console output only, so standalone calls
        during tests don't fail.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Message,

        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string] $Level = 'INFO',

        [string] $Domain
    )

    $timestamp = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $domainTag = if ($Domain) { "[$Domain] " } else { '' }
    $line = "$timestamp [$Level] $domainTag$Message"

    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'DEBUG' { Write-Verbose $line }
        default { Write-Host $line }
    }

    $ctx = $script:CAInvContext
    $logsDir = $null
    if ($ctx) {
        $pathsProp = $ctx.PSObject.Properties['Paths']
        if ($pathsProp -and $pathsProp.Value -is [System.Collections.IDictionary] -and $pathsProp.Value.Contains('Logs')) {
            $logsDir = $pathsProp.Value['Logs']
        }
    }
    if ($logsDir) {
        $logFile = Join-Path $logsDir 'collector.log'
        try {
            Add-Content -LiteralPath $logFile -Value $line -Encoding utf8 -ErrorAction Stop
        }
        catch {

            Write-Host "$timestamp [WARN] Could not write to the log file: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}
