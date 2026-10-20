function New-CAInvRecord {
    <#
    .SYNOPSIS
        Builds THE normalized inventory record. The only place records come into existence.
    .DESCRIPTION
        Implements the shared output contract and enforces
        the status model:
          - Status is one of: Ready | Gap | Review required | Not assessed.
          - A check that requires human review (ManualReview) may NEVER return 'Ready'; that is
            forced to 'Review required'.
          - 'Not assessed' always requires a reason (NotAssessedReason).
          - Category, Layer AND Severity are looked up from config/checkids.json based on
            CheckId, not passed in by the collector, so those labels can't drift out of sync with
            the catalog. Exception: at Status 'Ready' severity doesn't apply (no
            action needed) and is always 'Info', regardless of defaultSeverity.
        Each record is added to the run's record collection in the context object, so the
        reports are pure renderers over a stream.
    .OUTPUTS
        PSCustomObject with the contract fields.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string] $Domain,

        [Parameter(Mandatory)]
        [string] $CheckId,

        [string] $ObjectType,
        [string] $ObjectId,
        [string] $ObjectName,

        [string] $Property,
        $ObservedValue,

        [Parameter(Mandatory)]
        [ValidateSet('Ready', 'Gap', 'Review required', 'Not assessed')]
        [string] $Status,

        [string] $GraphSource,

        [ValidateSet('v1.0', 'beta', 'n/a')]
        [string] $ApiVersion = 'v1.0',

        [string] $LicenseRequirement,

        [switch] $ManualReview,

        [string] $Recommendation,

        [string] $RawPath,

        [string] $NotAssessedReason
    )

    $effectiveStatus = $Status

    if ($ManualReview -and $effectiveStatus -eq 'Ready') {
        Write-CAInvLog -Level 'DEBUG' -Domain $Domain -Message "CheckId $CheckId : ManualReview set, status 'Ready' reverted to 'Review required'."
        $effectiveStatus = 'Review required'
    }

    if ($effectiveStatus -eq 'Not assessed' -and [string]::IsNullOrWhiteSpace($NotAssessedReason)) {

        $NotAssessedReason = 'Reason not provided by collector.'
        Write-CAInvLog -Level 'WARN' -Domain $Domain -Message "CheckId $CheckId : 'Not assessed' without a reason; generic reason added."
    }

    $ctx = $script:CAInvContext

    $categoryMap = Get-CAInvProp $ctx 'CategoryMap'
    if (-not $categoryMap) {
        $catalog = Get-CAInvProp $ctx 'Config.CheckIds'
        if ($catalog) {
            $categoryMap = @{}
            foreach ($c in @($catalog.checks)) { $categoryMap[[string]$c.checkId] = [string](Get-CAInvProp $c 'category') }
            if ($ctx) { Add-CAInvContextData -Context $ctx -Name 'CategoryMap' -Value $categoryMap -AllowOverwrite }
        }
    }
    $category = $null
    if ($categoryMap -and $categoryMap.ContainsKey($CheckId)) { $category = [string]$categoryMap[$CheckId] }

    $layerMap = Get-CAInvProp $ctx 'LayerMap'
    if (-not $layerMap) {
        $catalogForLayer = Get-CAInvProp $ctx 'Config.CheckIds'
        $layerConfig = Get-CAInvProp $ctx 'Config.Layers'
        if ($catalogForLayer -and $layerConfig) {
            $labelByIndex = @{}
            foreach ($l in @($layerConfig.layers)) { $labelByIndex[[int]$l.index] = [string]$l.label }
            $layerMap = @{}
            foreach ($c in @($catalogForLayer.checks)) {
                $idx = Get-CAInvProp $c 'layer'
                if ($null -ne $idx -and $labelByIndex.ContainsKey([int]$idx)) {
                    $layerMap[[string]$c.checkId] = $labelByIndex[[int]$idx]
                }
            }
            if ($ctx) { Add-CAInvContextData -Context $ctx -Name 'LayerMap' -Value $layerMap -AllowOverwrite }
        }
    }
    $layer = 'Unknown'
    if ($layerMap -and $layerMap.ContainsKey($CheckId)) {
        $layer = [string]$layerMap[$CheckId]
    }
    else {

        Write-CAInvLog -Level 'WARN' -Domain $Domain -Message "CheckId $CheckId : no valid 'layer' in config/checkids.json; layer set to 'Unknown'."
    }

    $validSeverities = @('High', 'Medium', 'Low', 'Info')
    if ($effectiveStatus -eq 'Ready') {
        $Severity = 'Info'
    }
    else {
        $severityMap = Get-CAInvProp $ctx 'SeverityMap'
        if (-not $severityMap) {
            $catalogForSeverity = Get-CAInvProp $ctx 'Config.CheckIds'
            if ($catalogForSeverity) {
                $severityMap = @{}
                foreach ($c in @($catalogForSeverity.checks)) { $severityMap[[string]$c.checkId] = [string](Get-CAInvProp $c 'defaultSeverity') }
                if ($ctx) { Add-CAInvContextData -Context $ctx -Name 'SeverityMap' -Value $severityMap -AllowOverwrite }
            }
        }
        $catalogSeverity = $null
        if ($severityMap -and $severityMap.ContainsKey($CheckId)) { $catalogSeverity = [string]$severityMap[$CheckId] }
        if ($catalogSeverity -and $validSeverities -contains $catalogSeverity) {
            $Severity = $catalogSeverity
        }
        else {

            $Severity = 'Info'
            Write-CAInvLog -Level 'WARN' -Domain $Domain -Message "CheckId $CheckId : no valid 'defaultSeverity' in config/checkids.json; severity set to 'Info'."
        }
    }

    $record = [PSCustomObject]@{
        Layer              = $layer
        Domain             = $Domain
        CheckId            = $CheckId
        Category           = $category
        ObjectType         = $ObjectType
        ObjectId           = $ObjectId
        ObjectName         = $ObjectName
        Property           = $Property
        ObservedValue      = $ObservedValue
        Status             = $effectiveStatus
        Severity           = $Severity
        GraphSource        = $GraphSource
        ApiVersion         = $ApiVersion
        LicenseRequirement = $LicenseRequirement
        ManualReview       = [bool]$ManualReview
        Recommendation     = $Recommendation
        RawPath            = $RawPath
        NotAssessedReason  = $NotAssessedReason
        TenantId           = Get-CAInvProp $ctx 'TenantId'
        CollectedAt        = (Get-CAInvProp $ctx 'CollectedAt' ([DateTimeOffset]::UtcNow.ToString('o')))
    }

    if ($ctx) {
        $recordsProp = $ctx.PSObject.Properties['Records']
        if ($recordsProp -and $null -ne $recordsProp.Value) {
            [void]$recordsProp.Value.Add($record)
        }
    }

    return $record
}
