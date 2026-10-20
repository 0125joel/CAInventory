function Invoke-CAInventory {
    <#
    .SYNOPSIS
        Top-level entry point: runs the layers in a fixed order and generates reporting.
    .DESCRIPTION
        Builds the run context object, runs the
        preflight, runs the selected layer(s) (layer 0 ALWAYS runs), runs the referential
        integrity checks, and renders the scorecard + the findings register.

        All eight layers (0 through 7) are implemented. Layer 0 always runs; -Layer runs one or
        more of the remaining seven (layer 0 still supplies the context). The method matrix
        belongs to layer 2 but runs at the end of the chain because it needs the sign-in logs
        from layer 6.

        When -Layer is omitted on a Delegated call (the default -AuthMode), an interactive
        console menu asks which subject-matter topics to cover (Conditional Access, Break the
        glass, MFA, ...) rather than the seven raw layer names, then resolves each topic to the
        layer(s) needed to produce it (see Read-CAInvInteractiveTopicSelection), followed by
        follow-up questions for whichever parameters weren't already passed explicitly (break-glass
        accounts, the Azure context, the log window, output/brand paths, and — only when
        Authentication is selected — sensitive method details). This never
        triggers with -Layer set, or with -AuthMode AppOnly, so an unattended/scheduled run never
        blocks on input.
    .PARAMETER TenantId
        The Entra ID tenant to inventory (GUID or verified domain).
    .PARAMETER Layer
        One or more of: Foundation, Identity, Authentication, Application, Device,
        NetworkSession, Evidence, Governance, or All (the default once explicitly passed). Layer
        0 (Foundation) always runs regardless of this value, because license/tenant context
        determines which controls are meaningful afterwards. Omit this parameter entirely on a
        Delegated call to get the interactive topic menu described above instead of the All
        default.
    .PARAMETER LookbackDays
        Desired log window in days (default 90, same as -MaxLookbackDays). Automatically
        extended to the detected Log Analytics retention (unless -SkipAzure), capped by
        -MaxLookbackDays. Without a Log Analytics workspace, the Graph signInLogs retention
        (~30 days) remains the actual ceiling; the window reports that honestly (see
        Evidence-05/Evidence-06) instead of suggesting an unsubstantiated 90-day window.
    .PARAMETER MaxLookbackDays
        Ceiling for the effective log window when auto-extending based on LAW retention
        (default 90).
    .PARAMETER SkipAzure
        Skips the Azure context (Az). By default this IS built, because without Azure the
        diagnostic settings, the LAW retention, and the usage axis of the method matrix stay
        unmeasured, and the window is in practice capped by the Graph signInLogs retention
        (~30 days).
    .PARAMETER PrimaryWorkspaceId
        ARM resource ID (properties.workspaceId form, e.g.
        /subscriptions/.../resourceGroups/.../providers/Microsoft.OperationalInsights/workspaces/...)
        of the Log Analytics workspace that the method matrix usage axis and the legacy auth
        drilldown should query. If this tenant's Entra ID diagnostic settings point to exactly
        one workspace, that one is used automatically and this isn't needed. If they point to
        more than one, the module deliberately doesn't guess: Evidence-04 becomes
        'Review required' with all the workspaces found (name, retention, categories), and you
        re-run with this parameter to pin one.
    .PARAMETER EmergencyAccountUpn
        UPNs of the actual break-glass accounts. Only these get the full break-glass verdict;
        without this list the script shows candidates for confirmation at most.
    .PARAMETER EmergencyAccountId
        Object IDs (GUIDs) of the break-glass accounts — alternative to -EmergencyAccountUpn.
    .PARAMETER BrandFile
        Path to a JSON brand file (name, tagline, footer line, colors) for the report UI.
        Optional: without this parameter the module runs with CAInventory's own identity
        ("CAInventory - {tenant}", see Resolve-CAInvBrandIdentity) and a fixed color palette.
        Providing it disables that dynamic derivation; the file then always wins. See
        Get-CAInvBrand for the schema and the error-handling behavior for an unreadable file.
    .PARAMETER OutputPath
        Directory the timestamped run output is written to (default ./output under the current
        location).
    .PARAMETER IncludeSensitiveMethodDetails
        Includes sensitive authentication method details (phone numbers etc., masked) — off by
        default.
    .PARAMETER AuthMode
        'Delegated' (default, interactive user) or 'AppOnly' (certificate-based, for
        unattended/scheduled runs).
    .PARAMETER ClientId
        App registration (client) ID for -AuthMode AppOnly. Required with AppOnly, passed to
        Connect-CAInv. Ignored with Delegated.
    .PARAMETER CertificateThumbprint
        Thumbprint of the certificate used for -AuthMode AppOnly. Required with AppOnly, passed to
        Connect-CAInv. Ignored with Delegated.
    .PARAMETER SkipConnect
        Skips reconnecting if a Graph session already exists (e.g. after a separate
        Connect-CAInv call).
    .PARAMETER IncludeExchange
        Also connects Exchange Online (ExchangeOnlineManagement) for the SMTP AUTH and mailbox
        CAS checks. Passed to Connect-CAInv. Ignored with -SkipConnect.
    .PARAMETER Environment
        Microsoft cloud environment: 'Global' (default), 'USGov', 'USGovDoD', or 'China'.
    .EXAMPLE
        Connect-CAInv -TenantId 'contoso.onmicrosoft.com'
        Invoke-CAInventory -TenantId 'contoso.onmicrosoft.com' -Layer All -OutputPath ./output

        Full inventory (all 8 layers) against an already-connected tenant.
    .EXAMPLE
        Invoke-CAInventory -TenantId $tenantId -Layer Identity,Governance -EmergencyAccountUpn 'breakglass1@contoso.com','breakglass2@contoso.com'

        Runs layers 1 and 7 (layer 0 always runs alongside) and gives the two given UPNs the
        full break-glass verdict instead of just candidate flagging.
    .EXAMPLE
        Connect-CAInv -TenantId $tenantId
        Invoke-CAInventory -TenantId $tenantId

        -Layer is omitted on a Delegated call: this drops into the interactive topic menu and
        follow-up questions instead of defaulting to All.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $TenantId,

        [ValidateSet('All', 'Foundation', 'Identity', 'Authentication', 'Application',
            'Device', 'NetworkSession', 'Evidence', 'Governance')]
        [string[]] $Layer = @('All'),

        [int] $LookbackDays = 90,

        [int] $MaxLookbackDays = 90,

        [switch] $SkipAzure,

        [string] $PrimaryWorkspaceId,

        [string[]] $EmergencyAccountUpn,

        [string[]] $EmergencyAccountId,

        [string] $BrandFile,

        [string] $OutputPath = (Join-Path (Get-Location) 'output'),

        [switch] $IncludeSensitiveMethodDetails,

        [ValidateSet('Delegated', 'AppOnly')]
        [string] $AuthMode = 'Delegated',

        [string] $ClientId,

        [string] $CertificateThumbprint,

        [switch] $SkipConnect,

        [switch] $IncludeExchange,

        [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
        [string] $Environment = 'Global'
    )

    if ((-not $PSBoundParameters.ContainsKey('Layer')) -and $AuthMode -eq 'Delegated') {
        $Layer = Read-CAInvInteractiveTopicSelection
        $answers = Read-CAInvInteractiveFollowUpAnswer -SelectedLayers $Layer -BoundParameters $PSBoundParameters `
            -EmergencyAccountUpn $EmergencyAccountUpn `
            -EmergencyAccountId $EmergencyAccountId -SkipAzure ([bool]$SkipAzure) -LookbackDays $LookbackDays `
            -IncludeSensitiveMethodDetails ([bool]$IncludeSensitiveMethodDetails) -OutputPath $OutputPath -BrandFile $BrandFile

        $EmergencyAccountUpn           = $answers.EmergencyAccountUpn
        $EmergencyAccountId            = $answers.EmergencyAccountId
        $SkipAzure                     = [switch] $answers.SkipAzure
        $LookbackDays                  = $answers.LookbackDays
        $IncludeSensitiveMethodDetails = [switch] $answers.IncludeSensitiveMethodDetails
        $OutputPath                    = $answers.OutputPath
        $BrandFile                     = $answers.BrandFile

        $layerSummary = if ($Layer.Count -gt 0) { $Layer -join ', ' } else { '(Foundation only)' }
        Write-CAInvLog -Level 'INFO' -Message "Interactive run: layers = $layerSummary; Azure $(-not [bool]$SkipAzure); lookback $LookbackDays d; sensitive method details $([bool]$IncludeSensitiveMethodDetails)"
    }

    $runId = [Guid]::NewGuid().ToString()
    $collectedAt = [DateTimeOffset]::UtcNow.ToString('o')
    $runStamp = ([DateTimeOffset]::UtcNow).ToString('yyyyMMdd-HHmmss')
    $runRoot = Join-Path $OutputPath $runStamp

    $paths = @{
        Root       = $runRoot
        Raw        = Join-Path $runRoot 'raw'
        Normalized = Join-Path $runRoot 'normalized'
        Reports    = Join-Path $runRoot 'reports'
        Logs       = Join-Path $runRoot 'logs'
    }
    foreach ($p in $paths.Values) {
        if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }

    $config = Get-CAInvConfig
    $brand = Get-CAInvBrand -BrandFile $BrandFile

    $script:CAInvContext = [PSCustomObject]@{
        RunId                 = $runId
        TenantId              = $TenantId
        CollectedAt           = $collectedAt
        LookbackDays          = $LookbackDays
        MaxLookbackDays       = $MaxLookbackDays
        PrimaryWorkspaceId    = $PrimaryWorkspaceId
        EmergencyAccountUpn   = $EmergencyAccountUpn
        EmergencyAccountId    = $EmergencyAccountId
        EffectiveLookbackDays = $LookbackDays
        IncludeSensitive      = [bool]$IncludeSensitiveMethodDetails
        Paths                 = $paths
        Records               = [System.Collections.Generic.List[object]]::new()
        GraphCache            = @{}
        GraphBaseUri          = (Get-CAInvGraphBaseUri -Environment $Environment)
        Config                = $config
        Brand                 = $brand
        BrandFile             = $BrandFile
        Connections           = @{ Graph = $false; Azure = $false; Exchange = $false }
        AuthMode              = $AuthMode
        Preflight             = $null
        BetaEndpointsUsed     = [System.Collections.Generic.List[string]]::new()
    }

    Write-CAInvLog -Level 'INFO' -Message "=== CAInventory run $runId started (tenant $TenantId, layer $($Layer -join ', ')) ==="

    if (-not $SkipConnect) {
        Connect-CAInv -TenantId $TenantId -AuthMode $AuthMode -ClientId $ClientId `
            -CertificateThumbprint $CertificateThumbprint -Environment $Environment `
            -SkipAzure:$SkipAzure -IncludeExchange:$IncludeExchange | Out-Null
    }
    else {
        try { if (Get-MgContext) { $script:CAInvContext.Connections.Graph = $true } }
        catch { Write-CAInvLog -Level 'WARN' -Message 'SkipConnect set but no active Graph context found.' }

        if (-not $SkipAzure) {
            try { if (Get-AzContext -ErrorAction Stop) { $script:CAInvContext.Connections.Azure = $true } }
            catch { Write-CAInvLog -Level 'WARN' -Message 'No active Az context with -SkipConnect; log window detection and the usage axis of the method matrix will be Not assessed.' }
        }
    }

    Resolve-CAInvBrandIdentity

    $null = Test-CAInvPreflight

    Resolve-CAInvLogWindow

    $runAll = ($Layer -contains 'All')

    $layerScope = [System.Collections.Generic.List[string]]::new()
    [void]$layerScope.Add('0')
    foreach ($pair in @(
            @{ N = '1'; L = 'Identity' }, @{ N = '2'; L = 'Authentication' }, @{ N = '3'; L = 'Application' },
            @{ N = '4'; L = 'Device' }, @{ N = '5'; L = 'NetworkSession' }, @{ N = '6'; L = 'Evidence' },
            @{ N = '7'; L = 'Governance' })) {
        if ($runAll -or ($Layer -contains $pair.L)) { [void]$layerScope.Add($pair.N) }
    }
    Add-CAInvContextData -Context $script:CAInvContext -Name 'LayersRun' -Value $layerScope

    Write-CAInvLog -Level 'INFO' -Message '--- Layer 0: Foundation and CA basics ---'
    Invoke-CAInvFoundationLayer

    if ($runAll -or ($Layer -contains 'Identity')) {
        Write-CAInvLog -Level 'INFO' -Message '--- Layer 1: Identity ---'
        Invoke-CAInvIdentityLayer
    }

    if ($runAll -or ($Layer -contains 'Authentication')) {
        Write-CAInvLog -Level 'INFO' -Message '--- Layer 2: Authentication ---'
        Invoke-CAInvAuthenticationLayer
    }

    if ($runAll -or ($Layer -contains 'Application')) {
        Write-CAInvLog -Level 'INFO' -Message '--- Layer 3: Applications ---'
        Invoke-CAInvApplicationLayer
    }

    if ($runAll -or ($Layer -contains 'Device')) {
        Write-CAInvLog -Level 'INFO' -Message '--- Layer 4: Devices ---'
        Invoke-CAInvDeviceLayer
    }

    if ($runAll -or ($Layer -contains 'NetworkSession')) {
        Write-CAInvLog -Level 'INFO' -Message '--- Layer 5: Network and session ---'
        Invoke-CAInvNetworkSessionLayer
    }

    if ($runAll -or ($Layer -contains 'Evidence')) {
        Write-CAInvLog -Level 'INFO' -Message '--- Layer 6: Usage and evidence ---'
        Invoke-CAInvEvidenceLayer
    }

    Write-CAInvLog -Level 'INFO' -Message '--- Referential integrity checks ---'
    Test-CAInvReferentialIntegrity

    if ($runAll -or ($Layer -contains 'Governance')) {
        Write-CAInvLog -Level 'INFO' -Message '--- Layer 7: Governance ---'
        Invoke-CAInvGovernanceLayer
    }

    if ($runAll -or ($Layer -contains 'Authentication') -or ($Layer -contains 'Evidence')) {
        Write-CAInvLog -Level 'INFO' -Message '--- Method matrix (layer 2, after layer 6) ---'

        Get-CAInvSignInUsageKql
        Get-CAInvMethodUsageMatrix
    }

    Write-CAInvLog -Level 'INFO' -Message '--- Catalog integrity ---'
    Test-CAInvCheckIdCatalog

    Write-CAInvLog -Level 'INFO' -Message '--- Generating reports ---'
    $records = $script:CAInvContext.Records

    $csvPath = Join-Path $paths.Normalized 'findings.csv'
    $records | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8

    $jsonPath = Join-Path $paths.Normalized 'findings.json'
    ($records | ConvertTo-Json -Depth 6 -AsArray) | Set-Content -LiteralPath $jsonPath -Encoding utf8

    $scorecardHtml   = New-CAInvScorecard
    $reviewQueueHtml = New-CAInvReviewQueue
    $mfaMethodsHtml  = New-CAInvMfaMethodReport
    $registerPath    = New-CAInvFindingsRegister
    $apiDriftPath    = New-CAInvApiDriftReport
    $rolloutPlanHtml = New-CAInvRolloutPlan
    $referenceHtml   = New-CAInvReference

    $openWorkHtml    = New-CAInvOpenWork

    $workbookFactsPath = New-CAInvWorkbookExport

    $printReportPath = New-CAInvPrintReport

    $reportPath = New-CAInvCombinedReport -ReportsPath $paths.Reports `
        -ScorecardHtml $scorecardHtml -ReviewQueueHtml $reviewQueueHtml -MfaMethodsHtml $mfaMethodsHtml `
        -RolloutPlanHtml $rolloutPlanHtml -ReferenceHtml $referenceHtml -OpenWorkHtml $openWorkHtml `
        -Brand $script:CAInvContext.Brand

    Write-CAInvLog -Level 'INFO' -Message "=== Run completed. $($records.Count) records. Output: $runRoot ==="

    return [PSCustomObject]@{
        RunId          = $runId
        TenantId       = $TenantId
        RecordCount    = $records.Count
        OutputRoot     = $runRoot
        NormalizedCsv  = $csvPath
        NormalizedJson = $jsonPath
        FindingsRegister = $registerPath
        ApiDriftReport = $apiDriftPath
        WorkbookFacts  = $workbookFactsPath
        Report         = $reportPath
        PrintReport    = $printReportPath
        Records        = $records
    }
}

function Get-CAInvGraphBaseUri {
    param([string] $Environment = 'Global')
    switch ($Environment) {
        'USGov'    { 'https://graph.microsoft.us' }
        'USGovDoD' { 'https://dod-graph.microsoft.us' }
        'China'    { 'https://microsoftgraph.chinacloudapi.cn' }
        default    { 'https://graph.microsoft.com' }
    }
}
