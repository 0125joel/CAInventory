function Connect-CAInv {
    <#
    .SYNOPSIS
        Handles the multi-context authentication for CAInventory and reports per context.
    .DESCRIPTION
        Per the plan, the script runs multi-context: primarily Microsoft Graph (delegated
        preferred), with separate OPTIONAL connections for Azure (Log Analytics/diagnostics) and
        Exchange Online (SMTP AUTH/mailbox CAS).

        Delegated is the default. Where delegated isn't sufficient, that's flagged up front:
          - Unattended/scheduled runs require -AuthMode AppOnly (certificate).
          - Defender and GSA components may require separate registration/portal access (later,
            layer 4/5).

        The function doesn't hard-fail on connecting everything: if a module or context is
        missing, that's reported as a warning and the affected controls will later be
        'Not assessed'.
    .PARAMETER TenantId
        The Entra ID tenant to connect to (GUID or verified domain).
    .PARAMETER AuthMode
        'Delegated' (default, interactive user) or 'AppOnly' (certificate-based, for
        unattended/scheduled runs).
    .PARAMETER SkipAzure
        Skips the Azure context (Az). By default this IS built as soon as Az.Accounts is
        available, because without an Azure context the diagnostic settings, the Log Analytics
        retention (the log window), and the usage axis of the method matrix stay structurally
        unmeasured. Use this switch deliberately: a Graph-only run is faster and doesn't need a
        second sign-in, but measures fewer checks.
    .OUTPUTS
        Hashtable with the connection status per context.
    .EXAMPLE
        Connect-CAInv -TenantId 'contoso.onmicrosoft.com'

        Connects delegated (interactive sign-in) with only the Microsoft Graph context.
    .EXAMPLE
        Connect-CAInv -TenantId $tenantId -AuthMode AppOnly -ClientId $appId -CertificateThumbprint $thumb

        Unattended connection with a certificate. The Azure context is built with that same
        certificate, so without an interactive prompt. Suitable for a scheduled/CI run.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string] $TenantId,

        [ValidateSet('Delegated', 'AppOnly')]
        [string] $AuthMode = 'Delegated',

        [string] $ClientId,
        [string] $CertificateThumbprint,

        [string[]] $Scopes = @(
            'Organization.Read.All',
            'Directory.Read.All',
            'Policy.Read.All',
            'Policy.Read.AuthenticationMethod',
            'User.Read.All',
            'Group.Read.All',
            'RoleManagement.Read.Directory',
            'Application.Read.All',
            'AuditLog.Read.All',
            'Reports.Read.All',
            'Agreement.Read.All',
            'UserAuthenticationMethod.Read.All',
            'Device.Read.All',
            'DeviceManagementManagedDevices.Read.All',
            'DeviceManagementConfiguration.Read.All',
            'IdentityRiskyUser.Read.All',
            'IdentityRiskEvent.Read.All',
            'IdentityRiskyServicePrincipal.Read.All',
            'IdentityProvider.Read.All',

            'AccessReview.Read.All',

            'Domain.Read.All',

            'DeviceManagementApps.Read.All'
        ),

        [switch] $SkipAzure,

        [switch] $IncludeExchange,

        [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
        [string] $Environment = 'Global'
    )

    $connections = @{ Graph = $false; Azure = $false; Exchange = $false }

    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
        throw "Microsoft.Graph is not installed. Install it with: Install-Module Microsoft.Graph -Scope CurrentUser"
    }

    $graphEnv = switch ($Environment) {
        'USGov'    { 'USGov' }
        'USGovDoD' { 'USGovDoD' }
        'China'    { 'China' }
        default    { 'Global' }
    }

    try {
        if ($AuthMode -eq 'AppOnly') {
            if (-not $ClientId -or -not $CertificateThumbprint) {
                throw "AppOnly requires -ClientId and -CertificateThumbprint. Delegated is not sufficient for unattended runs."
            }
            Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -Environment $graphEnv -NoWelcome -ErrorAction Stop
            Write-CAInvLog -Level 'INFO' -Message "Graph connected (AppOnly) to tenant $TenantId."
        }
        else {
            Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -Environment $graphEnv -NoWelcome -ErrorAction Stop
            Write-CAInvLog -Level 'INFO' -Message "Graph connected (Delegated) to tenant $TenantId."
        }
        $connections.Graph = $true

        try {
            Set-MgRequestContext -MaxRetry 10 -RetryDelay 5 -RetriesTimeLimit 180 -ErrorAction Stop
        }
        catch {
            Write-CAInvLog -Level 'DEBUG' -Message "Set-MgRequestContext not available/failed (older SDK version?); Graph retry budget stays at the SDK default. $($_.Exception.Message)"
        }
    }
    catch {
        throw "Graph connection failed: $($_.Exception.Message)"
    }

    if ($SkipAzure) {
        Write-CAInvLog -Level 'INFO' -Message 'Azure context skipped (-SkipAzure); log window, diagnostic settings, and the usage axis of the method matrix will be Not assessed.'
    }
    elseif (Get-Module -ListAvailable -Name 'Az.Accounts') {
        try {

            $existing = $null
            try { $existing = Get-AzContext -ErrorAction Stop } catch { $existing = $null }
            $sameTenant = $existing -and $existing.Tenant -and (
                "$($existing.Tenant.Id)" -eq "$TenantId" -or "$($existing.Tenant.Directory)" -eq "$TenantId")

            if ($sameTenant) {
                Write-CAInvLog -Level 'INFO' -Message "Reused existing Azure context ($($existing.Account.Id))."
            }
            elseif ($AuthMode -eq 'AppOnly') {

                Connect-AzAccount -ServicePrincipal -Tenant $TenantId -ApplicationId $ClientId `
                    -CertificateThumbprint $CertificateThumbprint -AuthScope $script:CAInvLogAnalyticsResource -ErrorAction Stop | Out-Null
                Write-CAInvLog -Level 'INFO' -Message 'Azure context connected (AppOnly, certificate).'
            }
            else {
                Connect-AzAccount -Tenant $TenantId -AuthScope $script:CAInvLogAnalyticsResource -ErrorAction Stop | Out-Null
                Write-CAInvLog -Level 'INFO' -Message 'Azure context connected (Log Analytics/diagnostics available).'
            }
            $connections.Azure = $true
        }
        catch {
            Write-CAInvLog -Level 'WARN' -Message "Azure connection failed; log/diagnostic checks will be Not assessed: $($_.Exception.Message)"
        }
    }
    else {
        Write-CAInvLog -Level 'WARN' -Message 'Az.Accounts not present; Azure-dependent checks will be Not assessed. Install with: Install-Module Az.Accounts -Scope CurrentUser'
    }

    if ($IncludeExchange) {
        if (Get-Module -ListAvailable -Name 'ExchangeOnlineManagement') {
            try {
                Connect-ExchangeOnline -Organization $TenantId -ShowBanner:$false -ErrorAction Stop
                $connections.Exchange = $true
                Write-CAInvLog -Level 'INFO' -Message 'Exchange Online context connected.'
            }
            catch {
                Write-CAInvLog -Level 'WARN' -Message "EXO connection failed; EXO checks will be Not assessed: $($_.Exception.Message)"
            }
        }
        else {
            Write-CAInvLog -Level 'WARN' -Message 'ExchangeOnlineManagement not present; EXO checks will be Not assessed.'
        }
    }

    if ($script:CAInvContext) {
        $script:CAInvContext.Connections = $connections
        $script:CAInvContext.AuthMode = $AuthMode
    }

    return $connections
}
