function Test-CAInvPreflight {
    <#
    .SYNOPSIS
        Preflight: determines what the script can realistically assess.
    .DESCRIPTION
        Runs after Connect-CAInv and before the layers. Establishes:
          - Which Graph scopes the current connection has (delegated or app-only).
          - License context from subscribedSkus (P1/P2/Governance/Intune coverage) via the SKU
            map.
          - Availability of optional contexts (Az, EXO) from the connection state.
        Missing permissions or licenses do NOT abort the run; they cause the affected checks to
        later become 'Not assessed' with a reason. The outcome is stored in the context object so
        collectors can act on it.
    .OUTPUTS
        Hashtable with Scopes, WriteScopes, Licenses, LicensesKnown, Contexts, and Warnings.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $ctx = $script:CAInvContext
    $result = @{
        Scopes    = @()

        WriteScopes = @()
        Licenses  = @{ EntraIdP1 = $false; EntraIdP2 = $false; EntraIdGovernance = $false; IntunePlan1 = $false; DefenderForEndpoint = $false }

        LicensesKnown = $false
        Contexts  = @{ Graph = $false; Azure = $false; Exchange = $false; Reporting = $false }
        Warnings  = @()
    }

    try {
        $mgContext = Get-MgContext -ErrorAction Stop
        if ($mgContext) {
            $result.Contexts.Graph = $true
            $result.Scopes = @($mgContext.Scopes)
            $authType = $mgContext.AuthType
            Write-CAInvLog -Level 'INFO' -Message "Graph connected ($authType). Scopes: $($result.Scopes -join ', ')"

            $result.WriteScopes = @($result.Scopes | Where-Object { $_ -match '(?i)(ReadWrite|\.Write|\.Create|\.Manage)' } | Sort-Object)
            if ($result.WriteScopes.Count -gt 0) {
                $result.Warnings += "Session carries $($result.WriteScopes.Count) write scope(s) that this read-only inventory does not use."
                Write-CAInvLog -Level 'WARN' -Message "Session has $($result.WriteScopes.Count) write scope(s) that CAInventory does not need; the module never writes. Consider a read-only sign-in for a customer assessment. Concerns: $($result.WriteScopes -join ', ')"
            }
        }
    }
    catch {
        $result.Warnings += 'No active Microsoft Graph connection found.'
        Write-CAInvLog -Level 'WARN' -Message 'Preflight: no active Graph connection.'
    }

    if ($ctx -and $ctx.Connections) {
        $result.Contexts.Azure    = [bool]$ctx.Connections.Azure
        $result.Contexts.Exchange = [bool]$ctx.Connections.Exchange
    }
    $result.Contexts.Reporting = [bool](Get-Module -ListAvailable -Name 'ImportExcel')

    if ($result.Contexts.Graph) {
        $skuResp = Invoke-CAInvGraph -Uri 'subscribedSkus' -ApiVersion 'v1.0'
        if (-not $skuResp.Failed -and $skuResp.Value) {
            $planNames = $skuResp.Value |
                ForEach-Object { $_.servicePlans } |
                ForEach-Object { $_.servicePlanName } |
                Where-Object { $_ }

            $map = if ($ctx) { $ctx.Config.SkuMap } else { $null }
            if ($map -and $map.capabilities) {
                foreach ($capName in $result.Licenses.Keys.Clone()) {
                    $cap = $map.capabilities.$capName
                    if ($cap -and $cap.servicePlanNames) {
                        foreach ($needed in $cap.servicePlanNames) {
                            if ($planNames -contains $needed) { $result.Licenses[$capName] = $true; break }
                        }
                    }
                }
            }
            $result.LicensesKnown = $true
            Write-CAInvLog -Level 'INFO' -Message ("License context: P1=$($result.Licenses.EntraIdP1) P2=$($result.Licenses.EntraIdP2) Governance=$($result.Licenses.EntraIdGovernance) Intune=$($result.Licenses.IntunePlan1)")
        }
        else {
            $result.Warnings += 'Could not read subscribedSkus; license context unknown.'
            Write-CAInvLog -Level 'WARN' -Message 'Preflight: license context unknown; license gates are skipped (checks just run).'
        }
    }

    if ($ctx) { $ctx.Preflight = $result }
    return $result
}
