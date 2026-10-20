function Get-CAInvLogAnalyticsToken {
    <#
    .SYNOPSIS
        Fetches an access token for the Log Analytics data plane, with a single recovery attempt.
    .DESCRIPTION
        The only place where a token for api.loganalytics.io is obtained. Until 0.38.0, this block
        was literally duplicated in the module (Get-CAInvSignInUsageKql and
        Get-CAInvLegacyAuthUsageKql), which meant every improvement had to land twice.

        The recovery in step 2 comes from a real run (2026-08-26, wooninvest): there WAS a valid
        Az context with four visible subscriptions, the ARM calls succeeded, but the data-plane
        token failed with "User interaction is required ... conditional access policy settings
        such as multi-factor authentication". So the Az context was signed in for ARM and not for
        api.loganalytics.io. Az's own error message names the fix: sign in again with -AuthScope
        for that resource. We do that here once and in a targeted way, instead of making the user
        throw away a whole run.

        The result (including a failure) is cached on the run context object. Without that cache,
        the second caller would trigger another interactive prompt for a sign-in that just failed.

        If everything fails: WARN with the reason and return $null. Never a throw — the caller sets
        the affected finding to Not assessed or Review required, with a reason.
    .PARAMETER Domain
        The caller's domain, purely for the log line.
    .OUTPUTS
        [string] the token, or $null when it could not be obtained.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Domain
    )

    $ctx = $script:CAInvContext
    $resource = $script:CAInvLogAnalyticsResource

    if ($ctx -and $ctx.PSObject.Properties['LogAnalyticsToken']) {
        return $ctx.PSObject.Properties['LogAnalyticsToken'].Value
    }

    function Resolve-TokenValue {
        param($TokenObject)

        if ($TokenObject.Token -is [System.Security.SecureString]) {
            return [System.Net.NetworkCredential]::new('', $TokenObject.Token).Password
        }
        return [string]$TokenObject.Token
    }

    $token = $null
    $reason = $null

    try {
        $token = Resolve-TokenValue (Get-AzAccessToken -ResourceUrl $resource -ErrorAction Stop)
    }
    catch {
        $firstError = $_.Exception.Message
        Write-CAInvLog -Level 'DEBUG' -Domain $Domain -Message "Token for $resource not directly available; one-time recovery attempt with -AuthScope. ($firstError)"

        try {
            $tenantId = Get-CAInvProp $ctx 'TenantId'
            if ($tenantId) {
                Connect-AzAccount -Tenant $tenantId -AuthScope $resource -ErrorAction Stop | Out-Null
            }
            else {
                Connect-AzAccount -AuthScope $resource -ErrorAction Stop | Out-Null
            }
            $token = Resolve-TokenValue (Get-AzAccessToken -ResourceUrl $resource -ErrorAction Stop)
            Write-CAInvLog -Level 'INFO' -Domain $Domain -Message "Azure context re-signed in with scope $resource; usage data from Log Analytics is still available."
        }
        catch {
            $reason = "$firstError | herstelpoging: $($_.Exception.Message)"
            $token = $null
        }
    }

    if (-not $token) {
        Write-CAInvLog -Level 'WARN' -Domain $Domain -Message "Could not obtain a token for $resource; usage data from Log Analytics remains unmeasured. $reason"
        $token = $null
    }

    if ($ctx) { Add-CAInvContextData -Context $ctx -Name 'LogAnalyticsToken' -Value $token -AllowOverwrite }
    return $token
}
