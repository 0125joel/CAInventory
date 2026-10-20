function Set-CAInvAzureUnavailable {
    <#
    .SYNOPSIS
        Records that the Azure/Log Analytics route is unavailable for this run, with the reason.
    .DESCRIPTION
        The Log Analytics workspace is this module's extra log source: it supplies what Graph
        can't. Two checks need it for a verdict:

          - 6.16  legacy auth drilldown
          - 6.23  method matrix, usage axis (otherwise stays Not assessed)

        In the live run of 21-08-2026, one ARM token failed (an MFA challenge against
        management.azure.com) and those checks silently degraded. collector.log had separate
        DEBUG lines about it of the form "No primary Log Analytics workspace found" — all true,
        none of them named the cause.

        This function is the only place that fact lands. Consumers read it via
        Get-CAInvAzureUnavailableReason, letting them point to the REAL cause in their
        NotAssessedReason instead of the symptom.
    .PARAMETER Reason
        The underlying reason, in plain language.
    .PARAMETER Quiet
        Log at DEBUG instead of WARN. For the normal, expected case: running without -SkipAzure
        is a deliberate user choice, not worth a warning. A FAILED Azure connection when one was
        actually requested is.
    .OUTPUTS
        None. Sets $ctx.AzureUnavailableReason.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][string] $Reason,
        [switch] $Quiet
    )

    $ctx = $script:CAInvContext
    if ($ctx) { Add-CAInvContextData -Context $ctx -Name 'AzureUnavailableReason' -Value $Reason }

    $consequence = 'Consequence: the legacy auth drilldown (6.16) and the method matrix usage axis (6.23) stay Not assessed.'
    if ($Quiet) {
        Write-CAInvLog -Level 'DEBUG' -Domain '6.25' -Message "Log Analytics route not available: $Reason $consequence"
    }
    else {
        Write-CAInvLog -Level 'WARN' -Domain '6.25' -Message "Log Analytics route not available: $Reason $consequence"
    }
}

function Get-CAInvAzureUnavailableReason {
    <#
    .SYNOPSIS
        Returns the reason the Azure/Log Analytics route is unavailable, or an empty string.
    .DESCRIPTION
        Meant to let a NotAssessedReason or ObservedValue carry the cause instead of the symptom.
        Returns an empty string when nothing was recorded, so callers can interpolate the result
        without a check.
    .OUTPUTS
        String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return [string](Get-CAInvProp $script:CAInvContext 'AzureUnavailableReason' '')
}
