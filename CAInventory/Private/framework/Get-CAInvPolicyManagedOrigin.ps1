function Get-CAInvPolicyManagedOrigin {
    <#
    .SYNOPSIS
        Determines whether a CA policy is managed by Microsoft, comes from Baseline security mode,
        or is simply the customer's own.
    .DESCRIPTION
        One definition for Foundation-10 and New-CAInvWorkbookExport, so the report and the
        workbook never give a different answer to the same question.

        Graph v1.0 has NO field that marks a policy as Microsoft-managed. The conditionalAccessPolicy
        resource only has id, displayName, state, createdDateTime, modifiedDateTime, templateId,
        conditions, grantControls, and sessionControls. The portal does show it, via the 'Created by'
        column, but that column doesn't come through the API.

        The only Microsoft-documented signal is the name prefix: "Microsoft-managed policy names
        start with **Microsoft-managed:** so you can easily filter for them." Microsoft mentions
        that in the context of audit log filters, not as an API contract. It's therefore a strong
        indicator and not a guarantee, and that's how it's returned here too: every outcome carries
        its own rationale in Basis, so the consumer never gets a hard 'yes' suggested where a
        heuristic actually underlies it.

        Baseline security mode (BSM) is deliberately a SEPARATE outcome, not a synonym. Microsoft:
        "One important difference between BSM policies and Microsoft-managed policies is that the
        BSM policies are created by the administrator, not Microsoft." So they don't turn on
        automatically after thirty days, and the thirty-day warning doesn't apply to them. In the
        portal they show 'Baseline security mode' in the same column.

        Everything verified against Microsoft Learn (conditional-access/managed-policies) on
        2026-08-24.
    .PARAMETER Policy
        A CA policy object from Graph.
    .OUTPUTS
        PSCustomObject with Origin ('microsoftManaged' | 'baselineSecurityMode' | 'unknown'),
        IsVendorManaged (bool), Basis (string), and Reliability ('medium' | 'low').
    .EXAMPLE
        $origin = Get-CAInvPolicyManagedOrigin -Policy $p
        if ($origin.Origin -eq 'microsoftManaged') { ... }
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][AllowNull()][object] $Policy
    )

    $name = [string](Get-CAInvProp $Policy 'displayName' '')

    if ($name -like 'Microsoft-managed:*') {
        return [PSCustomObject]@{
            Origin          = 'microsoftManaged'
            IsVendorManaged = $true
            Reliability     = 'medium'
            Basis           = "Name starts with 'Microsoft-managed:'. Microsoft documents that prefix for filtering audit log rows; Graph v1.0 has no field that marks a policy as Microsoft-managed."
        }
    }

    $bsmNames = @(
        'Require phishing resistant authentication for admins'
        'Block legacy authentication'
    )
    foreach ($bsm in $bsmNames) {
        if ($name -eq $bsm) {
            return [PSCustomObject]@{
                Origin          = 'baselineSecurityMode'
                IsVendorManaged = $true
                Reliability     = 'low'
                Basis           = "Name matches exactly a Baseline security mode policy from the Microsoft 365 admin center. Those policies are created by the administrator, not Microsoft, and don't turn on by themselves. Name recognition without API confirmation: a customer's own policy with the same name cannot be distinguished."
            }
        }
    }

    return [PSCustomObject]@{
        Origin          = 'unknown'
        IsVendorManaged = $false
        Reliability     = 'low'
        Basis           = 'No confirmed signal in Graph v1.0; cannot determine whether Microsoft manages this policy.'
    }
}
