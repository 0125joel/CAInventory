function Get-CAInvGovernanceEvidence {
    <#
    .SYNOPSIS
        Domain 6.32 — Governance and manageability.
    .DESCRIPTION
        Layer 7 collector. The governance questions (ownership of the CA design, change and review
        process, naming conventions, documentation, test/rollback procedure) can't be read from the
        tenant; they come from a manual questionnaire and exports from SharePoint, DevOps, ITSM, or
        GRC. This collector has no Graph source and explicitly
        marks the governance topics as Review required, so they stay visible in the register and
        the scorecard instead of silently being absent.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.32'
    $src    = 'Manual register (SharePoint/DevOps/ITSM/GRC); not an Entra source'

    $topics = @(
        @{ Name = 'CA-ontwerpeigenaar en verantwoordelijkheid'; Prop = 'designOwnership' },
        @{ Name = 'Change and review process for CA policies';    Prop = 'changeProcess' },
        @{ Name = 'Naming conventions en documentatie';          Prop = 'namingAndDocs' },
        @{ Name = 'Test-, rollback- en noodprocedure';           Prop = 'testAndRollback' }
    )

    foreach ($t in $topics) {
        New-CAInvRecord -Domain $domain -CheckId 'Govern-02' -ObjectType 'Governance' `
            -ObjectName $t.Name -Property $t.Prop `
            -ObservedValue 'Cannot be read from the tenant; requires confirmation from the manual register.' `
            -Status 'Review required' -ManualReview -ApiVersion 'n/a' -GraphSource $src `
            -Recommendation ('Record this governance topic and link the evidence (document/ticket). Without recorded governance, the CA baseline drifts unnoticed.') | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($topics.Count) governance topics flagged for manual review."
}
