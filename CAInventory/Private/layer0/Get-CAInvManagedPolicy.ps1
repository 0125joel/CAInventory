function Get-CAInvManagedPolicy {
    <#
    .SYNOPSIS
        Foundation-10 — Inventory Microsoft-managed and Baseline security mode CA policies.
    .DESCRIPTION
        Microsoft creates Conditional Access policies in the tenant itself, based on license and
        eligibility. From the source article (conditional-access/managed-policies, verified
        24-08-2026): "The policy is automatically created in your tenant in a Report-only state",
        and "Microsoft enables these policies no less than 30 days after they're introduced in your
        tenant if they're left in the Report-only state." Customers get notified two weeks ahead of
        time. You can enable them earlier or opt out by setting the state to Off; renaming or
        deleting is not possible.

        Why this is a go-live dependency: a customer rolling out their own baseline while a
        Microsoft-managed policy kicks in by itself on day 30 gets duplicate or conflicting
        enforcement that's in no design at all. Microsoft itself warns on the all-users policy that
        "All Users could include service accounts or break-glass accounts, so you might want to
        exclude them".

        Baseline security mode policies are labelled separately: an administrator creates those
        themselves and they don't turn on by themselves, so the thirty-day warning doesn't apply to
        them. The classification lives in Get-CAInvPolicyManagedOrigin, shared with
        New-CAInvWorkbookExport.

        This collector makes NO Graph call of its own: it works on the policy set that
        Get-CAInvConditionalAccessPolicy already fetched.

        This function is PURELY AN INVENTORY. The break-glass exclusion
        verdict has moved to layer 1 (Get-CAInvEmergencyAccess), where the confirmed emergency
        account set is already established and the same helper (Test-CAInvUserExcludedFromPolicy)
        is reused as Emergency-03. Reason: layer 0 only knew -EmergencyAccountUpn/-Id (or nothing),
        never the actually resolved emergency accounts, and moreover only tested an exclusion on
        direct object id — an exclusion via a group or role remained structurally uncertain here.
        `config/checkids.json`'s `layer` field for Foundation-10 has moved along to 1.

        Gates on CAPoliciesFetchFailed, not on an empty policy set: a confirmed zero CA policies
        falls through to the existing "no managed policies found" branch below, which is already
        Ready ("absence here is not a shortcoming"). Only a failed fetch is Not assessed.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.2'
    $src    = 'GET /identity/conditionalAccess/policies (displayName-classificatie)'

    $policies = @(Get-CAInvCaPolicy)

    if ($policies.Count -eq 0 -and [bool](Get-CAInvProp $script:CAInvContext 'CAPoliciesFetchFailed' $true)) {
        New-CAInvRecord -Domain $domain -CheckId 'Foundation-10' -ObjectType 'ConditionalAccessPolicy' `
            -Property 'managedPolicies' -Status 'Not assessed' `
            -NotAssessedReason ('CA policies not available (layer 0 not run, or not readable).') `
            -GraphSource $src | Out-Null
        return
    }

    $managed = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $policies) {
        $origin = Get-CAInvPolicyManagedOrigin -Policy $p
        if ($origin.IsVendorManaged) {
            [void]$managed.Add([PSCustomObject]@{ Policy = $p; Origin = $origin })
        }
    }

    if ($managed.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Foundation-10' -ObjectType 'Tenant' `
            -Property 'managedPolicies' `
            -ObservedValue 'No Microsoft-managed or Baseline security mode policies found. Microsoft rolls these out per tenant based on license and eligibility, so absence here is not a shortcoming.' `
            -Status 'Ready' -GraphSource $src `
            -Recommendation ('Watch the Microsoft 365 message center posts: Microsoft announces new managed policies two weeks before enabling them.') | Out-Null
        Write-CAInvLog -Level 'INFO' -Domain $domain -Message 'Foundation-10: no Microsoft-managed or Baseline security mode policies found.'
        return
    }

    foreach ($entry in $managed) {
        $p = $entry.Policy
        $origin = $entry.Origin
        $name = [string](Get-CAInvProp $p 'displayName' '')
        $state = [string](Get-CAInvProp $p 'state' 'unknown')
        $isMicrosoftManaged = ($origin.Origin -eq 'microsoftManaged')
        $originLabel = if ($isMicrosoftManaged) { 'Microsoft-managed' } else { 'Baseline security mode' }

        $stateText = switch ($state) {
            'enabled' { 'on' }
            'enabledForReportingButNotEnforced' { 'report-only' }
            'disabled' { 'off' }
            default { $state }
        }

        if ($state -eq 'disabled') {
            New-CAInvRecord -Domain $domain -CheckId 'Foundation-10' -ObjectType 'ConditionalAccessPolicy' `
                -ObjectId (Get-CAInvProp $p 'id') -ObjectName $name -Property "$originLabel; state" `
                -ObservedValue "$originLabel, state off. $($origin.Basis)" `
                -Status 'Ready' -GraphSource $src `
                -Recommendation ('The policy is set to Off; the tenant has deliberately opted out and it won''t turn on by itself. Confirm this is a supported decision, not a leftover from testing.') | Out-Null
            continue
        }

        if ($state -eq 'enabledForReportingButNotEnforced') {
            $users = Get-CAInvProp $p 'conditions.users'
            $exclUsers  = @(Get-CAInvProp $users 'excludeUsers' @())
            $exclGroups = @(Get-CAInvProp $users 'excludeGroups' @())
            $exclRoles  = @(Get-CAInvProp $users 'excludeRoles' @())
            $hasAnyExclusion = (($exclUsers.Count + $exclGroups.Count + $exclRoles.Count) -gt 0)
            $exclText = if ($hasAnyExclusion) { 'Exclusions are set.' } else { 'No exclusion at all is set.' }

            $advice = if ($isMicrosoftManaged) {
                'Microsoft turns this policy on by itself no less than thirty days after introduction if it stays in report-only, and announces that two weeks ahead via email and the Microsoft 365 message center. Plan this moment into your own rollout: enable it yourself on a chosen date, or opt out by setting the state to Off. Check first that your emergency accounts are excluded.'
            }
            else {
                'This Baseline security mode policy was created by an administrator from the Microsoft 365 admin center and won''t turn on by itself. Manage it there, not in Entra. Do check that your emergency accounts are excluded before you enable it.'
            }

            New-CAInvRecord -Domain $domain -CheckId 'Foundation-10' -ObjectType 'ConditionalAccessPolicy' `
                -ObjectId (Get-CAInvProp $p 'id') -ObjectName $name -Property "$originLabel; state" `
                -ObservedValue "$originLabel, state report-only. $exclText $($origin.Basis)" `
                -Status 'Review required' -ManualReview -GraphSource $src `
                -Recommendation $advice | Out-Null
            continue
        }

        New-CAInvRecord -Domain $domain -CheckId 'Foundation-10' -ObjectType 'ConditionalAccessPolicy' `
            -ObjectId (Get-CAInvProp $p 'id') -ObjectName $name -Property "$originLabel; state" `
            -ObservedValue "$originLabel, state $stateText. $($origin.Basis)" `
            -Status 'Ready' -GraphSource $src | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Foundation-10: $($managed.Count) vendor-managed policy(s) inventoried."
}
