function Get-CAInvDirectorySyncAccount {
    <#
    .SYNOPSIS
        Identity-05 — holders of the Directory Synchronization Accounts role and their CA exclusion.
    .DESCRIPTION
        The account that Entra Connect or Cloud Sync synchronizes with carries the directory role
        Directory Synchronization Accounts (templateId in config/admin-roles.json,
        roleTemplateIds.directorySynchronizationAccounts).
        Microsoft names that account by name among the identities you exclude from blocking CA
        policies: "Service accounts and Service principals, such as the Microsoft Entra Connect
        Sync Account". The device compliance policy article is even more specific on how: for
        hybrid identity, choose "Directory roles, then select Directory Synchronization Accounts",
        i.e. exclude the ROLE instead of the individual user.

        Why this deserves its own check next to Identity-02/Identity-04: those work on a name
        heuristic, and that heuristic doesn't recognize 'sync'. An account like
        Sync_SERVER_<id>@<tenant>.onmicrosoft.com therefore slips through it, and showed up
        in the reference run's rollout plan among the "admins without a phishing-resistant method".
        That's both a false positive in the customer report and a missed real check. The role match
        here is deterministic and replaces that guess; the name pattern in
        Test-CAInvServiceAccountName is deliberately NOT widened, since that would make three checks
        noisier at once.

        Accounts found are flagged in the context (SyncAccountIds) so the user-focused MFA-readiness
        checks no longer count them as regular users.

        No Graph call of its own: reuses the role assignments Get-CAInvPrivilegedAccess already
        fetched. Note that collection contains both active and eligible assignments; the eligible
        objects carry assignmentType = 'Eligible' so a filter on 'Assigned' skips them without a
        StrictMode error.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.11'
    $src    = 'cross: roleManagement (Directory Synchronization Accounts) x CA-policies'

    $syncRoleTemplate = Get-CAInvRoleTemplateId -Name 'directorySynchronizationAccounts' -Fallback 'd29b2b05-8046-44ba-8758-1e26182fcf32'

    $ctx = $script:CAInvContext
    $privileged = @(if ($ctx.PSObject.Properties.Name -contains 'PrivilegedPrincipals') { @($ctx.PrivilegedPrincipals) } else { @() })
    $policies = @(Get-CAInvCaPolicy)

    if ($privileged.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-05' -ObjectType 'DirectoryRole' `
            -ObjectName 'Directory Synchronization Accounts' -Property 'roleMembers' `
            -Status 'Not assessed' `
            -NotAssessedReason ('Role assignments not available (Get-CAInvPrivilegedAccess not run, or not readable).') `
            -GraphSource $src | Out-Null
        return
    }

    $holders = @($privileged | Where-Object {
        $_.roleTemplate -eq $syncRoleTemplate -or $_.roleName -eq 'Directory Synchronization Accounts'
    })

    $holderIds = @($holders | ForEach-Object { [string]$_.principalId } | Where-Object { $_ } | Select-Object -Unique)
    Add-CAInvContextData -Context $script:CAInvContext -Name 'SyncAccountIds' -Value $holderIds

    if ($holders.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-05' -ObjectType 'DirectoryRole' `
            -ObjectName 'Directory Synchronization Accounts' -Property 'roleMembers' `
            -ObservedValue 'No holders of the Directory Synchronization Accounts role. That is normal for a cloud-only tenant without Entra Connect or Cloud Sync.' `
            -Status 'Ready' -GraphSource $src | Out-Null
        return
    }

    $restricting = @($policies | Where-Object { Test-CAInvPolicyRestrictsSignIn -Policy $_ })

    foreach ($h in $holders) {
        $holderId = [string]$h.principalId
        $name = [string]$h.principalName
        if ([string]::IsNullOrWhiteSpace($name)) { $name = $holderId }

        $notExcluded = [System.Collections.Generic.List[string]]::new()
        $uncertain = $false

        foreach ($p in $restricting) {
            $users = Get-CAInvProp $p 'conditions.users'
            $exclRoles = @(Get-CAInvProp $users 'excludeRoles' @())

            if ($exclRoles -contains $syncRoleTemplate) { continue }

            $exclUsers = @(Get-CAInvProp $users 'excludeUsers' @())
            if ($exclUsers -contains $holderId) { continue }

            if (@(Get-CAInvProp $users 'excludeGroups' @()).Count -gt 0) { $uncertain = $true }

            [void]$notExcluded.Add([string](Get-CAInvProp $p 'displayName'))
        }

        if ($notExcluded.Count -eq 0) {
            New-CAInvRecord -Domain $domain -CheckId 'Identity-05' -ObjectType 'User' `
                -ObjectId $holderId -ObjectName $name -Property 'caExclusion' `
                -ObservedValue 'Excluded from every policy that can block or restrict a sign-in.' `
                -Status 'Ready' -GraphSource $src | Out-Null
        }
        else {
            $status = if ($uncertain) { 'Review required' } else { 'Gap' }
            New-CAInvRecord -Domain $domain -CheckId 'Identity-05' -ObjectType 'User' `
                -ObjectId $holderId -ObjectName $name -Property 'caExclusion' `
                -ObservedValue "Sync account is not excluded from: $($notExcluded -join ', ')" `
                -Status $status -ManualReview:$uncertain -GraphSource $src `
                -Recommendation ('Exclude the Directory Synchronization Accounts ROLE instead of the individual account: when setting up the exclusion, choose Directory roles and select Directory Synchronization Accounts. That way the exception stays correct even when the sync account is replaced, e.g. during a migration to Cloud Sync.') | Out-Null
        }
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "Identity-05: $($holders.Count) holder(s) of the Directory Synchronization Accounts role."
}
