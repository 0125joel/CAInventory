function Get-CAInvProtectedAction {
    <#
    .SYNOPSIS
        Domain 6.13 — Protected actions on the management of Conditional Access.
    .DESCRIPTION
        Layer 1 collector. Protected actions are permissions tied to a Conditional Access
        authentication context: whoever wants to perform the action must first satisfy the CA
        policy behind that context. Enforcement happens at the moment of the action, not at sign-in
        or role activation, and thus works regardless of which role someone has or how they got
        that permission.

        The Conditional Access deployment article explicitly recommends this for managing CA
        policies themselves. That's the point: whoever can change CA can turn off every other
        control. Three permissions cover that management (Microsoft Learn,
        protected-actions-overview, verified 25-08-2026):

          microsoft.directory/conditionalAccessPolicies/basic/update
          microsoft.directory/conditionalAccessPolicies/create
          microsoft.directory/conditionalAccessPolicies/delete

        Measurement. This runs via BETA, not v1.0: the unifiedRbacResourceAction API that provides
        authenticationContextId and isAuthenticationContextSettable only exists there. Microsoft
        documents that itself in protected-actions-add. The backlog assumed v1.0 with a $filter;
        that's incorrect and has been corrected here. Deliberately NO $filter is used but
        client-side filtering instead: filterability on these properties isn't documented, and a
        400 on an unsupported query shape would incorrectly set the whole check to Not assessed.

        Status is Review required, not Gap. Microsoft recommends protected actions but nowhere
        requires them, and a tenant can achieve the same goal via PIM role activation with a CA
        policy on it. What's measured here is the absence of a recommended extra layer, not a
        deviation from a standard.

        Reuses $ctx.AuthContexts from layer 0 (Foundation-15) to be able to name the linked context;
        without that set the check keeps working, just with the id instead of the name.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.13'
    $src    = 'GET /beta/roleManagement/directory/resourceNamespaces/microsoft.directory/resourceActions'

    $resp = Invoke-CAInvGraph -Uri 'roleManagement/directory/resourceNamespaces/microsoft.directory/resourceActions?$select=id,actionVerb,authenticationContextId,isAuthenticationContextSettable' -ApiVersion 'beta'
    if ($resp.Failed) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-13' -ObjectType 'ProtectedAction' `
            -Property 'authenticationContextId' -Status 'Not assessed' `
            -NotAssessedReason ('Could not read the resourceActions of microsoft.directory: {0}. Can be checked in the portal via Entra ID > Roles and administrators > Protected actions.' -f @($resp.ErrorMessage)) `
            -ApiVersion 'beta' -GraphSource $src | Out-Null
        return
    }

    $actions = @($resp.Value)
    $raw = Write-CAInvRaw -Domain $domain -Endpoint 'resourceActions' -Data $actions

    $caActions = @($actions | Where-Object { [string](Get-CAInvProp $_ 'id' '') -match 'conditionalAccessPolicies' })

    if ($caActions.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-13' -ObjectType 'ProtectedAction' `
            -Property 'authenticationContextId' -Status 'Not assessed' `
            -NotAssessedReason ('The response contains no resourceActions for conditionalAccessPolicies, even though they should be there. The shape of the API may have changed; check the available actions manually.') `
            -ApiVersion 'beta' -GraphSource $src -RawPath $raw | Out-Null
        return
    }

    $settableActions = @($caActions | Where-Object { [bool](Get-CAInvProp $_ 'isAuthenticationContextSettable' $false) })

    if ($settableActions.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-13' -ObjectType 'ProtectedAction' `
            -Property 'authenticationContextId' -Status 'Not assessed' `
            -NotAssessedReason ('None of the conditionalAccessPolicies resourceActions in the response carries isAuthenticationContextSettable=true. The shape of the API may have changed; check the available actions manually.') `
            -ApiVersion 'beta' -GraphSource $src -RawPath $raw | Out-Null
        return
    }

    $protected = @($settableActions | Where-Object { -not [string]::IsNullOrWhiteSpace([string](Get-CAInvProp $_ 'authenticationContextId' '')) })

    if ($protected.Count -eq 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-13' -ObjectType 'ProtectedAction' `
            -Property 'authenticationContextId' `
            -ObservedValue "None of the $($settableActions.Count) attachable CA management actions is tied to an authentication context." `
            -Status 'Review required' -ApiVersion 'beta' -GraphSource $src -RawPath $raw `
            -Recommendation ('Management of Conditional Access is not protected with a protected action. Whoever can change CA can turn off every other control, and that permission isn''t tied to a role but to whoever holds it through whatever path. Assess whether that fits the management model. To enable it: create an authentication context, attach a CA policy to it that requires passwordless or phishing-resistant MFA, exclude an emergency account, and then attach the context to the create, delete, and basic/update actions on conditionalAccessPolicies. Mind the order, and set the accompanying CA policy to On, not report-only — otherwise the policy is never satisfied and you can no longer reach the CA page.') | Out-Null
        Write-CAInvLog -Level 'INFO' -Domain $domain -Message "No protected action on CA management ($($settableActions.Count) linkable actions assessed)."
        return
    }

    $ctx = $script:CAInvContext
    $authContexts = @(if ($ctx.PSObject.Properties.Name -contains 'AuthContexts') { @($ctx.AuthContexts) } else { @() })
    $ctxNames = @{}
    foreach ($ac in $authContexts) {
        $acId = [string](Get-CAInvProp $ac 'id' '')
        if ($acId) { $ctxNames[$acId] = [string](Get-CAInvProp $ac 'displayName' $acId) }
    }

    $labels = foreach ($a in $protected) {
        $acId = [string](Get-CAInvProp $a 'authenticationContextId' '')
        $acName = if ($ctxNames.ContainsKey($acId)) { "$acId ($($ctxNames[$acId]))" } else { $acId }
        "$([string](Get-CAInvProp $a 'id' '')) -> $acName"
    }

    $allCovered = ($protected.Count -eq $settableActions.Count)
    $observed = "$($protected.Count) of $($settableActions.Count) CA management actions protected: $(@($labels) -join '; ')"

    if ($allCovered) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-13' -ObjectType 'ProtectedAction' `
            -Property 'authenticationContextId' -ObservedValue $observed `
            -Status 'Ready' -ApiVersion 'beta' -GraphSource $src -RawPath $raw `
            -Recommendation ('Still verify that the CA policy behind this authentication context is set to On, not report-only, and that an emergency account is excluded from it. A protected action with a policy that never gets satisfied locks the CA page for everyone.') | Out-Null
    }
    else {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-13' -ObjectType 'ProtectedAction' `
            -Property 'authenticationContextId' -ObservedValue $observed `
            -Status 'Review required' -ApiVersion 'beta' -GraphSource $src -RawPath $raw `
            -Recommendation ('Part of CA management is protected, but not all of it. An uncovered action is a workaround to the same end: someone who isn''t allowed to change a policy but is allowed to delete it can still disable it that way. Attach the same authentication context to all three actions on conditionalAccessPolicies, or record why the remaining one deliberately stays open.') | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($protected.Count) of $($settableActions.Count) CA management actions protected with an authentication context."
}
