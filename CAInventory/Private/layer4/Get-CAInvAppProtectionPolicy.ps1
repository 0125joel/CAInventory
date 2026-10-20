function Get-CAInvAppProtectionPolicy {
    <#
    .SYNOPSIS
        Domain 6.18 — App protection policy as a CA dependency.
    .DESCRIPTION
        Layer 4 collector. The CA grant control "Require app protection policy"
        (grantControls.builtInControls = compliantApplication) doesn't work on its own. Microsoft:
        "This policy works in tandem with an app protection policy created in Microsoft Intune."
        Without an assigned app protection policy, no user can satisfy the control, regardless of
        what they do. So that's not a configuration detail but a hard precondition that must exist
        before rollout.

        The item gains weight because "Require app protection policy" is the migration
        destination of the phased-out "Require approved client app" (see Condition-08): tenants
        following that path pass through here.

        Source choice, and this deviates from what seems obvious at first glance. The
        /deviceAppManagement/managedAppPolicies endpoint delivers all MAM policies in one call,
        but the base type managedAppPolicy carries NO assignment information: isAssigned and
        deployedAppCount only exist on the platform-specific subtypes (verified against Microsoft
        Learn, 25-08-2026, both v1.0 and beta). It's precisely "policy exists but is assigned to
        nobody" that's the situation where the portal shows a policy while nobody can satisfy the
        control. Hence two targeted calls instead of one broad one.

        Windows stays out of scope: the compliantApplication control affects iOS and Android in
        practice, and the Windows variant has a different object model.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.18'
    $src    = 'GET /deviceAppManagement/iosManagedAppProtections; GET /deviceAppManagement/androidManagedAppProtections'

    $ok = Test-CAInvLicensePrecondition -CheckId 'Device-09' -Domain $domain `
        -ObjectType 'AppProtectionPolicy' -Property 'managedAppProtections' -GraphSource $src `
        -Consequence ('Without Intune, there is no app protection policy, so a CA control requiring an app protection policy cannot be satisfied by anyone.')
    if (-not $ok) { return }

    $caPolicies = @(Get-CAInvCaPolicy)

    $mamPolicies = @($caPolicies | Where-Object {
            $_.state -ne 'disabled' -and
            (@(Get-CAInvProp $_ 'grantControls.builtInControls' @()) -contains 'compliantApplication')
        })

    $protections = [System.Collections.Generic.List[object]]::new()
    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($ep in @(
            @{ Uri = 'deviceAppManagement/iosManagedAppProtections'; Platform = 'iOS' }
            @{ Uri = 'deviceAppManagement/androidManagedAppProtections'; Platform = 'Android' }
        )) {
        $resp = Invoke-CAInvGraph -Uri $ep.Uri -ApiVersion 'v1.0'
        if ($resp.Failed) {
            $failures.Add("$($ep.Platform): $($resp.ErrorMessage)")
            continue
        }
        foreach ($pol in @($resp.Value)) {
            [void]$protections.Add([PSCustomObject]@{
                    Platform    = $ep.Platform
                    Id          = [string](Get-CAInvProp $pol 'id' '')
                    DisplayName = [string](Get-CAInvProp $pol 'displayName' '')
                    IsAssigned  = [bool](Get-CAInvProp $pol 'isAssigned' $false)
                    AppCount    = [int](Get-CAInvProp $pol 'deployedAppCount' 0)
                })
        }
    }

    $raw = Write-CAInvRaw -Domain $domain -Endpoint 'managedAppProtections' -Data @($protections)

    if ($failures.Count -eq 2) {
        New-CAInvRecord -Domain $domain -CheckId 'Device-09' -ObjectType 'AppProtectionPolicy' `
            -Property 'managedAppProtections' -Status 'Not assessed' `
            -NotAssessedReason ('Could not read either app protection endpoint. {0}' -f @($failures -join '; ')) `
            -GraphSource $src -RawPath $raw | Out-Null
        return
    }
    if ($failures.Count -eq 1) {
        New-CAInvRecord -Domain $domain -CheckId 'Device-09' -ObjectType 'AppProtectionPolicy' `
            -Property 'managedAppProtections' -Status 'Not assessed' `
            -NotAssessedReason ('One of the two platforms could not be read, so the picture is incomplete. {0}' -f @($failures -join '; ')) `
            -GraphSource $src -RawPath $raw | Out-Null
    }

    $assigned = @($protections | Where-Object { $_.IsAssigned })
    $unassigned = @($protections | Where-Object { -not $_.IsAssigned })
    $caNames = @($mamPolicies | ForEach-Object { Get-CAInvProp $_ 'displayName' }) -join ', '

    if ($protections.Count -eq 0) {
        if ($mamPolicies.Count -gt 0) {
            New-CAInvRecord -Domain $domain -CheckId 'Device-09' -ObjectType 'AppProtectionPolicy' `
                -Property 'managedAppProtections' `
                -ObservedValue "No app protection policy in the tenant, while $($mamPolicies.Count) CA policy(s) use the 'Require app protection policy' control: $caNames" `
                -Status 'Gap' -GraphSource $src -RawPath $raw `
                -Recommendation ('This CA policy is unsatisfiable: the control requires an app protection policy from Intune, and none exists. Every user covered by it will be blocked, regardless of what they do. Create app protection policy for iOS and Android and assign it before enabling this policy.') | Out-Null
        }
        else {

            New-CAInvRecord -Domain $domain -CheckId 'Device-09' -ObjectType 'Tenant' `
                -Property 'managedAppProtections' `
                -ObservedValue 'No app protection policy, and no CA policy uses the control.' `
                -Status 'Ready' -GraphSource $src -RawPath $raw | Out-Null
        }
        Write-CAInvLog -Level 'INFO' -Domain $domain -Message "No app protection policies found; $($mamPolicies.Count) CA policy(s) use the control."
        return
    }

    if ($assigned.Count -eq 0 -and $mamPolicies.Count -gt 0) {
        New-CAInvRecord -Domain $domain -CheckId 'Device-09' -ObjectType 'AppProtectionPolicy' `
            -Property 'isAssigned' `
            -ObservedValue "$($protections.Count) app protection polic(ies) exist, but none is assigned, while $($mamPolicies.Count) CA policy(s) use the control: $caNames" `
            -Status 'Gap' -GraphSource $src -RawPath $raw `
            -Recommendation ('The policy exists but is assigned to nobody. In the portal this looks like it''s handled, while no user can actually satisfy the CA control. Assign the policy to the groups covered by the CA policy.') | Out-Null
    }
    else {
        foreach ($u in $unassigned) {
            New-CAInvRecord -Domain $domain -CheckId 'Device-09' -ObjectType 'AppProtectionPolicy' `
                -ObjectId $u.Id -ObjectName "$($u.DisplayName) ($($u.Platform))" -Property 'isAssigned' `
                -ObservedValue "isAssigned=false; deployedAppCount=$($u.AppCount)" `
                -Status 'Review required' -GraphSource $src -RawPath $raw `
                -Recommendation ('This app protection policy is assigned to no group and therefore does nothing. Determine whether that''s deliberate, e.g. because it''s still in preparation, or clean it up to keep the set manageable.') | Out-Null
        }

        foreach ($e in @($assigned | Where-Object { $_.AppCount -le 0 })) {
            $emptyStatus = if ($mamPolicies.Count -gt 0) { 'Gap' } else { 'Review required' }
            New-CAInvRecord -Domain $domain -CheckId 'Device-09' -ObjectType 'AppProtectionPolicy' `
                -ObjectId $e.Id -ObjectName "$($e.DisplayName) ($($e.Platform))" -Property 'deployedAppCount' `
                -ObservedValue "isAssigned=true; deployedAppCount=0" `
                -Status $emptyStatus -GraphSource $src -RawPath $raw `
                -Recommendation ('This policy is assigned to users but to no app at all, and therefore protects nothing. The CA control looks at the app the user is coming in through, so with zero apps nobody can satisfy it. Add the apps that should be covered by the policy.') | Out-Null
        }

        $totalApps = ($assigned | Measure-Object -Property AppCount -Sum).Sum
        $platforms = @($assigned | ForEach-Object { $_.Platform } | Sort-Object -Unique) -join ', '
        $observed = "$($assigned.Count) assigned app protection polic(ies) across $platforms; $totalApps app assignment(s)"
        $observed += if ($mamPolicies.Count -gt 0) { "; $($mamPolicies.Count) CA policy(s) use the control." } else { '; no CA policy uses the control at this time.' }

        New-CAInvRecord -Domain $domain -CheckId 'Device-09' -ObjectType 'AppProtectionPolicy' `
            -Property 'managedAppProtections' -ObservedValue $observed `
            -Status 'Ready' -GraphSource $src -RawPath $raw | Out-Null
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($protections.Count) app protection policy(s) ($($assigned.Count) assigned); $($mamPolicies.Count) CA policy(s) with the control."
}
