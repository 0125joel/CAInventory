function Get-CAInvExternalIdentity {
    <#
    .SYNOPSIS
        Domain 6.21 — Cross-tenant access and external identities.
    .DESCRIPTION
        Reads crossTenantAccessPolicy (default + partners), authorizationPolicy, and
        identityProviders. Flags inbound trust for MFA/device from external tenants (trust moves
        the check to the home tenant). Guests are counted from the already-fetched user set.
        Trust effect remains context-dependent → 'Review required' where it concerns an
        organizational choice.

        Precheck: Identity-14 (partner inbound trust) and
        Identity-16 (guest role level) don't apply without guests in the tenant, regardless of the
        configuration on paper. The guest count is therefore determined here first (from the
        already-fetched user set, Get-CAInvUser always runs before this collector) and used to gate
        both checks. If the user set is unknown (e.g. -Layer Identity without layer 0/1 in the same
        run), behavior stays unchanged: we never gamble on the absence of guests we couldn't
        measure.

        Since 01-09-2026, after a successful partners read, sets `CrossTenantTrustKnown` (bool) and
        `AnyCrossTenantDeviceOrMfaTrust` (bool: at least one trusting partner) on the context
        object. Sole consumer: Identity-20 in Test-CAInvReferentialIntegrity, which can then factor
        in whether a device-requiring CA policy is still feasible for the guest population, without
        repeating the partners call. If the read doesn't happen (0 guests, or $partResp.Failed),
        both properties stay unset: Identity-20 treats that as unknown, not as "no trust".
    #>
    [CmdletBinding()]
    param()

    $domain = '6.21'

    $ctx = $script:CAInvContext
    $guestsKnown = ($ctx.PSObject.Properties.Name -contains 'Users')
    $guests = @(if ($guestsKnown) { @($ctx.Users | Where-Object { $_.userType -eq 'Guest' }) } else { @() })
    $noGuests = $guestsKnown -and ($guests.Count -eq 0)

    $defResp = Invoke-CAInvGraphOrNotAssessed -Uri 'policies/crossTenantAccessPolicy/default' -ApiVersion 'v1.0' `
        -Domain $domain -CheckId 'Identity-15' -ObjectType 'CrossTenantAccess' -Property 'default' `
        -GraphSource 'GET /policies/crossTenantAccessPolicy/default' `
        -NotAssessedReasonPrefix ('Could not read crossTenantAccessPolicy/default')
    if (-not $defResp.Failed) {
        $def = $defResp.Value | Select-Object -First 1
        Write-CAInvRaw -Domain $domain -Endpoint 'crossTenantAccessDefault' -Data $def | Out-Null
        $defTrust = Get-CAInvProp $def 'inboundTrust'
        New-CAInvRecord -Domain $domain -CheckId 'Identity-15' -ObjectType 'CrossTenantAccess' `
            -ObjectName 'default' -Property 'inboundTrust' `
            -ObservedValue ($(if ($defTrust) { $defTrust | ConvertTo-Json -Compress -Depth 5 } else { 'none' })) `
            -Status 'Ready' -GraphSource 'GET /policies/crossTenantAccessPolicy/default' | Out-Null
    }

    if ($noGuests) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-14' -ObjectType 'CrossTenantPartner' `
            -Property 'inboundTrust' -ObservedValue "0 guests in the tenant; partner inbound trust does not apply." `
            -Status 'Ready' -GraphSource 'GET /users (userType eq Guest)' | Out-Null
    }
    else {
        $partResp = Invoke-CAInvGraph -Uri 'policies/crossTenantAccessPolicy/partners' -ApiVersion 'v1.0'
        if ($partResp.Failed) {

            New-CAInvRecord -Domain $domain -CheckId 'Identity-14' -ObjectType 'CrossTenantPartner' `
                -Property 'inboundTrust' -Status 'Not assessed' `
                -NotAssessedReason ('Could not read crossTenantAccessPolicy/partners: {0}' -f @($partResp.ErrorMessage)) `
                -GraphSource 'GET /policies/crossTenantAccessPolicy/partners' | Out-Null
        }
        else {
            $partners = @($partResp.Value)
            Write-CAInvRaw -Domain $domain -Endpoint 'crossTenantAccessPartners' -Data $partners | Out-Null
            $trustingPartners = [System.Collections.Generic.List[object]]::new()
            foreach ($pt in $partners) {
                $trust = Get-CAInvProp $pt 'inboundTrust'
                $trustsMfa = [bool](Get-CAInvProp $trust 'isMfaAccepted' $false)
                $trustsDevice = [bool](Get-CAInvProp $trust 'isCompliantDeviceAccepted' $false) -or [bool](Get-CAInvProp $trust 'isHybridAzureADJoinedDeviceAccepted' $false)
                if ($trustsMfa -or $trustsDevice) {
                    [void]$trustingPartners.Add($pt)
                    New-CAInvRecord -Domain $domain -CheckId 'Identity-14' -ObjectType 'CrossTenantPartner' `
                        -ObjectId $pt.tenantId -Property 'inboundTrust' `
                        -ObservedValue ("MFA=$trustsMfa; device=$trustsDevice") -Status 'Review required' `
                        -GraphSource 'GET /policies/crossTenantAccessPolicy/partners' -ManualReview `
                        -Recommendation ('Confirm whether trusting MFA/device from this external tenant is desired.') | Out-Null
                }
            }

            if ($trustingPartners.Count -eq 0) {
                New-CAInvRecord -Domain $domain -CheckId 'Identity-14' -ObjectType 'CrossTenantPartner' `
                    -Property 'inboundTrust' -ObservedValue "None of the $($partners.Count) partner(s) trust MFA or device compliance from this tenant." `
                    -Status 'Ready' -GraphSource 'GET /policies/crossTenantAccessPolicy/partners' | Out-Null
            }

            Add-CAInvContextData -Context $ctx -Name 'CrossTenantTrustKnown' -Value $true
            Add-CAInvContextData -Context $ctx -Name 'AnyCrossTenantDeviceOrMfaTrust' -Value ($trustingPartners.Count -gt 0)
        }
    }

    $idpResp = Invoke-CAInvGraph -Uri 'identity/identityProviders' -ApiVersion 'v1.0'
    if (-not $idpResp.Failed) {
        $idps = @($idpResp.Value)
        Write-CAInvRaw -Domain $domain -Endpoint 'identityProviders' -Data $idps | Out-Null
        New-CAInvRecord -Domain $domain -CheckId 'Identity-15' -ObjectType 'IdentityProvider' `
            -Property 'count' -ObservedValue $idps.Count -Status 'Ready' `
            -GraphSource 'GET /identity/identityProviders' | Out-Null
    }

    if ($guestsKnown) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-15' -ObjectType 'Tenant' `
            -Property 'guestCount' -ObservedValue $guests.Count -Status 'Ready' `
            -GraphSource 'GET /users (userType eq Guest)' | Out-Null
    }

    if ($noGuests) {
        New-CAInvRecord -Domain $domain -CheckId 'Identity-16' -ObjectType 'Policy' `
            -Property 'guestUserRoleId' -ObservedValue '0 guests in the tenant; guest role level is not applicable.' `
            -Status 'Ready' -GraphSource 'GET /users (userType eq Guest)' | Out-Null
    }
    else {

        $restrictedGuestRoleId = Get-CAInvRoleTemplateId -Name 'restrictedGuestUserRoleId' -Fallback '2af84b1e-32c8-42b7-82bc-daa82404023b'
        $azResp = Invoke-CAInvGraph -Uri 'policies/authorizationPolicy' -ApiVersion 'v1.0'
        if ($azResp.Failed) {
            New-CAInvRecord -Domain $domain -CheckId 'Identity-16' -ObjectType 'Policy' `
                -Property 'guestUserRoleId' -Status 'Not assessed' `
                -NotAssessedReason ('Could not read authorizationPolicy: {0}' -f @($azResp.ErrorMessage)) `
                -GraphSource 'GET /policies/authorizationPolicy' | Out-Null
        }
        else {
            $az = @($azResp.Value) | Select-Object -First 1
            $guestRoleId = Get-CAInvProp $az 'guestUserRoleId'
            $isRestricted = ($guestRoleId -eq $restrictedGuestRoleId)
            New-CAInvRecord -Domain $domain -CheckId 'Identity-16' -ObjectType 'Policy' `
                -Property 'guestUserRoleId' -ObservedValue "guestUserRoleId=$guestRoleId; restricted=$isRestricted" `
                -Status ($(if ($isRestricted) { 'Ready' } else { 'Review required' })) `
                -ManualReview:(-not $isRestricted) `
                -GraphSource 'GET /policies/authorizationPolicy' `
                -Recommendation ($(if (-not $isRestricted) { 'Consider the most restricted guest role level (Restricted Guest User) unless guests deliberately need more permissions.' } else { $null })) | Out-Null
        }
    }
}
