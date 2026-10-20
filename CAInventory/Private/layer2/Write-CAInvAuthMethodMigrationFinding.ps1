function Write-CAInvAuthMethodMigrationFinding {
    <#
    .SYNOPSIS
        Auth-02 — migration status of the authentication methods policy.
    .DESCRIPTION
        Managing authentication methods in the legacy MFA and SSPR policy is being phased out:
        since September 30, 2025, methods can no longer be managed there. The three states mean
        something materially different (Microsoft Learn, concept-authentication-methods-manage,
        verified 24-08-2026):

          premigration        The authentication methods policy only applies to authentication;
                              the legacy settings are still honored.
          migrationInProgress The policy applies to authentication and SSPR; legacy still counts.
          migrationComplete   Only this policy counts; legacy settings are ignored.

        Why this matters for the assessment itself, not just for the customer: if a tenant isn't
        on migrationComplete yet, Auth-01 and the entire method usage matrix (Auth-05 through
        Auth-07) measure a policy that isn't solely authoritative. Those outcomes are then
        factually correct and practically misleading.

        Note the exact enum value 'premigration': lowercase m, no camelCase. The portal shows
        'Pre-migration', which easily leads to a wrong comparison. That's why we compare
        case-insensitively on the normalized value.
    .PARAMETER Layer
        The layer name under which the record is written.
    .PARAMETER Domain
        The domain number (6.5).
    .PARAMETER Policy
        The authenticationMethodsPolicy object from Graph.
    .PARAMETER GraphSource
        The source designation for the record.
    .PARAMETER RawPath
        Path to the written raw evidence.
    .OUTPUTS
        None. Writes one record via New-CAInvRecord.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][string] $Domain,
        [Parameter(Mandatory)][AllowNull()][object] $Policy,
        [Parameter(Mandatory)][string] $GraphSource,
        [string] $RawPath
    )

    $state = [string](Get-CAInvProp $Policy 'policyMigrationState' '')
    $normalized = $state.Trim().ToLowerInvariant()

    Add-CAInvContextData -Context $script:CAInvContext -Name 'AuthMethodPolicyMigrationState' `
        -Value $(if ([string]::IsNullOrWhiteSpace($state)) { $null } else { $state })

    if ([string]::IsNullOrWhiteSpace($normalized) -or $normalized -eq 'unknownfuturevalue') {
        $reason = if ([string]::IsNullOrWhiteSpace($normalized)) {
            'The response contains no policyMigrationState; the migration status therefore cannot be determined.'
        }
        else {
            'The response reports policyMigrationState = unknownFutureValue, a sentinel value for a state this module doesn''t recognize yet.'
        }
        New-CAInvRecord -Domain $Domain -CheckId 'Auth-02' -ObjectType 'Policy' `
            -ObjectName 'Authentication methods policy' -Property 'policyMigrationState' `
            -Status 'Not assessed' -NotAssessedReason $reason `
            -GraphSource $GraphSource -RawPath $RawPath | Out-Null
        return
    }

    switch ($normalized) {
        'migrationcomplete' {
            New-CAInvRecord -Domain $Domain -CheckId 'Auth-02' -ObjectType 'Policy' `
                -ObjectName 'Authentication methods policy' -Property 'policyMigrationState' `
                -ObservedValue 'migrationComplete' -Status 'Ready' `
                -GraphSource $GraphSource -RawPath $RawPath `
                -Recommendation ('The migration is complete: only the authentication methods policy governs, and the legacy settings are ignored. The method matrix therefore measures the policy that actually applies.') | Out-Null
        }
        'migrationinprogress' {
            New-CAInvRecord -Domain $Domain -CheckId 'Auth-02' -ObjectType 'Policy' `
                -ObjectName 'Authentication methods policy' -Property 'policyMigrationState' `
                -ObservedValue 'migrationInProgress' -Status 'Gap' `
                -GraphSource $GraphSource -RawPath $RawPath `
                -Recommendation ('The authentication methods policy already applies to authentication and SSPR, but the legacy MFA and SSPR settings still count: a method you turn off here can still be usable via the legacy policy. Finish the migration via Entra ID > Authentication methods > Policies > Manage migration, and then turn off the methods in the legacy policy. Until then, the method matrix doesn''t measure the full picture.') | Out-Null
        }
        'premigration' {
            New-CAInvRecord -Domain $Domain -CheckId 'Auth-02' -ObjectType 'Policy' `
                -ObjectName 'Authentication methods policy' -Property 'policyMigrationState' `
                -ObservedValue 'premigration' -Status 'Gap' `
                -GraphSource $GraphSource -RawPath $RawPath `
                -Recommendation ('The tenant is still on pre-migration: the authentication methods policy only applies to authentication, and the legacy MFA and SSPR settings are still honored. The deadline of September 30, 2025 has passed; since then, methods in those legacy policies can no longer be managed. Finish the migration before enabling the CA baseline, or you''ll be enforcing a methods policy that isn''t solely authoritative. Note: only the converged registration experience recognizes this policy, and targeting works via groups, not individual users.') | Out-Null
        }
        default {

            New-CAInvRecord -Domain $Domain -CheckId 'Auth-02' -ObjectType 'Policy' `
                -ObjectName 'Authentication methods policy' -Property 'policyMigrationState' `
                -Status 'Not assessed' `
                -NotAssessedReason ('Unknown migration state ''{0}''; this module recognizes premigration, migrationInProgress, and migrationComplete. Check whether Microsoft has added a new state.' -f @($state)) `
                -GraphSource $GraphSource -RawPath $RawPath | Out-Null
        }
    }
}
