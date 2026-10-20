function Get-CAInvIntuneCompliance {
    <#
    .SYNOPSIS
        Domain 6.18 — Intune enrollment and compliance.
    .DESCRIPTION
        Layer 4 collector. Reads the device compliance policies with their assignments and
        summarizes the compliance status of the managed devices per platform. Device compliance is
        a hard precondition for CA controls that enforce 'require compliant device': if a
        compliance policy is missing for a platform, that control is meaningless for that platform. Reliability depends on the device match from 6.17.

        Keeps the per-platform assignment status on the context object (CompliancePolicyByPlatform)
        so the referential integrity check can cross CA policies that require 'compliant device'
        against actual policy coverage per platform.

        Also keeps whether any
        compliance policy uses `deviceThreatProtectionEnabled`, so Device-10 (Defender connector)
        can determine whether a missing connector is actually relevant: without a device-risk-based
        rule in the compliance policy, a connector has no CA effect. No extra Graph call:
        `deviceCompliancePolicies` already returns these fields without `$select`.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.18'
    $src    = 'GET /deviceManagement/deviceCompliancePolicies'

    $intuneChecks = @(
        @{ CheckId = 'Device-02'; ObjectType = 'CompliancePolicy'; Property = 'deviceCompliancePolicies' }
        @{ CheckId = 'Device-03'; ObjectType = 'Device';           Property = 'complianceState' }
        @{ CheckId = 'Device-05'; ObjectType = 'Policy';           Property = 'defaultComplianceAction' }
        @{ CheckId = 'Device-06'; ObjectType = 'Policy';           Property = 'deviceComplianceCheckinThresholdDays' }
    )
    $intuneLicensed = $true
    foreach ($check in $intuneChecks) {
        $ok = Test-CAInvLicensePrecondition -CheckId $check.CheckId -Domain $domain `
            -ObjectType $check.ObjectType -Property $check.Property -GraphSource $src `
            -Consequence ('Without Intune, there is no compliance policy, so a CA control requiring a compliant device cannot work.')
        if (-not $ok) { $intuneLicensed = $false }
    }
    if (-not $intuneLicensed) { return }

    $cpResp = Invoke-CAInvGraph -Uri 'deviceManagement/deviceCompliancePolicies?$expand=assignments' -ApiVersion 'v1.0'
    if ($cpResp.Failed) {
        New-CAInvRecord -Domain $domain -CheckId 'Device-02' -ObjectType 'CompliancePolicy' `
            -Property 'deviceCompliancePolicies' -Status 'Not assessed' `
            -NotAssessedReason ('Could not read deviceCompliancePolicies: {0}. Possibly no Intune license/permissions.' -f @($cpResp.ErrorMessage)) `
            -GraphSource $src | Out-Null
        return
    }

    $policies = @($cpResp.Value)
    Write-CAInvRaw -Domain $domain -Endpoint 'deviceCompliancePolicies' -Data $policies | Out-Null

    $platformOf = {
        param($p)
        $t = "$(Get-CAInvProp $p '@odata.type' '')".ToLowerInvariant()
        switch -Regex ($t) {
            'windows'  { 'Windows'; break }
            'ios'      { 'iOS'; break }
            'android'  { 'Android'; break }
            'macos'    { 'macOS'; break }
            default    { 'Other' }
        }
    }

    $byPlatform = @{}
    foreach ($p in $policies) {
        $plat = & $platformOf $p
        $assigned = @(Get-CAInvProp $p 'assignments' @()).Count -gt 0
        if (-not $byPlatform.ContainsKey($plat)) { $byPlatform[$plat] = [PSCustomObject]@{ Total = 0; Assigned = 0 } }
        $byPlatform[$plat].Total++
        if ($assigned) { $byPlatform[$plat].Assigned++ }
    }

    $assignedByPlatform = @{}
    foreach ($plat in @('Windows', 'iOS', 'Android', 'macOS')) {
        $info = if ($byPlatform.ContainsKey($plat)) { $byPlatform[$plat] } else { $null }
        $assignedByPlatform[$plat] = [bool]($info -and $info.Assigned -gt 0)
    }
    Add-CAInvContextData -Context $script:CAInvContext -Name 'CompliancePolicyByPlatform' -Value $assignedByPlatform

    $usesDefender = (@($policies | Where-Object { [bool](Get-CAInvProp $_ 'deviceThreatProtectionEnabled' $false) })).Count -gt 0
    Add-CAInvContextData -Context $script:CAInvContext -Name 'CompliancePolicyUsesDefender' -Value $usesDefender

    foreach ($plat in @('Windows', 'iOS', 'Android', 'macOS')) {
        $info = if ($byPlatform.ContainsKey($plat)) { $byPlatform[$plat] } else { $null }
        if (-not $info -or $info.Assigned -eq 0) {
            New-CAInvRecord -Domain $domain -CheckId 'Device-02' -ObjectType 'CompliancePolicy' `
                -ObjectName $plat -Property 'assignedCompliancePolicy' `
                -ObservedValue ($(if ($info) { "$($info.Total) polic(ies), none assigned" } else { 'no compliance policy' })) `
                -Status 'Gap' -GraphSource $src `
                -Recommendation ('No assigned compliance policy for {0}. A CA control requiring a compliant device is meaningless for this platform as long as no policy is assigned.' -f @($plat)) | Out-Null
        }
        else {
            New-CAInvRecord -Domain $domain -CheckId 'Device-02' -ObjectType 'CompliancePolicy' `
                -ObjectName $plat -Property 'assignedCompliancePolicy' `
                -ObservedValue "$($info.Assigned) assigned of $($info.Total) polic(ies)" `
                -Status 'Ready' -GraphSource $src | Out-Null
        }
    }

    $ctx = $script:CAInvContext
    if ($ctx.PSObject.Properties.Name -contains 'ManagedDevices') {
        $managed = @($ctx.ManagedDevices)
        $compliant = @($managed | Where-Object { (Get-CAInvProp $_ 'complianceState' '') -eq 'compliant' }).Count
        New-CAInvRecord -Domain $domain -CheckId 'Device-03' -ObjectType 'Device' `
            -Property 'complianceState' -ObservedValue "$compliant of $($managed.Count) managed devices compliant." `
            -Status 'Ready' -GraphSource 'GET /deviceManagement/managedDevices' | Out-Null
    }

    $dmsResp = Invoke-CAInvGraph -Uri 'deviceManagement/settings' -ApiVersion 'beta'
    if ($dmsResp.Failed) {

        foreach ($cid in @(
                @{ CheckId = 'Device-05'; Property = 'secureByDefault' }
                @{ CheckId = 'Device-06'; Property = 'deviceComplianceCheckinThresholdDays' }
            )) {
            New-CAInvRecord -Domain $domain -CheckId $cid.CheckId -ObjectType 'Policy' `
                -Property $cid.Property -Status 'Not assessed' `
                -NotAssessedReason ('Could not read deviceManagement/settings: {0}' -f @($dmsResp.ErrorMessage)) `
                -ApiVersion 'beta' -GraphSource 'GET /deviceManagement/settings' | Out-Null
        }
    }
    else {
        $dms = @($dmsResp.Value) | Select-Object -First 1
        $secureByDefault = [bool](Get-CAInvProp $dms 'secureByDefault' $false)
        New-CAInvRecord -Domain $domain -CheckId 'Device-05' -ObjectType 'Policy' `
            -Property 'secureByDefault' -ObservedValue "secureByDefault=$secureByDefault" `
            -Status ($(if ($secureByDefault) { 'Ready' } else { 'Gap' })) `
            -ApiVersion 'beta' -GraphSource 'GET /deviceManagement/settings' `
            -Recommendation ($(if (-not $secureByDefault) { 'Set "Mark devices with no compliance policy assigned as" to Not compliant. Without this setting, devices with no assigned compliance policy are silently treated as compliant.' } else { $null })) | Out-Null

        $threshold = Get-CAInvProp $dms 'deviceComplianceCheckinThresholdDays' $null
        if ($null -eq $threshold) {
            New-CAInvRecord -Domain $domain -CheckId 'Device-06' -ObjectType 'Policy' `
                -Property 'deviceComplianceCheckinThresholdDays' -Status 'Not assessed' `
                -NotAssessedReason ('The deviceManagement/settings response contains no deviceComplianceCheckinThresholdDays; the compliance status''s validity period therefore cannot be determined.') `
                -ApiVersion 'beta' -GraphSource 'GET /deviceManagement/settings' | Out-Null
        }
        else {
            $days = [int]$threshold

            if ($days -le 30) {
                New-CAInvRecord -Domain $domain -CheckId 'Device-06' -ObjectType 'Policy' `
                    -Property 'deviceComplianceCheckinThresholdDays' `
                    -ObservedValue "$days days (default is 30)" -Status 'Ready' `
                    -ApiVersion 'beta' -GraphSource 'GET /deviceManagement/settings' | Out-Null
            }
            else {
                New-CAInvRecord -Domain $domain -CheckId 'Device-06' -ObjectType 'Policy' `
                    -Property 'deviceComplianceCheckinThresholdDays' `
                    -ObservedValue "$days days (default is 30, maximum settable 120)" `
                    -Status 'Review required' `
                    -ApiVersion 'beta' -GraphSource 'GET /deviceManagement/settings' `
                    -Recommendation ('The compliance status stays valid for {0} days after a device last checked in. It counts as compliant for that whole period, even if it has reported nothing that entire time, and a CA policy that requires a compliant device simply lets it through. Assess whether this period was deliberately extended, and whether it fits how long devices in this organization are allowed to stay offline. Without such a reason, the default of 30 days is the safer choice.' -f @($days)) | Out-Null
            }
        }
    }

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($policies.Count) compliance policy(s) assessed across platforms."
}
