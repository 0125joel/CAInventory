function Invoke-CAInvDeviceLayer {
    <#
    .SYNOPSIS
        Layer function 4 — Devices. Calls this layer's collectors.
    .DESCRIPTION
        Domains: 6.17 devices/device identities, 6.18 Intune enrollment/compliance, 6.19 device
        registration/join, 6.29 Defender dependencies. Devices first,
        so the compliance collector can reuse the device match (azureADDeviceId).
    #>
    [CmdletBinding()]
    param()

    Get-CAInvDevice
    Get-CAInvIntuneCompliance

    Get-CAInvAppProtectionPolicy
    Get-CAInvAppProtectionCoverage
    Get-CAInvDeviceRegistrationPolicy
    Get-CAInvDefenderDependency
}
