function Get-CAInvDevice {
    <#
    .SYNOPSIS
        Domain 6.17 — Devices and device identities.
    .DESCRIPTION
        Layer 4 collector. Reads /devices (Entra device objects) and /deviceManagement/
        managedDevices (Intune) and records the population of both.

        Keeps ManagedDevices on the context object; Get-CAInvIntuneCompliance (6.18, Device-03)
        uses exclusively ManagedDevices for the compliance-state count, so that count is already
        scoped to devices actually managed by Intune. The Entra device population itself has no
        other consumer within this run and therefore stays a local variable.

        DEV-002 (device match quality: hard/weak/absent match on azureADDeviceId) has been removed. Almost every tenant has
        Entra device objects that simply never get managed by Intune (BYOD, other MDM, stale
        objects) — that's normal, not a data-quality problem, but the check flagged it as 'Review
        required' anyway as soon as there was even one such device. Device-03 also had a
        dependency on this count ("less reliable with a weak/absent match") that therefore
        triggered almost always, while Device-03's own compliance percentage was already computed
        purely on ManagedDevices and so never needed that noise to be reliable.
    #>
    [CmdletBinding()]
    param()

    $domain = '6.17'

    $devResp = Invoke-CAInvGraphOrNotAssessed -Uri 'devices?$select=id,deviceId,displayName,operatingSystem,trustType,isCompliant,isManaged,accountEnabled' -ApiVersion 'v1.0' -MaxPages 100 `
        -Domain $domain -CheckId 'Device-01' -ObjectType 'Device' -Property 'devices' `
        -GraphSource 'GET /devices' -NotAssessedReasonPrefix ('Could not read /devices')
    if ($devResp.Failed) { return }

    $devices = @($devResp.Value)
    Write-CAInvRaw -Domain $domain -Endpoint 'devices' -Data $devices | Out-Null

    $mdResp = Invoke-CAInvGraph -Uri 'deviceManagement/managedDevices?$select=id,azureADDeviceId,deviceName,complianceState,operatingSystem,managementAgent' -ApiVersion 'v1.0' -MaxPages 100
    $intuneAvailable = -not $mdResp.Failed
    $managed = @(if ($intuneAvailable) { @($mdResp.Value) } else { @() })
    if ($intuneAvailable) {
        Write-CAInvRaw -Domain '6.18' -Endpoint 'managedDevices' -Data $managed | Out-Null
        Add-CAInvContextData -Context $script:CAInvContext -Name 'ManagedDevices' -Value $managed
    }

    $devCappedNote = if ($devResp.Capped -or ($intuneAvailable -and $mdResp.Capped)) { ' (page limit reached on at least one of the two; possibly incomplete)' } else { '' }

    $intuneText = if ($intuneAvailable) { "$($managed.Count)" } else { "unknown (could not be read: $($mdResp.ErrorMessage))" }
    New-CAInvRecord -Domain $domain -CheckId 'Device-01' -ObjectType 'Device' `
        -Property 'devicePopulation' `
        -ObservedValue "$($devices.Count) Entra devices; Intune-devices=$intuneText$devCappedNote" `
        -Status ($(if ($intuneAvailable) { 'Ready' } else { 'Review required' })) `
        -ManualReview:(-not $intuneAvailable) `
        -GraphSource 'GET /devices' | Out-Null

    Write-CAInvLog -Level 'INFO' -Domain $domain -Message "$($devices.Count) Entra devices; $($managed.Count) Intune managed devices (available=$intuneAvailable)."
}
