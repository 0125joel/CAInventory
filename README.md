# CAInventory

A pre-implementation inventory of Microsoft Entra ID and Conditional Access. It does not answer
"is my tenant compliant right now". It answers the question before that: can this tenant take the
planned Conditional Access rollout?

CAInventory is **read-only**. It changes nothing and enforces nothing. It measures, and it says
honestly when it could not measure.

For how to use it, including every parameter, see **[How-To-Use.md](How-To-Use.md)**.

## Quick start

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module Az.Accounts -Scope CurrentUser   # optional, but needed for the full log window

Import-Module ./CAInventory/CAInventory.psd1 -Force

Connect-CAInv -TenantId 'contoso.onmicrosoft.com'
Invoke-CAInventory -TenantId 'contoso.onmicrosoft.com' -Layer All -OutputPath ./output
```

Open `output/<timestamp>/reports/report.html` when the run finishes. It is one file with all report
pages behind tabs.

Leave out `-Layer` on an interactive run and you get a menu of topics instead, such as Conditional
Access or Break the glass. See [Invoke-CAInventory](How-To-Use.md#invoke-cainventory).

## Parameters at a glance

Both exported functions are documented in full in [How-To-Use.md](How-To-Use.md). These are the
parameter categories:

| Category | Parameters | Details |
|---|---|---|
| Connection | `-TenantId`, `-AuthMode`, `-ClientId`, `-CertificateThumbprint`, `-Scopes`, `-SkipConnect`, `-SkipAzure`, `-IncludeExchange`, `-Environment` | [Connect-CAInv](How-To-Use.md#connect-cainv), [Invoke-CAInventory](How-To-Use.md#invoke-cainventory) |
| Scope of the run | `-Layer` | [Parameters by category](How-To-Use.md#parameters-by-category) |
| Log window | `-LookbackDays`, `-MaxLookbackDays`, `-PrimaryWorkspaceId` | [Invoke-CAInventory](How-To-Use.md#invoke-cainventory) |
| Break-glass accounts | `-EmergencyAccountUpn`, `-EmergencyAccountId` | [Invoke-CAInventory](How-To-Use.md#invoke-cainventory) |
| Output and branding | `-OutputPath`, `-BrandFile` | [Invoke-CAInventory](How-To-Use.md#invoke-cainventory) |
| Sensitive data | `-IncludeSensitiveMethodDetails` | [Invoke-CAInventory](How-To-Use.md#invoke-cainventory) |

Unattended runs (a scheduled task or CI job) use `-AuthMode AppOnly` with a certificate. See
[Unattended runs](How-To-Use.md#invoke-cainventory).

To brand the report, copy `brand.example.json`, edit the copy, and pass it with `-BrandFile`.

## Requirements

- PowerShell 7.2 or later.
- `Microsoft.Graph` (required). Only `Microsoft.Graph.Authentication` is needed. The other Graph
  calls run as raw REST requests.
- `Az.Accounts` (recommended). With it, CAInventory also signs in to Azure. That context feeds the
  log window and the usage axis of the method matrix. Without it, those checks are `Not assessed`.
- Optional: `ExchangeOnlineManagement` (for Exchange checks, via `-IncludeExchange`) and `ImportExcel`
  (for the xlsx findings register; without it, the register falls back to CSV).

Permissions: an interactive user with **Global Reader** and **Security Reader** is enough for a full
read-only run. The Log Analytics checks also need **Log Analytics Reader** or **Monitoring Reader** on
the workspace. Graph scopes alone are not enough there.

If a module, scope or context is missing, the run does not stop. The affected checks become
`Not assessed`, with a reason. That is an outcome, not an error. See
[Troubleshooting](How-To-Use.md#troubleshooting).

## Results

Every finding gets one of four statuses: **Ready**, **Gap**, **Review required** or **Not assessed**.
Only `Ready` counts toward the scorecard. Details are in the [status model](How-To-Use.md#status-model).

Each run writes a readiness scorecard, a review queue, an MFA method report, a rollout order, a
printable report, and a findings register. Each run also keeps the raw Graph responses with a SHA256
hash, so every finding can be traced. The full output list is in [Output](How-To-Use.md#output).

> The output folder contains tenant evidence: users, policies and raw Graph responses. Treat it as
> confidential. Do not commit it to a repository, and do not share it without a reason.

## Repository layout

| Path | Contents |
|---|---|
| `CAInventory/CAInventory.psd1` / `.psm1` | Module manifest and loader. Import the `.psd1`. |
| `CAInventory/Public/` | The two exported functions: `Connect-CAInv` and `Invoke-CAInventory`. |
| `CAInventory/Private/` | Internal code: the collectors per layer, the shared framework, the report generators and the integrity checks. |
| `CAInventory/config/` | Check catalog, sections, categories, license mapping and rollout waves, as JSON. |
| `brand.example.json` | Example brand file for the report. |
| `How-To-Use.md` | The full usage and parameter reference. |

Do not move or rename anything inside `CAInventory/`. The loader reads the folder structure.

## License

No license has been chosen yet. Until one is added, the code is not licensed for reuse.
