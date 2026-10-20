# CAInventory

A read-only, pre-implementation inventory of Microsoft Entra ID and Conditional Access.

Not "is my tenant compliant right now?", but the question before that: can this tenant take the
planned Conditional Access rollout?

It changes nothing and enforces nothing. It measures, and when it cannot measure something, it says
so instead of guessing. That is the whole point. A control you could not check is not a control that
passed.

For usage and every parameter, see **[How-To-Use.md](How-To-Use.md)**.

## Quick start

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module Az.Accounts -Scope CurrentUser   # optional, but you want it for the full log window

Import-Module ./CAInventory/CAInventory.psd1 -Force

Connect-CAInv -TenantId 'contoso.onmicrosoft.com'
Invoke-CAInventory -TenantId 'contoso.onmicrosoft.com' -Layer All -OutputPath ./output
```

When the run finishes, open `output/<timestamp>/reports/report.html`. It is one file. Everything is
behind tabs, in the order you would walk through them.

Leave out `-Layer` on an interactive run and you get a menu of topics instead, such as Conditional
Access or Break the glass. [Details here](How-To-Use.md#invoke-cainventory).

## Parameters at a glance

Both exported functions are documented in full in [How-To-Use.md](How-To-Use.md). The parameters
fall into these groups:

| Category | Parameters | Where to read more |
|---|---|---|
| Connection | `-TenantId`, `-AuthMode`, `-ClientId`, `-CertificateThumbprint`, `-Scopes`, `-SkipConnect`, `-SkipAzure`, `-IncludeExchange`, `-Environment` | [Connect-CAInv](How-To-Use.md#connect-cainv), [Invoke-CAInventory](How-To-Use.md#invoke-cainventory) |
| Scope of the run | `-Layer` | [Parameters by category](How-To-Use.md#parameters-by-category) |
| Log window | `-LookbackDays`, `-MaxLookbackDays`, `-PrimaryWorkspaceId` | [Invoke-CAInventory](How-To-Use.md#invoke-cainventory) |
| Break-glass accounts | `-EmergencyAccountUpn`, `-EmergencyAccountId` | [Invoke-CAInventory](How-To-Use.md#invoke-cainventory) |
| Output and branding | `-OutputPath`, `-BrandFile` | [Invoke-CAInventory](How-To-Use.md#invoke-cainventory) |
| Sensitive data | `-IncludeSensitiveMethodDetails` | [Invoke-CAInventory](How-To-Use.md#invoke-cainventory) |

Scheduled and CI runs use `-AuthMode AppOnly` with a certificate, so nothing waits for a prompt.
See [Invoke-CAInventory](How-To-Use.md#invoke-cainventory).

To brand the report, copy `brand.example.json`, edit the copy, and pass it with `-BrandFile`.

## Requirements

- PowerShell 7.2 or later.
- `Microsoft.Graph` (install the package). The module loads only its `Microsoft.Graph.Authentication`
  submodule at runtime. The other Graph calls are raw REST requests, so no other Graph submodule is
  needed. Installing `Microsoft.Graph.Authentication` on its own also works.
- `Az.Accounts` (recommended). With it, CAInventory also signs in to Azure. That feeds the log window
  and the usage axis of the method matrix. Without it, those checks report `Not assessed`.
- Optional: `ExchangeOnlineManagement` (for the Exchange checks, via `-IncludeExchange`) and
  `ImportExcel` (for the xlsx findings register; without it you get CSV).

Permissions: an interactive user with **Global Reader** and **Security Reader** is enough for a full
read-only run. The Log Analytics checks also need **Log Analytics Reader** or **Monitoring Reader** on
the workspace. Graph scopes alone are not enough there.

A missing module, scope or context does not stop the run. The affected checks become `Not assessed`
with a reason. That is an outcome, not an error. See [Troubleshooting](How-To-Use.md#troubleshooting).

## Results

Every finding gets one of four statuses: **Ready**, **Gap**, **Review required** or **Not assessed**.
Only `Ready` counts toward the scorecard. Why the last two are not `Ready` is in the
[status model](How-To-Use.md#status-model).

Each run produces a readiness scorecard, a review queue, an MFA method report, a rollout order, a
printable report and a findings register. The raw Graph responses are kept with a SHA256 hash next to
them, so every finding can be traced back to the response it came from. The full list of files is in
[Output](How-To-Use.md#output).

> The output folder contains tenant evidence: users, policies and raw Graph responses. Treat it as
> confidential. Do not commit it to a repository, and do not share it without a reason.

## Repository layout

| Path | Contents |
|---|---|
| `CAInventory/CAInventory.psd1` / `.psm1` | Module manifest and loader. Import the `.psd1`. |
| `CAInventory/Public/` | The two exported functions: `Connect-CAInv` and `Invoke-CAInventory`. |
| `CAInventory/Private/` | Internal code: collectors per layer, the shared framework, report generators and integrity checks. |
| `CAInventory/config/` | Check catalog, sections, categories, license mapping and rollout waves, as JSON. |
| `brand.example.json` | Example brand file for the report. |
| `How-To-Use.md` | The full usage and parameter reference. |

Do not move or rename anything inside `CAInventory/`. The loader reads the folder structure.

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Joel Prins.
