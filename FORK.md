# About this fork

This is a fork of [SkipToTheEndpoint/OpenIntuneBaseline](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline). The baseline itself is James Robinson's work. Read the main [README](README.md) first.

The fork does two things:

1. It collects community work that was offered to the original project and is still waiting, or that lives only in other forks.
2. It adds an audit tool, [`Scripts/Invoke-OIBAudit.ps1`](#the-audit-tool), that compares a tenant with the baseline and with rules that you write. It is read-only.

The base is upstream v4.0 (2026-09-30).

## What is merged on `main`

| From | What it does | Upstream PR | Notes |
| --- | --- | --- | --- |
| [royklo](https://github.com/royklo) | macOS OneDrive: removes the deprecated "Open at login" setting, which has done nothing since sync app 24.113, and adds a script that uses OneDrive's own login item command. | [#231](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/pull/231) | Known Folder Move policy becomes v1.1. |
| [robm82](https://github.com/robm82) | macOS FileVault: adds the Defer setting that Intune needs to turn encryption on. | [#210](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/pull/210) | FileVault policy becomes v1.1 (NativeImport copy only). |
| [ee61re](https://github.com/ee61re) | Renames `Trigger-PosstOOBEUpdates.ps1` to `Trigger-PostOOBEUpdates.ps1` and updates the Scripts readme. | [#230](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/pull/230) | |
| [ShocOne](https://github.com/ShocOne) | The two Windows 365 policies as Terraform, for the `deploymenttheory/microsoft365` provider. | [#113](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/pull/113) | In `WINDOWS365/Terraform/`. Passes `terraform fmt`. Not applied to a tenant by this fork. |
| [MadCrabCyder](https://github.com/MadCrabCyder) | `Disable-Services.ps1`: disables the Windows services that the CIS benchmark lists, with Level 1 and Level 2 switches and an exclusion list. | [#108](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/pull/108) | Optional. See the caution below. |
| [murtazaraj786](https://github.com/murtazaraj786) | A pytest suite that checks every policy export: valid JSON, correct encoding, naming convention, no duplicate names or IDs. Runs on each push. | none | In `tests/`. Updated here for v4.0. 849 checks pass. |
| [ogdjohnson1998](https://github.com/ogdjohnson1998) | Scripts that try to convert Intune policies to Group Policy. | none | Experimental. Moved to [`EXPERIMENTAL/GPO/`](EXPERIMENTAL/GPO/README.md). |

### Caution on `Disable-Services.ps1`

The upstream author chose not to merge this script. His reasons, from PR #108: the baseline already mitigates most of these services by policy, and he disagrees with the CIS on some of them. A reviewer also reported that disabling `WpnService` (Windows Push Notifications) degrades Intune remote actions and Autopatch. This fork adds `WpnService` to the default exclusion list. Level 2 is off by default.

## What is on a separate branch

| Branch | From | What it is | Upstream PR |
| --- | --- | --- | --- |
| [`macos-v2.1-beta`](../../tree/macos-v2.1-beta) | [EspenJoensson](https://github.com/EspenJoensson) | A proposed macOS v2.1 on top of the upstream macOS v2.0 beta: closer to the CIS recommendations, a new Apple Intelligence policy, a new Energy Saver policy, and the firewall and Gatekeeper policies split apart. | [#224](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/pull/224) |

It is a separate branch because upstream keeps the macOS v2.0 beta on its own branch. `main` still carries macOS v1.0. Merging the beta into `main` would put three macOS generations side by side.

## What is not carried, and why

| From | Change | Reason |
| --- | --- | --- |
| [MikkelLundKnudsen](https://github.com/MikkelLundKnudsen) | Renames the Delivery Optimisation policy file to the American spelling ([#248](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/pull/248)). | The change renames the file only. The policy name inside the file and the v4.0 `PolicyManifest.json` entry keep the original spelling, so `Update-OIBManifest.ps1 -Mode Validate` fails. |
| [0xAnalyst](https://github.com/0xAnalyst) | Changes the list of file types that open in Notepad in the Script File Associations policy ([#84](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/pull/84)). | It adds `.chm`, `.diff`, `.iqy`, `.iso`, `.msc`, `.prn`, `.rdg`, `.scr`, `.slk`, `.url` and removes `.vbs`, `.wsf`, `.wsh`. Sending `.url`, `.iso`, and `.msc` to Notepad breaks shortcuts, disk images, and admin consoles for users. Removing the three script types weakens the policy. It was also written against v3.4. |

## The audit tool

`Scripts/Invoke-OIBAudit.ps1` needs PowerShell 7 and nothing else. It does not use the Microsoft Graph PowerShell modules.

| Mode | What it does |
| --- | --- |
| `ReadOnly` (default) | Reads the Intune policies of a tenant. Lists which baseline policies are present, older, or absent. Can save a snapshot to a folder outside the repo. |
| `DiffOnly` | Reports the differences, setting by setting, between the baseline and a tenant, a saved snapshot, or another version of the baseline. Changes nothing. |
| `BestPractices` | Checks the baseline, a tenant, or a snapshot against rules that you write in a Markdown table. See [`Scripts/BestPractices.example.md`](Scripts/BestPractices.example.md). |
| `Deploy` | Off by default. Needs `-AllowWrite` and `-ConfirmTenant <the tenant's domain>`. Version 0.1.0 shows what a deployment would create and stops. It does not write. |

### How read-only is enforced

Every request to Microsoft Graph goes through one function. That function refuses any request that is not a `GET`. The report states how many requests were sent and of what kind. No code path in version 0.1.0 opens the gate. Give the tool an app registration that has only read permissions and the tenant enforces the same limit a second time.

Permissions: `DeviceManagementConfiguration.Read.All` is required. `Organization.Read.All` adds the tenant name. `DeviceManagementApps.Read.All` adds the BYOD app protection policies. A policy type that cannot be read is reported as `Unknown`. It is never reported as absent.

### Examples

```powershell
# What changed between two versions of the baseline. No tenant, no sign-in.
pwsh Scripts/Invoke-OIBAudit.ps1 -Mode DiffOnly -CompareRef windows-v3.8 -Platform Windows

# Read a tenant and keep a snapshot. Later runs can use the snapshot with no sign-in.
$env:OIB_TENANT_ID = '...'; $env:OIB_CLIENT_ID = '...'; $env:OIB_CLIENT_SECRET = '...'
pwsh Scripts/Invoke-OIBAudit.ps1 -Mode ReadOnly -SaveSnapshot ~/oib-snapshots/contoso

# Differences between the baseline and that tenant.
pwsh Scripts/Invoke-OIBAudit.ps1 -Mode DiffOnly -SnapshotPath ~/oib-snapshots/contoso -OutFile report.md -OutJson report.json

# Your own rules. Start from a generated file, or from the example.
pwsh Scripts/Invoke-OIBAudit.ps1 -Mode BestPractices -NewRulesFile ~/my-rules.md
pwsh Scripts/Invoke-OIBAudit.ps1 -ListSettings 'Edge Password Management'
pwsh Scripts/Invoke-OIBAudit.ps1 -Mode BestPractices -Rules ~/my-rules.md -SnapshotPath ~/oib-snapshots/contoso
```

### What to know

- **How a tenant policy is matched to a baseline policy.** First by the `OIBID` in the policy description (v4.0 adds it), then by name, then by the name without its version, then by the baseline name inside a longer name (a customer prefix, for example).
- **When a baseline policy is absent,** the report says how many of its settings another policy in the tenant already sets, and lists the ones set to a different value.
- **A rule that the tool cannot match** to a real policy or setting is reported as `NotUnderstood`. It is never counted as a pass.
- **With no tenant and no snapshot,** `BestPractices` compares your rules with the baseline. That shows where your standard differs from OIB.
- **Friendly setting names** come from `Scripts/OIBAudit.SettingNames.json`. Run the tool with `-RefreshSettingNames` after the baseline gains settings.
- **Exit codes:** 0 = no differences and no failed rules. 1 = differences, or a rule failed or was not understood. 2 = refused. 3 = Deploy stopped before writing.
- **Keep tenant data and your own rules file out of this repo.** It is public. The tool refuses to save a snapshot inside the repo.

Limits of version 0.1.0: Settings Catalog and Endpoint Security policies are compared setting by setting. Compliance, device configuration, update ring, and driver policies are compared property by property. Assignments are not compared. Old-style Endpoint Security "intents" are not read.

## How to check the fork

```shell
pip install -r tests/requirements.txt
pytest tests/
pwsh -File Scripts/Update-OIBManifest.ps1 -Mode Validate -Platform All
pwsh -Command "Invoke-Pester tests/Invoke-OIBAudit.Tests.ps1"
```

All three pass on `main`. The pytest suite (from murtazaraj786) checks every policy export for valid JSON in its real encoding, the naming convention, and duplicate names or IDs. The Pester suite checks the audit tool. Neither needs a tenant or a network connection.

## License

GPL v3, the same as upstream. Each merged contribution keeps its author in the commit history.
