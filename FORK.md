# About this fork

This is a fork of [SkipToTheEndpoint/OpenIntuneBaseline](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline). The baseline itself is James Robinson's work. Read the main [README](README.md) first.

The fork does one thing so far: it collects community work that was offered to the original project and is still waiting, or that lives only in other forks. The base is upstream v4.0 (2026-09-30).

## What is merged on `main`

| From | What it does | Upstream PR | Notes |
|---|---|---|---|
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
|---|---|---|---|
| [`macos-v2.1-beta`](../../tree/macos-v2.1-beta) | [EspenJoensson](https://github.com/EspenJoensson) | A proposed macOS v2.1 on top of the upstream macOS v2.0 beta: closer to the CIS recommendations, a new Apple Intelligence policy, a new Energy Saver policy, and the firewall and Gatekeeper policies split apart. | [#224](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/pull/224) |

It is a separate branch because upstream keeps the macOS v2.0 beta on its own branch. `main` still carries macOS v1.0. Merging the beta into `main` would put three macOS generations side by side.

## What is not carried, and why

| From | Change | Reason |
|---|---|---|
| [MikkelLundKnudsen](https://github.com/MikkelLundKnudsen) | Renames the Delivery Optimisation policy file to the American spelling ([#248](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/pull/248)). | The change renames the file only. The policy name inside the file and the v4.0 `PolicyManifest.json` entry keep the original spelling, so `Update-OIBManifest.ps1 -Mode Validate` fails. |
| [0xAnalyst](https://github.com/0xAnalyst) | Changes the list of file types that open in Notepad in the Script File Associations policy ([#84](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/pull/84)). | It adds `.chm`, `.diff`, `.iqy`, `.iso`, `.msc`, `.prn`, `.rdg`, `.scr`, `.slk`, `.url` and removes `.vbs`, `.wsf`, `.wsh`. Sending `.url`, `.iso`, and `.msc` to Notepad breaks shortcuts, disk images, and admin consoles for users. Removing the three script types weakens the policy. It was also written against v3.4. |

## How to check the fork

```
pip install -r tests/requirements.txt
pytest tests/
pwsh -File Scripts/Update-OIBManifest.ps1 -Mode Validate -Platform All
```

Both pass on `main`.

## License

GPL v3, the same as upstream. Each merged contribution keeps its author in the commit history.
