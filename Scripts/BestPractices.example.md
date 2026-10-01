# Best practices (example)

This is an example rules file for `Invoke-OIBAudit.ps1 -Mode BestPractices`. Copy it to a place outside this repo and edit the two tables. The tool reads only the tables. All other text is for you.

How the tool reads a row:

- **Policy** names one or more baseline policies. Use the full name, a `*` wildcard, or a few words that all appear in the name. The version at the end of a name is optional.
- **Decision** is `Keep` (must be deployed), `Change` (deployed, with your setting rows below), `Skip` (must not be deployed), or `Add` (a policy of your own that is not part of OIB).
- **Setting** is the friendly name of a setting. Run `./Scripts/Invoke-OIBAudit.ps1 -ListSettings '<policy>'` to get rows with the exact names.
- **Must be** is `On`, `Off`, a number, a comparison such as `>= 1800`, the name of an option, or `Not set`.
- **Level** is `Fail`, `Warn`, or `Info`. It is the result the rule gets when the target does not meet it.
- **Reason** is for you and for the report. Write why the rule exists.

A row the tool cannot match to a real policy or setting is reported as `NotUnderstood`. It is never counted as a pass.

## Policies

| Policy | Decision | Reason |
| --- | --- | --- |
| Defender Antivirus | Skip | Example: the client uses a third-party EDR |
| WUfB | Skip | Example: the RMM does the patching |
| BitLocker (OS Disk) | Keep | |
| Edge Password Management | Change | Example: see the setting row below |
| Contoso - Company Wi-Fi | Add | Example: a policy of our own |

## Settings

| Policy | Setting | Must be | Level | Reason |
| --- | --- | --- | --- | --- |
| Edge Password Management | Enable saving passwords to the password manager (User) | Off | Fail | Example: we deploy a separate password manager |
| Power and Device Lock | Unattended Sleep Timeout Plugged In | >= 1800 | Warn | Example: users complained about a 15 minute sleep |
| Power and Device Lock | Interactive Logon Machine Inactivity Limit | <= 900 | Fail | Example: lock the screen within 15 minutes |
| BitLocker (OS Disk) | Select the encryption method for operating system drives: | XTS-AES 256-bit | Fail | |
| Firewall Configuration | Disable Stealth Mode | False | Warn | |
