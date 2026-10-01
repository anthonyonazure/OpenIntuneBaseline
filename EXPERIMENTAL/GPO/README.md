# Experimental: Intune policy to Group Policy scripts

These 11 scripts come from [ogdjohnson1998's fork](https://github.com/ogdjohnson1998/OpenIntuneBaseline/tree/feature/gpo-script-generation-part1). An AI coding agent generated them. Each script reads one OIB policy export and tries to create an equivalent Group Policy Object.

**Status: not tested, not supported. Read a script before you run it.**

What to know before you use them:

- They were written against OIB v3.x policy exports. Four of them target the v3.1 compliance policies, which no longer exist under those names in v4.0.
- Many Intune settings have no Group Policy registry equivalent. The scripts print a warning for each setting they cannot map. Password length, complexity, and history are examples: those are domain or local security policy settings, not registry values.
- Compliance policies report state. They do not configure a device. A GPO built from a compliance policy is an approximation at best.
- They need the `GroupPolicy` PowerShell module and a domain-joined Windows machine.

Changes made in this fork:

- Moved out of `WINDOWS/IntuneManagement/` so that the policy folders contain policy exports only.
- Fixed four string-formatting syntax errors in the ASR Audit Mode and Defender AV Configuration scripts. Before the fix those two scripts did not parse.
