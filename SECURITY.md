# Security policy

These hooks exist to refuse unsafe agent actions, so a way past them is exactly the report I want.

## Reporting

Use **[Report a vulnerability](https://github.com/andreybuilt/agent-guardrails/security/advisories/new)**
on this repository. It opens a private advisory that only the maintainer can see. Please do not open a
public issue for a bypass that is not already listed.

A useful report carries:

- the hook, and the exact command or tool input;
- what the hook decided, and what it should have decided;
- whether the command actually does something harmful, or only looks like it could.

## What counts

| Severity | Shape |
|---|---|
| Highest | A **wrong ALLOW**: `bash-approver.py` auto-approves a command that writes, deletes, runs code or discloses a secret. This repository treats it as the only unacceptable outcome. |
| High | Any other hook lets through the shape it exists to refuse. |
| Normal | An over-block: a harmless command is denied or asked about. Friction, not a hole, and still worth a report. |

**Already public, no report needed:** everything in the README's
[Known limitations](README.md#known-limitations) table. Those are open by design and published so you
can decide before installing.

## What happens next

This is a one-maintainer project, so responses are best effort. A confirmed bypass is fixed by adding
it to the adversarial battery first, so the failing case exists before the fix does, and then closing
it. The case stays in the battery permanently.

## Supported versions

Only the latest release and `main` receive fixes.
