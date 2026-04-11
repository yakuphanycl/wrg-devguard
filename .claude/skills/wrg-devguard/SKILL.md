---
name: wrg-devguard
description: Scan a repository for leaked secrets and prompt-policy violations before committing. Use BEFORE any git commit/push/release, or when the user asks "is this safe", "any leaks", "check for secrets", or "scan the repo".
---

# wrg-devguard skill

Run the `wrg-devguard` scanner and report findings. Scope: two classes of
issues — leaked secrets (API keys, tokens, private keys) and prompt-policy
violations (deny-listed patterns, hardcoded system prompts, PII in AI-facing
text).

## When to run

Invoke this skill automatically when any of the following applies:

- User says "commit", "push", "release", "publish", or "ship"
- User asks "is this safe", "any leaks", "scan for secrets", "check the repo"
- User pastes code that contains what looks like credentials or tokens
- Before suggesting any `git commit` command

## Workflow

1. Check if wrg-devguard is installed:
   ```bash
   wrg-devguard --version
   ```
   If the command is missing, install it:
   ```bash
   pip install wrg-devguard
   ```

2. Run the combined check from the repo root and write a JSON report:
   ```bash
   wrg-devguard check --path . --json-out /tmp/wrg-devguard.json
   ```

3. Read `/tmp/wrg-devguard.json`. For each finding, report:
   - `file:line`
   - `severity` (info, warning, error)
   - `rule_id`
   - `message`
   - a short snippet with the secret value replaced by `<redacted>`

4. Decision policy:
   - Any `severity=error` finding → **block the commit** and propose a fix
     (move value to `.env`, use `os.environ["KEY"]`, delete the file,
     rotate the credential).
   - Only `severity=warning` → warn the user, let them decide.
   - No findings → say so in one sentence and continue.

5. Never print the actual secret value. Always redact with `<redacted>`.

## Optional: stricter profile for release audits

For release or pre-publish checks, use the strict profile:

```bash
wrg-devguard check --path . --profile strict --fail-on warning --json-out /tmp/wrg-devguard.json
```

## Allowlist

If the user maintains `.wrg/allowlist.json`, pass it explicitly:

```bash
wrg-devguard check --path . --allowlist .wrg/allowlist.json --json-out /tmp/wrg-devguard.json
```

## Exit codes

- `0` — clean (no findings above threshold)
- `1` — findings at or above `--fail-on` threshold
- `2` — config or input error (not a scan failure)

## Do not

- Do not install `wrg-devguard` inside a dry-run. Only when actually scanning.
- Do not echo real secret values. Always redact.
- Do not override the user's existing `.wrg/policy.json` — read it, use it.
- Do not suggest `git commit --no-verify` to bypass findings. Fix them first.
