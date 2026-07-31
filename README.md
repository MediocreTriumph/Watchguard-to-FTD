# WatchGuard to Cisco FTD Migration Tool

Migrates WatchGuard firewall configurations to Cisco Firepower Management Center (FMC): address/service objects, groups, policies, applications, zones, and users.

## Workflow

The migration is a two-stage pipeline: **parse** the WatchGuard XML export, then **migrate** the parsed JSON into FMC.

```
WatchGuard XML export
        │
        ▼
watchparse-json-v5.py          → watchguard_config_v5_<timestamp>.json
(watchparse-xlsx-v5_4.py       → .xlsx workbook, for human review only)
        │
        ▼
cli.py (dry run)               → migration_plan.json  (review this)
        │
        ▼
cli.py --execute               → objects + ACP rules created in FMC
        │                        migration_report.json
        ▼
audit_migration.py             → policy_audit_report.json  (verify)
```

## Setup

```bash
pip install -r requirements.txt
```

Requires Python 3.7+ and network access to the FMC API (port 443).

**Password:** set the `FMC_PASSWORD` environment variable, or omit `--fmc-pass` and you'll be prompted interactively. Avoid passing `--fmc-pass` on the command line — it's visible in shell history and process lists.

## Step 1: Parse the WatchGuard config

Export the config XML from WatchGuard, then:

```bash
# JSON output (input for the migration tool)
python watchparse-json-v5.py config.xml
# → watchguard_config_v5_<timestamp>.json

# Optional: Excel workbook for review (one worksheet per object category,
# plus reference validation). Use v5_4 — it's the latest revision.
python watchparse-xlsx-v5_4.py config.xml
```

## Step 2: Dry run

Dry run is the default. It connects to FMC, discovers existing objects, classifies policies, builds the full plan, and writes `migration_plan.json` — but creates nothing.

**Policy classification:** WatchGuard management-plane policies (Web UI, cert portal, Ping To Firebox, anything to/from the Firebox itself) and built-in default-deny rules (Unhandled Internal/External Packet) are skipped by default — FTD handles those outside the ACP. Each skip is listed in the output and in the plan file with a reason. Use `--include-management` to migrate them anyway.

**The plan file is executable.** `migration_plan.json` contains everything needed to run the migration. Review it, hand-edit it if you like (e.g. delete a rule from `policies_to_create`), then execute it directly — no re-planning:

```bash
python cli.py --from-plan migration_plan.json                    # validate (offline)
python cli.py --from-plan migration_plan.json --execute \
    --fmc-host <ip> --fmc-user admin --new-acp "Migrated-WG-Policy"
```

```bash
export FMC_PASSWORD='...'
python cli.py watchguard_config_v5_<timestamp>.json \
    --fmc-host 192.168.255.122 \
    --fmc-user admin \
    --no-verify-ssl
```

Review `migration_plan.json` before executing — especially `warnings`, `errors`, and the application/user mapping sections.

## Step 3: Execute

```bash
# Into a NEW Access Control Policy
python cli.py <parsed>.json --fmc-host <ip> --fmc-user admin \
    --no-verify-ssl --execute --new-acp "Migrated-WG-Policy"

# Into an EXISTING ACP
python cli.py <parsed>.json --fmc-host <ip> --fmc-user admin \
    --no-verify-ssl --execute --existing-acp "My-Existing-Policy"
```

### Optional flags

| Flag | Purpose |
|---|---|
| `--enable-zones` | Map WatchGuard interfaces to FMC security zones. The zones must already exist in FMC; mapping is disabled with a warning otherwise. |
| `--zone-inside <name>` | FMC zone for internal/RFC1918 networks (default `INSIDE`). |
| `--zone-outside <name>` | FMC zone for external/public networks (default `OUTSIDE`). |
| `--fmc-pass <pw>` | FMC password. Prefer `FMC_PASSWORD` env var or the interactive prompt. |
| `--include-management` | Also migrate management-plane and default-deny policies (skipped by default). |
| `--from-plan <file>` | Execute a saved (optionally hand-edited) plan file instead of re-planning. Without `--execute`, validates the file offline. |
| `--enable-users` | Map WatchGuard user aliases to FMC realm users. Requires an identity realm configured in FMC. |
| `--user-confidence <0-1>` | User match threshold (default 0.85). |
| `--app-confidence <0-1>` | Application match threshold (default 0.85). |
| `--app-mappings <file>` | Manual WatchGuard→FMC application name mappings. A starter file is included: `application_mappings.json`. |
| `--no-verify-ssl` | Skip cert verification (self-signed FMC certs). |

Manual app mappings format:

```json
{
  "mappings": {
    "Outlook.com": "Outlook",
    "iTunes/App Store": "iTunes"
  }
}
```

## Step 4: Audit

Compares WatchGuard policies against the migrated ACP and reports missing/incomplete rules:

```bash
python audit_migration.py <parsed>.json \
    --fmc-host <ip> --fmc-user admin \
    --acp-name "Migrated-WG-Policy" --no-verify-ssl
# → policy_audit_report.json
```

## Output files

| File | Produced by | Contents |
|---|---|---|
| `watchguard_config_v5_<ts>.json` | parser | Parsed WatchGuard config (migration input) |
| `watchguard_config_v5_<ts>.xlsx` | xlsx parser | Human-readable workbook with validation sheet |
| `migration_plan.json` | cli.py | Object/policy mappings, warnings, errors, zone/user/app reports |
| `migration_report.json` | executor | Post-execution results and failures |
| `policy_audit_report.json` | audit_migration.py | WatchGuard vs. FMC policy comparison |

## Project structure

```
cli.py                  Migration entry point (parse → discover → map → plan → execute)
audit_migration.py      Standalone post-migration audit
config.py               MigrationConfig dataclass (thresholds, rate limiting, dry-run)
models.py               WatchGuardConfig / FMCObjects data models
watchparse-json-v5.py   XML → JSON parser (migration input)
watchparse-xlsx-v5*.py  XML → Excel parsers (v5_4 is current; older kept as history)
analysis/
  service_mapper.py     WG services → FMC port objects
  app_mapper.py         WG apps → FMC applications (fuzzy + manual mappings)
fmc/
  client.py             FMC REST client (auth, token refresh, pagination)
  discovery.py          Discovers existing FMC objects
  canonical.py          Canonical port mapping (prefers FMC built-ins)
  zones.py              Interface → zone mapping
  user_mapper.py        WG aliases → FMC realm users
migration/
  classifier.py         Tags policies traffic/management-plane/default-deny
  planner.py            Builds the migration plan
  planfile.py           Full-fidelity plan save/load (executable plan files)
  executor.py           Creates objects/rules in FMC
  auditor.py            Policy comparison logic
  reporter.py           Unified error/warning/statistics reporting
tests/                  pytest suite (parser, classifier, plan round-trip)
```

## Running tests

```bash
pip install pytest
python -m pytest tests/
```

## Known quirks

- Rules that were scoped by WatchGuard interface aliases (`Any-Trusted`, `Any-External`, BOVPN/SSLVPN constructs) lose that scoping in FMC — empty source/destination means "any," which is broader than the original. Review these (the audit flags them) until interface-to-zone mapping lands.
- Executing the same plan twice is safe for objects (already-exists is tolerated) but will duplicate rules in the ACP.
