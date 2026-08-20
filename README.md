# DependencyTrack Vulnerability Assessor

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A CLI tool that automates recurring vulnerability assessments in [OWASP Dependency-Track](https://dependencytrack.org/). Written for the case where several projects share the same tech stack and assessments are regularly lost after SBOM uploads — instead of manually re-suppressing each CVE in each project, you maintain **one** CSV file and the tool replays your decisions idempotently.

## Table of Contents

- [Workflow](#workflow)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [CSV Format](#csv-format)
- [Architecture](#architecture)
- [Build and Publish](#build-and-publish)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Workflow

```
+-----------------+     +------------------+     +-------------------+
| 1. export       | --> | 2. fill in CSV   | --> | 3. apply          |
| fetches all CVEs|     | suppress + com-  |     | writes assessment |
| from DT         |     | ment in Excel    |     | back to DT        |
+-----------------+     +------------------+     +-------------------+
                                 ^                        |
                                 |                        v
                          Source of Truth          idempotent: can
                          (git-versioned)          run any number of times
```

The CSV becomes your "source of truth". If Dependency-Track loses your assessments again — just run `dtrack-assessor apply`, done.

## Features

- **Deduplicated by CVE + component name**: one row in the CSV applies to every project where the combination appears — regardless of which patch version each project ships. On apply it is automatically rolled out to all matching projects.
- **Idempotent**: findings whose suppress flag, analysis state, and comment already match are skipped.
- **Full analysis state control**: pick `NOT_AFFECTED`, `FALSE_POSITIVE`, `EXPLOITABLE`, `IN_TRIAGE`, `RESOLVED`, or `NOT_SET` via the `AnalysisState` column (with lenient parsing for aliases like `fp`, `na`).
- **Dry run**: `--dry-run` previews what would change.
- **Raw export as JSON**: alongside the CSV, the findings are saved as JSON (backup / debug). Note: reduced to the fields this tool reads (component, vulnerability, analysis) — not the byte-for-byte API response.
- **Excel-friendly CSV**: semicolon-separated, UTF-8 with BOM, opens by double-click.
- **Self-signed certificates**: optionally via `DependencyTrack:VerifySsl=false` in user secrets or `DT_VERIFY_SSL=false` as an env var.

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- Dependency-Track 4.x with the REST API enabled
- An API key with permissions
  - `VIEW_PORTFOLIO`
  - `VIEW_VULNERABILITY`
  - `VULNERABILITY_ANALYSIS`

## Installation

```bash
git clone https://github.com/<your-user>/DependencyTrackVulnAssessor.git
cd DependencyTrackVulnAssessor
dotnet restore
dotnet build -c Release
```

The compiled exe ends up at `bin/Release/net10.0/dtrack-assessor.exe`.

If you want a single-file variant:

```bash
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
```

Or just run it directly from the repo:

```bash
dotnet run -- export
dotnet run -- apply --dry-run
```

## Configuration

The repo ships with an empty `appsettings.json` as a template and to document the schema:

```json
{
  "DependencyTrack": {
    "Url": "",
    "ApiKey": "",
    "VerifySsl": true
  }
}
```

The real values (in particular the API key) do **not** belong in the repo. They live in [.NET User Secrets](https://learn.microsoft.com/aspnet/core/security/app-secrets), a JSON file addressed per project ID under `%APPDATA%\Microsoft\UserSecrets\<UserSecretsId>\secrets.json` (Windows) or `~/.microsoft/usersecrets/<UserSecretsId>/secrets.json` (Linux/macOS). Manage them with the SDK tool:

```bash
dotnet user-secrets set "DependencyTrack:Url"    "https://dependencytrack.example.com"
dotnet user-secrets set "DependencyTrack:ApiKey" "odt_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
# Optional:
dotnet user-secrets set "DependencyTrack:VerifySsl" "false"

# Inspect / clean up:
dotnet user-secrets list
dotnet user-secrets remove "DependencyTrack:ApiKey"
```

The `UserSecretsId` is pinned in the `.csproj` — all devs point at the same (local) store. Because user secrets are never copied into the build output, they are cleanly dev-only.

Alternatively (e.g. for CI / pipelines / published builds without the SDK) you can set `DT_URL`, `DT_API_KEY`, and `DT_VERIFY_SSL` as environment variables — they override values from appsettings.json or user secrets.

### Creating an API Key in Dependency-Track

1. **Administration -> Access Management -> Teams**
2. Create a new team (e.g. `Vulnerability-Automation`) or use an existing one
3. Assign permissions: `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`, `VULNERABILITY_ANALYSIS`
4. Optionally restrict the team to specific projects
5. Under **API Keys**, click the plus icon and copy the key — it is shown only once

## Usage

### Export Vulnerabilities

```bash
dtrack-assessor export
# or with custom paths
dtrack-assessor export --out my_template.csv --raw exports/dump.json
```

Produces `vulnerabilities_template.csv` with every unique vuln+component combination across all active projects.

### Fill in the CSV

On export, existing DT assessments are pre-filled: as soon as a finding is suppressed in **at least one** project, the row is written with `Suppress=yes` and the most recent DT comment (by timestamp, across all projects) in that cell. `apply` then spreads the assessment across the remaining projects on the next run — projects that are already suppressed are skipped by the idempotency check.

Open in Excel, decide row by row:

- `Suppress = yes` -> the finding is suppressed in every affected project
- `Suppress = no` -> an existing suppression is lifted
- leave all three user columns empty -> the row is ignored

Fill in `AnalysisState` (e.g. `NOT_AFFECTED` or `FALSE_POSITIVE`) and `Comment` with your justification, then save as **`vulnerabilities_assessed.csv`** (Excel: "Save as" -> file type "CSV UTF-8"). A row is applied as soon as any of `Suppress`, `AnalysisState`, or `Comment` is set.

### Write Assessments Back

Dry run first:

```bash
dtrack-assessor apply --dry-run
```

If the output looks right:

```bash
dtrack-assessor apply
```

Optionally pass a different CSV path:

```bash
dtrack-assessor apply path/to/file.csv
```

### What Happens After a "Reset" in DT?

Just run `dtrack-assessor apply` again. The CSV stays untouched and the tool writes all assessments back.

### When a New Project With the Same Stack Joins

Also just run `apply` — the tool automatically finds the vuln+component in the new project and applies the assessment there as well.

### When a New SBOM Delivers New CVEs

1. `dtrack-assessor export` -> a fresh template
2. Merge the contents of your existing CSV into the new one (e.g. with Excel VLOOKUP)
3. `dtrack-assessor apply`

## CSV Format

Separator `;`, UTF-8 with BOM. Columns:

| Column                  | Meaning                                              | Filled by   |
|-------------------------|------------------------------------------------------|-------------|
| `VulnSource`            | Source of the vulnerability (NVD, GITHUB, OSSINDEX …)| Export      |
| `VulnId`                | CVE / GHSA / other ID                                | Export      |
| `Severity`              | CRITICAL/HIGH/MEDIUM/LOW/INFO/UNASSIGNED             | Export      |
| `CvssScore`             | CVSS v3 (falls back to v2)                           | Export      |
| `ComponentName`         | Name of the affected component                       | Export      |
| `ComponentVersion`      | Versions seen across projects (`|`-separated, documentary only — not used for matching) | Export      |
| `ComponentPurl`         | Package URL(s) (`|`-separated if versions differ)    | Export      |
| `Title`                 | Short description                                    | Export      |
| `AffectedProjectsCount` | Number of projects where the finding appears        | Export      |
| `AffectedProjects`      | List of project names (`|`-separated)                | Export      |
| `CurrentlySuppressedIn` | Where it is already suppressed                       | Export      |
| **`Suppress`**          | **`yes` / `no` / empty**                             | **User** (export pre-fills when at least one project is suppressed) |
| **`AnalysisState`**     | **`NOT_AFFECTED`, `FALSE_POSITIVE`, `EXPLOITABLE`, `IN_TRIAGE`, `RESOLVED`, `NOT_SET` (or empty)** | **User** (export carries over the most common existing DT state; case/space/hyphen tolerant — `fp`, `false positive`, `na`, etc. are accepted) |
| **`Comment`**           | **Free-text justification**                          | **User** (export carries over the most recent DT comment by timestamp) |

## Architecture

```
+-----------------+
|   Program.cs    |   CLI routing: export | apply
+--------+--------+
         |
   +-----+-----+--------------------------+
   |           |                          |
   v           v                          v
+--------+ +--------+              +------------+
|Export- | |Apply-  |              |   Config   |  reads appsettings.json + user secrets
|Command | |Command |              +------------+  + DT_* env vars as overrides
+----+---+ +---+----+
     |         |
     +----+----+
          v
   +-------------+      +----------+
   |DTrackClient |----->|   DT API |
   +-------------+      +----------+
          |
          v
   +-------------+
   |   Models    |   DtProject, DtFinding, AnalysisRequest, …
   +-------------+
```

- **DTrackClient** wraps HTTP, pagination, and error handling. Uses `HttpClient` and `System.Text.Json`.
- **ExportCommand** handles dedup and CSV creation (CsvHelper, UTF-8 with BOM).
- **ApplyCommand** builds an in-memory index of all findings, matches CSV rows against it, and calls `PUT /api/v1/analysis` per match.
- **Config** reads `appsettings.json` and .NET User Secrets via `Microsoft.Extensions.Configuration`; env vars (`DT_*`) are explicit overrides.
- No external frameworks for DI / logging — kept deliberately minimal so the tool is a single exe.

## Build and Publish

### Local Release Build

```bash
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
```

Output: `bin/Release/net10.0/win-x64/publish/dtrack-assessor.exe`. Requires the .NET 10 runtime on the target system.

### Standalone (no .NET installed)

```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

The result is larger (~60 MB) but runs without a .NET installation.

### GitHub Actions Sketch

`.github/workflows/build.yml` (not shipped — for inspiration):

```yaml
on: [push, pull_request]
jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with: { dotnet-version: '10.0.x' }
      - run: dotnet build -c Release
      - run: dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
      - uses: actions/upload-artifact@v4
        with:
          name: dtrack-assessor
          path: bin/Release/net10.0/win-x64/publish/dtrack-assessor.exe
```

## Troubleshooting

| Symptom                                              | Likely cause                                                  |
|------------------------------------------------------|---------------------------------------------------------------|
| `HTTP 401`                                           | API key missing or invalid                                    |
| `HTTP 403`                                           | API key is missing one of the three permissions, or the project is not in the team |
| `HTTP 404` at startup                                | `DT_URL` wrong (typo, missing `/api` suffix to adjust)        |
| `No projects found`                                  | The team has no projects assigned, or all are inactive        |
| Mangled umlauts in the CSV                           | Excel saved without UTF-8. On "Save as" pick file type **CSV UTF-8** |
| `Row X not found in DT` on apply                     | The component was replaced by a new SBOM (different version). Re-run export |
| SSL errors with self-signed certs                    | `dotnet user-secrets set "DependencyTrack:VerifySsl" "false"` (or `DT_VERIFY_SSL=false` as an env var) |

## Contributing

Pull requests welcome. Tests are still rudimentary — the logic is well isolated and easy to cover (`ApplyCommand.LoadCsv`, `ApplyCommand.ParseBool`, `ExportCommand.WriteTemplate`).

## License

[MIT](LICENSE)
