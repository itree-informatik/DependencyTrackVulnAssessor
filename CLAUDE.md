# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Type

Standalone .NET CLI tool (`dtrack-assessor`) — **not** part of the ItreeBlazor family under `C:\repos\`. The parent `C:\repos\CLAUDE.md` (Blazor WASM, Telerik, etc.) does **not** apply here, even though the target framework (`net10.0`) and solution format (`.slnx`) are the same. This repo is intentionally minimal: a single exe, flat file structure in the repo root (no `src/`), no ASP.NET building blocks.

## Build and Run

```powershell
dotnet restore DependencyTrackVulnAssessor.slnx
dotnet build DependencyTrackVulnAssessor.slnx -c Release

# Directly from the repo
dotnet run -- export
dotnet run -- apply --dry-run
dotnet run -- apply path/to/assessed.csv

# Single-file publish (runtime required on target machine)
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
# Output: bin/Release/net10.0/win-x64/publish/dtrack-assessor.exe
```

Tests: none in the repo yet. The README calls out `ApplyCommand.LoadCsv`, `ApplyCommand.ParseBool`, and `ExportCommand.WriteTemplate` as the parts that can be tested in isolation.

## Runtime Configuration

`AppConfig.Load` (`Config.cs`) layers configuration in two steps:

1. **`appsettings.json`** — empty template in the repo, documents the schema (`DependencyTrack:Url|ApiKey|VerifySsl`). The loader walks upward if `BaseDirectory` points into `bin/.../` during `dotnet run`.
2. **.NET User Secrets** (`AddUserSecrets<AppConfig>(optional: true)`) — per dev machine, addressed by `<UserSecretsId>` in the `.csproj`. Physically stored at `%APPDATA%\Microsoft\UserSecrets\<id>\secrets.json` (Windows). Never copied to the build output — automatically dev-only.

Values are set via `dotnet user-secrets set "DependencyTrack:ApiKey" "..."`. Do not edit the JSON directly — the tool handles folder creation and path resolution.

**Override order:** the environment variables `DT_URL`, `DT_API_KEY`, `DT_VERIFY_SSL` override JSON and user-secret values. This is required for CI/pipelines and published builds where the `dotnet user-secrets` tool is not available. The env vars use a flat key space (`DT_URL`) rather than the section path (`DependencyTrack__Url`) — the mapping happens manually in `Config.cs:Pick`, not via `AddEnvironmentVariables`.

## Architecture — The Essentials

Four main files in the root, loosely connected through `static` entry points. No DI, no logging framework, no ASP.NET pieces — a deliberate design choice so the result is a single exe.

```
Program.cs            CLI dispatch: "export" | "apply"
  ├─> ExportCommand   reads DT, deduplicates, writes CSV template + raw JSON dump
  └─> ApplyCommand    reads assessed CSV, builds an index of all DT findings, writes PUT /api/v1/analysis

DTrackClient          HttpClient wrapper, pagination via X-Total-Count, X-Api-Key header
Models.cs             all DTOs plus internal aggregation and CSV types in one file
```

### Central Invariant: `FindingKey`

`FindingKey` (`Models.cs`) = `(VulnSource, VulnId, ComponentName)` — **deliberately without version**. Background: the same system component (musl, openssl, glibc, …) carries different patch versions across projects depending on base-image age (e.g. AVG2 on Alpine 3.23.3 ships `musl 1.2.5-r21`, ProForm on Alpine 3.23.4 ships `1.2.5-r23`). If the version were part of the key, a single triage decision would split into multiple CSV rows and the source-of-truth idea would break. Therefore one CSV row matches every project with the same vuln+component regardless of the concrete version. The `ComponentVersion` and `ComponentPurl` columns in the CSV template are documentary (joined with `|`).

**If you change the schema**, `MakeKey` in `ExportCommand` and the key construction in `ApplyCommand.BuildFindingIndexAsync` must be updated in lockstep, otherwise older CSVs stop matching.

### CSV Contract

- Separator `;`, UTF-8 **with BOM** (Excel compatible, see `ExportCommand.WriteTemplate`).
- Column names exactly as in `CsvTemplateRow`. `ApplyCommand.LoadCsv` accepts both PascalCase (`VulnSource`) and snake_case (`vuln_source`) as a header fallback — when extending, offer both variants so older CSVs do not break.
- `Suppress` values are parsed leniently by `ApplyCommand.ParseBool`: `yes/y/ja/j/true/1/x` → true, `no/n/nein/false/0` → false, anything else → null = the row is ignored (unless a comment is set).

### Apply Idempotency

`ApplyCommand.ApplyRowAsync` (`ApplyCommand.cs:238`) skips when `m.CurrentSuppressed == targetSuppressed` **and** the comment is already contained as a substring in the DT comment field. If you touch the idempotency check, keep in mind: DT comments are an append-only history, which is why `Contains` is used instead of equality.

### Analysis State Handling

The `AnalysisState` column in the CSV lets the user pin the DT analysis state explicitly (`NOT_AFFECTED`, `FALSE_POSITIVE`, `EXPLOITABLE`, `IN_TRIAGE`, `RESOLVED`, `NOT_SET`). `ApplyCommand.ParseAnalysisState` accepts lowercase, spaces, hyphens, and a few aliases (`fp` → `FALSE_POSITIVE`, `na` → `NOT_AFFECTED`, `falsepositiv` / `nicht_betroffen` / `ausnutzbar` / `in_pruefung` / `behoben`). Unknown values produce a warning and are treated as empty (= old default logic kicks in).

If the column is empty, the legacy convention applies: `NOT_AFFECTED` on suppress, otherwise the current DT state if set, else `IN_TRIAGE` (`ApplyCommand.cs` defaults `DefaultSuppressState` / `DefaultUnsuppressState`). This is a convention of this tool — not an official DT mapping. Older CSVs without the column continue to work unchanged.

The idempotency check in `ApplyRowAsync` compares suppress flag **and** state **and** comment — touching one of the three forces a PUT.

### Comment Pre-Fill (N+1 Detail Calls)

The findings endpoint (`GET /api/v1/finding/project/{uuid}`) always returns `analysis.comment` as `null` — the comment history is only available via the separate endpoint `GET /api/v1/analysis?project=…&component=…&vulnerability=…`. Therefore `ExportCommand` issues one extra detail call per finding **only** when the finding already has an analysis (`IsSuppressed == true` or `State != null`), keeping the overhead bounded. `Task.Delay(50)` per detail call rate-limits the extra traffic.

DT mixes automatic markers into the comment history (`Suppressed`, `Unsuppressed`, `Analysis: NOT_SET → NOT_AFFECTED`, `Severity: HIGH → CRITICAL`). `ExportCommand.IsAutoMarker` filters them out (single-line, contains `→` and `:`, or equals `Suppressed`/`Unsuppressed`). The latest remaining entry by `timestamp` is pre-filled into the `Comment` column. This includes prior comments written by the tool itself (commenter `VulnerabilityAssessor` in the user's setup) — that's intentional and gives a clean round-trip: export → CSV → apply → export.

## Conventions

- German CLI output and comments, German domain terms (Bewertung = assessment, Projekt = project, Findings).
- Nullable reference types enabled (`<Nullable>enable</Nullable>`).
- No async streams / IAsyncEnumerable — `await client.GetFindingsAsync(...)` loads everything per project into memory because the DT findings endpoint itself is not paginated.
- `Task.Delay(50)` between project requests is intentional rate limiting for the DT server.

## Read-Only Artifacts

`vulnerabilities_template.csv`, `vulnerabilities_assessed.csv`, and `exports/` are generated and in `.gitignore`. Never commit them. The API key lives in .NET User Secrets (`%APPDATA%\Microsoft\UserSecrets\<UserSecretsId>\secrets.json`) — outside the repo, so it cannot be committed accidentally.
