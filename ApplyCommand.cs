using System.Globalization;
using System.Text;
using CsvHelper;
using CsvHelper.Configuration;

namespace DependencyTrackVulnAssessor;

/// <summary>
/// Liest die ausgefuellte CSV und wendet die Suppress-/Comment-Entscheidungen
/// per PUT /api/v1/analysis auf alle betroffenen Projekte an. Idempotent.
/// </summary>
public static class ApplyCommand
{
    private const string DefaultSuppressState = "NOT_AFFECTED";
    private const string DefaultUnsuppressState = "IN_TRIAGE";

    public sealed class AssessedRow
    {
        public int Line { get; init; }
        public string VulnSource { get; init; } = "";
        public string VulnId { get; init; } = "";
        public string ComponentName { get; init; } = "";
        public string ComponentVersion { get; init; } = "";
        public bool? Suppress { get; init; }

        /// <summary>Normalisierter DT-Analysis-State (z.B. NOT_AFFECTED, FALSE_POSITIVE) oder leer.</summary>
        public string AnalysisState { get; init; } = "";

        public string Comment { get; init; } = "";

        public FindingKey Key => new(VulnSource, VulnId, ComponentName);
    }

    public static async Task<int> RunAsync(string csvPath, bool dryRun, CancellationToken ct)
    {
        if (!File.Exists(csvPath))
        {
            Console.Error.WriteLine($"Datei nicht gefunden: {csvPath}");
            return 1;
        }

        AppConfig cfg;
        try { cfg = AppConfig.Load(Directory.GetCurrentDirectory()); }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }

        Console.WriteLine($"CSV: {csvPath}");
        Console.WriteLine($"DT:  {cfg.BaseUrl}");
        if (dryRun) Console.WriteLine("MODUS: DRY-RUN (keine Aenderungen werden geschrieben)\n");
        else Console.WriteLine();

        var rows = LoadCsv(csvPath);
        if (rows.Count == 0)
        {
            Console.Error.WriteLine("Keine bewerteten Zeilen gefunden. Hast du 'suppress' und/oder 'comment' ausgefuellt?");
            return 1;
        }
        Console.WriteLine($"{rows.Count} bewertete Zeilen aus CSV geladen.\n");

        using var client = new DTrackClient(cfg);
        var projects = await client.ListProjectsAsync(ct).ConfigureAwait(false);
        Console.WriteLine($"{projects.Count} Projekte in DT gefunden.\n");

        var index = await BuildFindingIndexAsync(client, projects, ct).ConfigureAwait(false);
        Console.WriteLine($"\n{index.Count} eindeutige Finding-Keys in DT.\n");

        int totalChanged = 0, totalSkipped = 0, totalMissing = 0;

        foreach (var row in rows)
        {
            if (!index.TryGetValue(row.Key, out var matches) || matches.Count == 0)
            {
                Console.WriteLine($"  HINWEIS: Zeile {row.Line} ({row.VulnId} / {row.ComponentName}@{row.ComponentVersion}) nicht in DT gefunden.");
                totalMissing++;
                continue;
            }

            var (changed, skipped) = await ApplyRowAsync(client, row, matches, dryRun, ct).ConfigureAwait(false);
            totalChanged += changed;
            totalSkipped += skipped;
        }

        Console.WriteLine("\n--- Zusammenfassung ---");
        Console.WriteLine($"  Geaendert:                  {totalChanged}");
        Console.WriteLine($"  Schon aktuell (skipped):    {totalSkipped}");
        Console.WriteLine($"  Nicht in DT gefunden:       {totalMissing}");
        if (dryRun) Console.WriteLine("\n(Dry-Run: nichts wurde tatsaechlich geschrieben.)");

        return 0;
    }

    // -----------------------------------------------------------------------
    // CSV-Lesen
    // -----------------------------------------------------------------------

    public static bool? ParseBool(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var v = value.Trim().ToLowerInvariant();
        return v switch
        {
            "yes" or "y" or "ja" or "j" or "true" or "1" or "x" => true,
            "no" or "n" or "nein" or "false" or "0" => false,
            _ => null,
        };
    }

    /// <summary>
    /// Akzeptiert die DT-Analysis-States lose (Case-/Space-/Underscore-tolerant) und normalisiert
    /// auf die offizielle SCREAMING_SNAKE_CASE-Form. Leerer Input -> "".
    /// Ungueltige Eingaben werden gewarnt und auf "" gemappt (= alte Default-Logik greift).
    /// </summary>
    public static string ParseAnalysisState(string? value, int line = 0)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        var v = value.Trim().ToLowerInvariant().Replace(' ', '_').Replace('-', '_');
        var mapped = v switch
        {
            "not_affected" or "na" or "nicht_betroffen" => "NOT_AFFECTED",
            "false_positive" or "fp" or "falsepositiv" => "FALSE_POSITIVE",
            "exploitable" or "exp" or "ausnutzbar" => "EXPLOITABLE",
            "in_triage" or "triage" or "in_pruefung" => "IN_TRIAGE",
            "resolved" or "behoben" => "RESOLVED",
            "not_set" or "none" or "" => "NOT_SET",
            _ => "",
        };
        if (mapped.Length == 0)
        {
            Console.Error.WriteLine($"  WARNUNG: Zeile {line}: AnalysisState '{value}' nicht erkannt, wird ignoriert (alte Default-Logik greift).");
        }
        return mapped;
    }

    public static List<AssessedRow> LoadCsv(string path)
    {
        var rows = new List<AssessedRow>();
        var cfg = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            Delimiter = ";",
            HasHeaderRecord = true,
            HeaderValidated = null,
            MissingFieldFound = null,
        };

        using var reader = new StreamReader(path, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        using var csv = new CsvReader(reader, cfg);

        csv.Read();
        csv.ReadHeader();

        int lineNo = 1; // Header
        while (csv.Read())
        {
            lineNo++;

            var suppressRaw = TryGet(csv, "Suppress") ?? TryGet(csv, "suppress");
            var commentRaw = TryGet(csv, "Comment") ?? TryGet(csv, "comment") ?? "";
            var analysisStateRaw = TryGet(csv, "AnalysisState") ?? TryGet(csv, "analysis_state") ?? "";
            var suppress = ParseBool(suppressRaw);
            var analysisState = ParseAnalysisState(analysisStateRaw, lineNo);

            if (suppress is null && string.IsNullOrWhiteSpace(commentRaw) && string.IsNullOrEmpty(analysisState))
                continue;

            rows.Add(new AssessedRow
            {
                Line = lineNo,
                VulnSource = (TryGet(csv, "VulnSource") ?? TryGet(csv, "vuln_source") ?? "").Trim(),
                VulnId = (TryGet(csv, "VulnId") ?? TryGet(csv, "vuln_id") ?? "").Trim(),
                ComponentName = (TryGet(csv, "ComponentName") ?? TryGet(csv, "component_name") ?? "").Trim(),
                ComponentVersion = (TryGet(csv, "ComponentVersion") ?? TryGet(csv, "component_version") ?? "").Trim(),
                Suppress = suppress,
                AnalysisState = analysisState,
                Comment = commentRaw.Trim(),
            });
        }

        return rows;
    }

    private static string? TryGet(CsvReader csv, string header)
    {
        try { return csv.GetField(header); }
        catch { return null; }
    }

    // -----------------------------------------------------------------------
    // Index aller Findings ueber alle Projekte
    // -----------------------------------------------------------------------

    private static async Task<Dictionary<FindingKey, List<FindingMatch>>> BuildFindingIndexAsync(
        DTrackClient client,
        List<DtProject> projects,
        CancellationToken ct)
    {
        var index = new Dictionary<FindingKey, List<FindingMatch>>();
        for (int i = 0; i < projects.Count; i++)
        {
            var p = projects[i];
            Console.WriteLine($"[{i + 1}/{projects.Count}] Lade Findings: {p.Label}");

            List<DtFinding> findings;
            try
            {
                findings = await client.GetFindingsAsync(p.Uuid, true, ct).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"  WARNUNG: uebersprungen ({ex.Message})");
                continue;
            }

            foreach (var f in findings)
            {
                var key = new FindingKey(
                    (f.Vulnerability.Source ?? "").Trim(),
                    (f.Vulnerability.VulnId ?? "").Trim(),
                    (f.Component.Name ?? "").Trim());

                if (string.IsNullOrEmpty(key.VulnId)) continue;
                if (string.IsNullOrEmpty(f.Component.Uuid) || string.IsNullOrEmpty(f.Vulnerability.Uuid)) continue;

                if (!index.TryGetValue(key, out var list))
                {
                    list = new List<FindingMatch>();
                    index[key] = list;
                }

                list.Add(new FindingMatch
                {
                    ProjectUuid = p.Uuid,
                    ProjectLabel = p.Label,
                    ComponentUuid = f.Component.Uuid!,
                    ComponentVersion = (f.Component.Version ?? "").Trim(),
                    VulnerabilityUuid = f.Vulnerability.Uuid!,
                    CurrentSuppressed = f.Analysis?.IsSuppressed == true,
                    CurrentState = f.Analysis?.State,
                    CurrentComment = f.Analysis?.Comment ?? "",
                });
            }

            await Task.Delay(50, ct).ConfigureAwait(false);
        }
        return index;
    }

    // -----------------------------------------------------------------------
    // Eine CSV-Zeile auf alle Matches anwenden
    // -----------------------------------------------------------------------

    private static async Task<(int changed, int skipped)> ApplyRowAsync(
        DTrackClient client,
        AssessedRow row,
        List<FindingMatch> matches,
        bool dryRun,
        CancellationToken ct)
    {
        int changed = 0, skipped = 0;

        foreach (var m in matches)
        {
            var targetSuppressed = row.Suppress ?? m.CurrentSuppressed;

            // Explizit gesetzter Analysis-State aus der CSV ueberschreibt die alte Default-Logik.
            // Fallback (= leere CSV-Spalte): bei Suppress -> NOT_AFFECTED, sonst CurrentState bzw. IN_TRIAGE.
            string targetState;
            if (!string.IsNullOrEmpty(row.AnalysisState))
                targetState = row.AnalysisState;
            else if (targetSuppressed)
                targetState = DefaultSuppressState;
            else
                targetState = m.CurrentState is { Length: > 0 } cur ? cur : DefaultUnsuppressState;

            // Idempotenz: skippen wenn Suppress + State + Comment schon identisch sind.
            var commentAlreadyThere = string.IsNullOrEmpty(row.Comment)
                                      || (m.CurrentComment?.Contains(row.Comment, StringComparison.Ordinal) == true);
            var stateMatches = string.Equals(m.CurrentState ?? "", targetState, StringComparison.OrdinalIgnoreCase);
            if (m.CurrentSuppressed == targetSuppressed && stateMatches && commentAlreadyThere)
            {
                skipped++;
                continue;
            }

            var payload = new AnalysisRequest
            {
                Project = m.ProjectUuid,
                Component = m.ComponentUuid,
                Vulnerability = m.VulnerabilityUuid,
                AnalysisState = targetState,
                Suppressed = targetSuppressed,
                Comment = string.IsNullOrWhiteSpace(row.Comment) ? null : row.Comment,
            };

            var verb = dryRun ? "DRY-RUN" : "PUT";
            Console.WriteLine($"  -> {verb} {row.VulnId} @ {row.ComponentName}@{m.ComponentVersion} in '{m.ProjectLabel}' (suppress={targetSuppressed}, state={targetState})");

            if (!dryRun)
            {
                if (await client.PutAnalysisAsync(payload, ct).ConfigureAwait(false))
                    changed++;
            }
            else
            {
                changed++;
            }

            await Task.Delay(50, ct).ConfigureAwait(false);
        }

        return (changed, skipped);
    }
}
