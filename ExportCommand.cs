using System.Globalization;
using System.Text;
using System.Text.Json;
using CsvHelper;
using CsvHelper.Configuration;

namespace DependencyTrackVulnAssessor;

/// <summary>
/// 1. Holt alle Projekte und ihre Findings.
/// 2. Dedupliziert nach (vuln_source, vuln_id, comp_name, comp_version).
/// 3. Schreibt ein CSV-Template, das der Nutzer mit Suppress-Flag + Kommentar fuellt.
/// </summary>
public static class ExportCommand
{
    private static readonly Dictionary<string, int> SeverityOrder = new(StringComparer.OrdinalIgnoreCase)
    {
        ["CRITICAL"] = 0, ["HIGH"] = 1, ["MEDIUM"] = 2, ["LOW"] = 3,
        ["INFO"] = 4, ["UNASSIGNED"] = 5, [""] = 6,
    };

    public static async Task<int> RunAsync(string outputCsvPath, string? rawJsonPath, CancellationToken ct)
    {
        AppConfig cfg;
        try { cfg = AppConfig.Load(Directory.GetCurrentDirectory()); }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }

        using var client = new DTrackClient(cfg);

        Console.WriteLine($"Verbinde mit {cfg.BaseUrl} ...");
        var projects = await client.ListProjectsAsync(ct).ConfigureAwait(false);
        Console.WriteLine($"  {projects.Count} Projekte gefunden.\n");

        if (projects.Count == 0)
        {
            Console.Error.WriteLine("Keine Projekte gefunden. Stimmt der API-Key (VIEW_PORTFOLIO)?");
            return 1;
        }

        var aggregated = new Dictionary<FindingKey, AggregatedFinding>();
        var rawDump = new Dictionary<string, List<DtFinding>>();

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

            rawDump[p.Label] = findings;

            int detailCalls = 0;
            foreach (var f in findings)
            {
                var key = MakeKey(f);
                if (string.IsNullOrEmpty(key.VulnId)) continue;

                if (!aggregated.TryGetValue(key, out var entry))
                {
                    entry = new AggregatedFinding
                    {
                        Key = key,
                        Severity = f.Vulnerability.Severity ?? "",
                        CvssScore = f.Vulnerability.Cvss,
                        Title = (f.Vulnerability.Title ?? "").Replace('\n', ' ').Trim(),
                    };
                    aggregated[key] = entry;
                }

                var version = (f.Component.Version ?? "").Trim();
                if (!string.IsNullOrEmpty(version)) entry.ComponentVersions.Add(version);

                var purl = (f.Component.Purl ?? "").Trim();
                if (!string.IsNullOrEmpty(purl)) entry.ComponentPurls.Add(purl);

                entry.AffectedProjects.Add(p.Label);
                if (f.Analysis?.IsSuppressed == true)
                {
                    entry.CurrentlySuppressedIn.Add(p.Label);
                }

                var existingState = (f.Analysis?.State ?? "").Trim();
                if (!string.IsNullOrEmpty(existingState))
                {
                    entry.ExistingStates.Add(existingState);
                }

                // Comments holen wir nur fuer Findings, die schon eine Bewertung haben — sonst gibt
                // es ohnehin nichts zu lesen. Der Findings-Endpoint liefert das comment-Feld immer
                // als null; den Verlauf bekommen wir nur per separatem GET /api/v1/analysis.
                var needsDetail = (f.Analysis?.IsSuppressed == true) || !string.IsNullOrEmpty(existingState);
                if (!needsDetail) continue;
                if (string.IsNullOrEmpty(f.Component.Uuid) || string.IsNullOrEmpty(f.Vulnerability.Uuid)) continue;

                try
                {
                    var detail = await client.GetAnalysisDetailAsync(p.Uuid, f.Component.Uuid!, f.Vulnerability.Uuid!, ct).ConfigureAwait(false);
                    detailCalls++;
                    var userComment = ExtractLatestUserComment(detail);
                    if (!string.IsNullOrEmpty(userComment))
                    {
                        entry.ExistingComments.Add(userComment);
                    }
                }
                catch (HttpRequestException ex)
                {
                    Console.WriteLine($"  WARNUNG: Analysis-Detail fuer {key.VulnId}/{key.ComponentName} uebersprungen ({ex.Message})");
                }

                await Task.Delay(50, ct).ConfigureAwait(false);
            }

            if (detailCalls > 0) Console.WriteLine($"  ({detailCalls} Comment-Detail-Calls)");

            await Task.Delay(50, ct).ConfigureAwait(false);
        }

        Console.WriteLine($"\n{aggregated.Count} eindeutige Vuln+Komponente-Kombinationen.");

        // Roh-Dump speichern (optional)
        if (!string.IsNullOrEmpty(rawJsonPath))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(rawJsonPath)!);
            await File.WriteAllTextAsync(
                rawJsonPath,
                JsonSerializer.Serialize(rawDump, new JsonSerializerOptions { WriteIndented = true }),
                Encoding.UTF8,
                ct).ConfigureAwait(false);
            Console.WriteLine($"Roh-Findings gespeichert: {rawJsonPath}");
        }

        WriteTemplate(aggregated.Values, outputCsvPath);
        Console.WriteLine($"\nTemplate geschrieben: {outputCsvPath}");
        Console.WriteLine("\nNaechste Schritte:");
        Console.WriteLine("  1. CSV in Excel oeffnen (Semikolon-getrennt, UTF-8 mit BOM)");
        Console.WriteLine("  2. Spalten 'Suppress' (yes/no) und 'Comment' ausfuellen");
        Console.WriteLine("  3. Als 'vulnerabilities_assessed.csv' speichern");
        Console.WriteLine("  4. 'dtrack-assessor apply' starten");

        return 0;
    }

    // -----------------------------------------------------------------------

    // Suppress: "yes" sobald mindestens ein Projekt suppressed ist. apply ist pro Projekt-Match
    // idempotent, also wird die Bewertung sicher auf alle noch nicht suppressed Projekte gespreaded,
    // ohne bereits korrekte Projekte anzufassen. Konsistent zur Source-of-Truth-Worldview des Tools
    // (eine CSV-Zeile = eine Entscheidung fuer alle Projekte).
    private static string DefaultSuppress(AggregatedFinding e) =>
        e.CurrentlySuppressedIn.Count > 0 ? "yes" : "";

    // Haeufigsten Comment uebernehmen; bei Gleichstand lexikographisch ersten.
    private static string DefaultComment(AggregatedFinding e) => MostCommon(e.ExistingComments);

    // Haeufigsten Analysis-State uebernehmen (NOT_AFFECTED, FALSE_POSITIVE, ...).
    private static string DefaultAnalysisState(AggregatedFinding e) => MostCommon(e.ExistingStates);

    private static string MostCommon(IReadOnlyCollection<string> values)
    {
        if (values.Count == 0) return "";
        return values
            .GroupBy(v => v, StringComparer.Ordinal)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.Ordinal)
            .First()
            .Key;
    }

    private static FindingKey MakeKey(DtFinding f) => new(
        (f.Vulnerability.Source ?? "").Trim(),
        (f.Vulnerability.VulnId ?? "").Trim(),
        (f.Component.Name ?? "").Trim()
    );

    /// <summary>
    /// Extrahiert den neuesten "echten" User-Comment aus dem Verlauf. DT mischt im Verlauf
    /// automatische Marker ("Suppressed", "Analysis: NOT_SET → NOT_AFFECTED", "Severity: X → Y"),
    /// die wir wegfiltern.
    /// </summary>
    private static string ExtractLatestUserComment(DtAnalysisDetail? detail)
    {
        if (detail?.AnalysisComments is null) return "";
        return detail.AnalysisComments
            .Where(c => !string.IsNullOrWhiteSpace(c.Comment) && !IsAutoMarker(c.Comment!))
            .OrderByDescending(c => c.Timestamp ?? 0L)
            .Select(c => c.Comment!.Trim())
            .FirstOrDefault() ?? "";
    }

    private static bool IsAutoMarker(string comment)
    {
        var t = comment.Trim();
        if (t.Equals("Suppressed", StringComparison.OrdinalIgnoreCase)) return true;
        if (t.Equals("Unsuppressed", StringComparison.OrdinalIgnoreCase)) return true;
        // Mehrzeilige Eintraege sind in der Praxis immer User-Texte
        if (t.Contains('\n')) return false;
        // Field-Transitions: "Analysis: NOT_SET → NOT_AFFECTED", "Severity: HIGH → CRITICAL", ...
        if (t.Contains('→') && t.Contains(':')) return true;
        return false;
    }

    public static void WriteTemplate(IEnumerable<AggregatedFinding> entries, string path)
    {
        var sorted = entries
            .OrderBy(e => SeverityOrder.GetValueOrDefault(e.Severity ?? "", 9))
            .ThenByDescending(e => e.CvssScore)
            .ThenBy(e => e.ComponentName, StringComparer.OrdinalIgnoreCase)
            .Select(e => new CsvTemplateRow
            {
                VulnSource = e.VulnSource,
                VulnId = e.VulnId,
                Severity = e.Severity,
                CvssScore = e.CvssScore > 0 ? e.CvssScore.ToString("0.0", CultureInfo.InvariantCulture) : "",
                ComponentName = e.ComponentName,
                ComponentVersion = string.Join(" | ", e.ComponentVersions),
                ComponentPurl = string.Join(" | ", e.ComponentPurls),
                Title = e.Title,
                AffectedProjectsCount = e.AffectedProjects.Count,
                AffectedProjects = string.Join(" | ", e.AffectedProjects),
                CurrentlySuppressedIn = string.Join(" | ", e.CurrentlySuppressedIn),
                Suppress = DefaultSuppress(e),
                AnalysisState = DefaultAnalysisState(e),
                Comment = DefaultComment(e),
            })
            .ToList();

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".");

        var cfg = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            Delimiter = ";",
            HasHeaderRecord = true,
        };

        // UTF-8 mit BOM, damit Excel die Datei sauber per Doppelklick oeffnet
        using var writer = new StreamWriter(path, false, new UTF8Encoding(true));
        using var csv = new CsvWriter(writer, cfg);
        csv.WriteHeader<CsvTemplateRow>();
        csv.NextRecord();
        foreach (var row in sorted)
        {
            csv.WriteRecord(row);
            csv.NextRecord();
        }
    }
}
