namespace DependencyTrackVulnAssessor;

public static class Program
{
    private const string DefaultTemplateCsv = "vulnerabilities_template.csv";
    private const string DefaultAssessedCsv = "vulnerabilities_assessed.csv";
    private const string DefaultRawJson = "exports/findings_raw.json";

    public static async Task<int> Main(string[] args)
    {
        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
            Console.WriteLine("\nAbbruch angefordert ...");
        };

        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintHelp();
            return 0;
        }

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "export" => await HandleExport(args.Skip(1).ToArray(), cts.Token).ConfigureAwait(false),
                "apply" => await HandleApply(args.Skip(1).ToArray(), cts.Token).ConfigureAwait(false),
                _ => UnknownCommand(args[0]),
            };
        }
        // Nur echter User-Abbruch (Ctrl+C) ist "Abgebrochen." — ein HttpClient-Timeout wirft
        // ebenfalls eine OperationCanceledException (TaskCanceledException) und soll stattdessen
        // als normaler Fehler gemeldet werden.
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            Console.Error.WriteLine("Abgebrochen.");
            return 130;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Unerwarteter Fehler: {ex.Message}");
            return 1;
        }
    }

    private static Task<int> HandleExport(string[] args, CancellationToken ct)
    {
        string outputCsv = ResolveArg(args, "--out", DefaultTemplateCsv);
        string rawJson = ResolveArg(args, "--raw", DefaultRawJson);
        return ExportCommand.RunAsync(outputCsv, rawJson, ct);
    }

    private static Task<int> HandleApply(string[] args, CancellationToken ct)
    {
        bool dryRun = args.Contains("--dry-run", StringComparer.OrdinalIgnoreCase);

        // Positional CSV-Pfad (erstes nicht-Option-Argument)
        var positional = args.FirstOrDefault(a => !a.StartsWith("--"));
        string csv = positional ?? (File.Exists(DefaultAssessedCsv) ? DefaultAssessedCsv : DefaultTemplateCsv);

        return ApplyCommand.RunAsync(csv, dryRun, ct);
    }

    private static int UnknownCommand(string cmd)
    {
        Console.Error.WriteLine($"Unbekannter Befehl: {cmd}\n");
        PrintHelp();
        return 2;
    }

    private static string ResolveArg(string[] args, string flag, string fallback)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], flag, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        }
        return fallback;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("""
            DependencyTrack Vulnerability Assessor

            Verwendung:
              dtrack-assessor export [--out PFAD] [--raw PFAD]
              dtrack-assessor apply  [PFAD] [--dry-run]

            Befehle:
              export      Holt alle Findings aus DT und schreibt ein CSV-Template
              apply       Liest die bewertete CSV und schreibt Suppress + Kommentar zurueck

            Optionen:
              --out PFAD   Zieldatei fuer das Template (Default: vulnerabilities_template.csv)
              --raw PFAD   Pfad fuer den JSON-Roh-Dump   (Default: exports/findings_raw.json)
              --dry-run    Zeigt Aenderungen ohne sie zu schreiben

            Konfiguration:
              appsettings.json im Arbeitsverzeichnis (Template, Section "DependencyTrack")
              .NET User Secrets fuer die echten Werte:
                dotnet user-secrets set "DependencyTrack:ApiKey" "..."
              Umgebungsvariablen DT_URL, DT_API_KEY, DT_VERIFY_SSL als Override.
            """);
    }
}
