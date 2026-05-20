using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace DependencyTrackVulnAssessor;

/// <summary>
/// Minimaler HTTP-Client fuer die Dependency-Track REST-API.
/// </summary>
public sealed class DTrackClient : IDisposable
{
    private const int PageSize = 100;
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _http;
    private readonly string _baseUrl;

    public DTrackClient(AppConfig cfg)
    {
        _baseUrl = cfg.BaseUrl;

        var handler = new HttpClientHandler();
        if (!cfg.VerifySsl)
        {
            // Nur fuer self-signed Zertifikate: SSL-Validation aushebeln.
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
        }

        _http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(60),
        };
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _http.DefaultRequestHeaders.Add("X-Api-Key", cfg.ApiKey);
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    public async Task<List<DtProject>> ListProjectsAsync(CancellationToken ct = default)
    {
        var all = new List<DtProject>();
        var page = 1;
        while (true)
        {
            var url = $"{_baseUrl}/api/v1/project?pageSize={PageSize}&pageNumber={page}&excludeInactive=true";
            using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
            EnsureSuccess(resp, $"Projekte abrufen (Page {page})");
            await EnsureJsonResponseAsync(resp, $"Projekte abrufen (Page {page})", ct).ConfigureAwait(false);

            var batch = await resp.Content.ReadFromJsonAsync<List<DtProject>>(JsonOpts, ct).ConfigureAwait(false);
            if (batch is null || batch.Count == 0) break;

            all.AddRange(batch);

            var total = ReadTotal(resp.Headers, all.Count);
            if (all.Count >= total) break;
            page++;
        }
        return all;
    }

    public async Task<List<DtFinding>> GetFindingsAsync(string projectUuid, bool includeSuppressed = true, CancellationToken ct = default)
    {
        var url = $"{_baseUrl}/api/v1/finding/project/{projectUuid}?suppressed={(includeSuppressed ? "true" : "false")}";
        using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
        EnsureSuccess(resp, $"Findings fuer Projekt {projectUuid}");
        await EnsureJsonResponseAsync(resp, $"Findings fuer Projekt {projectUuid}", ct).ConfigureAwait(false);
        return await resp.Content.ReadFromJsonAsync<List<DtFinding>>(JsonOpts, ct).ConfigureAwait(false)
               ?? new List<DtFinding>();
    }

    /// <summary>
    /// Holt das vollstaendige Analysis-Objekt inkl. Comment-Verlauf fuer ein konkretes Finding.
    /// Liefert null wenn kein Analysis-Eintrag existiert (HTTP 404) — z.B. unbewertete Findings.
    /// </summary>
    public async Task<DtAnalysisDetail?> GetAnalysisDetailAsync(string projectUuid, string componentUuid, string vulnerabilityUuid, CancellationToken ct = default)
    {
        var url = $"{_baseUrl}/api/v1/analysis?project={projectUuid}&component={componentUuid}&vulnerability={vulnerabilityUuid}";
        using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
        if (resp.StatusCode == HttpStatusCode.NotFound) return null;
        EnsureSuccess(resp, "Analysis-Detail abrufen");
        await EnsureJsonResponseAsync(resp, "Analysis-Detail abrufen", ct).ConfigureAwait(false);
        return await resp.Content.ReadFromJsonAsync<DtAnalysisDetail>(JsonOpts, ct).ConfigureAwait(false);
    }

    public async Task<bool> PutAnalysisAsync(AnalysisRequest payload, CancellationToken ct = default)
    {
        var url = $"{_baseUrl}/api/v1/analysis";
        var json = JsonSerializer.Serialize(payload, JsonOpts);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var resp = await _http.PutAsync(url, content, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            Console.Error.WriteLine($"  FEHLER {(int)resp.StatusCode}: {Truncate(body, 300)}");
            return false;
        }
        return true;
    }

    public void Dispose() => _http.Dispose();

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static void EnsureSuccess(HttpResponseMessage resp, string operation)
    {
        if (resp.IsSuccessStatusCode) return;

        var hint = resp.StatusCode switch
        {
            HttpStatusCode.Unauthorized => " (API-Key fehlt oder ungueltig?)",
            HttpStatusCode.Forbidden => " (API-Key hat nicht genug Rechte? Pruefe VIEW_PORTFOLIO + VULNERABILITY_ANALYSIS)",
            HttpStatusCode.NotFound => " (URL nicht gefunden - stimmt DT_URL?)",
            _ => "",
        };
        throw new HttpRequestException($"{operation} fehlgeschlagen: HTTP {(int)resp.StatusCode}{hint}");
    }

    private static async Task EnsureJsonResponseAsync(HttpResponseMessage resp, string operation, CancellationToken ct)
    {
        // DT liefert bei korrekter API-Antwort application/json. Eine HTML-Antwort (z.B. weil
        // DT_URL auf das SPA-Frontend statt auf die API zeigt) wuerde sonst erst beim
        // JSON-Parsen als kryptischer "'<' is an invalid start of a value"-Fehler auffallen.
        var mediaType = resp.Content.Headers.ContentType?.MediaType;
        if (mediaType is null || mediaType.Contains("json", StringComparison.OrdinalIgnoreCase)) return;

        var preview = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        throw new HttpRequestException(
            $"{operation}: Server lieferte Content-Type '{mediaType}' statt JSON. " +
            $"Wahrscheinlich zeigt DependencyTrack:Url auf das Frontend statt auf die API " +
            $"(z.B. /static/config.json der DT-Frontend enthaelt die API-Base-URL). " +
            $"Antwort-Auszug: {Truncate(preview, 200)}");
    }

    private static int ReadTotal(HttpResponseHeaders headers, int fallback)
    {
        if (headers.TryGetValues("X-Total-Count", out var values))
        {
            foreach (var v in values)
            {
                if (int.TryParse(v, out var n)) return n;
            }
        }
        return fallback;
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "...";
}
