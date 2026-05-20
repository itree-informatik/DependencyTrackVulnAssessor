using Microsoft.Extensions.Configuration;

namespace DependencyTrackVulnAssessor;

public sealed record AppConfig(string BaseUrl, string ApiKey, bool VerifySsl)
{
    private const string SectionName = "DependencyTrack";

    public static AppConfig Load(string? workingDir = null)
    {
        var dir = workingDir ?? AppContext.BaseDirectory;

        // appsettings.json: bei dotnet run liegt sie im Repo-Root, BaseDirectory aber in bin/.../.
        // Deshalb nach oben suchen, falls sie im aktuellen Verzeichnis fehlt.
        if (!File.Exists(Path.Combine(dir, "appsettings.json")))
        {
            dir = FindUpwards(dir, "appsettings.json") ?? dir;
        }

        var config = new ConfigurationBuilder()
            .SetBasePath(dir)
            .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
            .AddUserSecrets<AppConfig>(optional: true)
            .Build();

        var section = config.GetSection(SectionName);

        // ENV-Vars sind expliziter Override; behalten den bisherigen Vertrag (DT_URL, DT_API_KEY, DT_VERIFY_SSL).
        var url = Pick(Environment.GetEnvironmentVariable("DT_URL"), section["Url"]).Trim().TrimEnd('/');
        var apiKey = Pick(Environment.GetEnvironmentVariable("DT_API_KEY"), section["ApiKey"]).Trim();
        var verifyRaw = Pick(Environment.GetEnvironmentVariable("DT_VERIFY_SSL"), section["VerifySsl"]).Trim();
        var verify = !string.Equals(verifyRaw, "false", StringComparison.OrdinalIgnoreCase);

        if (string.IsNullOrEmpty(url) || string.IsNullOrEmpty(apiKey))
        {
            throw new InvalidOperationException(
                "DependencyTrack:Url und DependencyTrack:ApiKey muessen gesetzt sein. " +
                "Hinterlege die Werte per `dotnet user-secrets set \"DependencyTrack:Url\" \"...\"` " +
                "und `dotnet user-secrets set \"DependencyTrack:ApiKey\" \"...\"`, " +
                "oder setze DT_URL und DT_API_KEY als Umgebungsvariablen.");
        }

        return new AppConfig(url, apiKey, verify);
    }

    private static string Pick(string? envValue, string? configValue) =>
        !string.IsNullOrWhiteSpace(envValue) ? envValue : (configValue ?? "");

    private static string? FindUpwards(string startDir, string filename)
    {
        var current = new DirectoryInfo(startDir);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, filename)))
                return current.FullName;
            current = current.Parent;
        }
        return null;
    }
}
