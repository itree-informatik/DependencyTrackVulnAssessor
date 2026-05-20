using System.Text.Json.Serialization;

namespace DependencyTrackVulnAssessor;

// ---------------------------------------------------------------------------
// Dependency-Track API DTOs
// ---------------------------------------------------------------------------

public sealed class DtProject
{
    [JsonPropertyName("uuid")] public string Uuid { get; set; } = "";
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("version")] public string? Version { get; set; }
    [JsonPropertyName("active")] public bool? Active { get; set; }

    public string Label => string.IsNullOrWhiteSpace(Version) ? Name : $"{Name} {Version}";
}

public sealed class DtComponent
{
    [JsonPropertyName("uuid")] public string? Uuid { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("version")] public string? Version { get; set; }
    [JsonPropertyName("purl")] public string? Purl { get; set; }
}

public sealed class DtVulnerability
{
    [JsonPropertyName("uuid")] public string? Uuid { get; set; }
    [JsonPropertyName("source")] public string? Source { get; set; }
    [JsonPropertyName("vulnId")] public string? VulnId { get; set; }
    [JsonPropertyName("severity")] public string? Severity { get; set; }
    [JsonPropertyName("title")] public string? Title { get; set; }
    [JsonPropertyName("cvssV3BaseScore")] public double? CvssV3 { get; set; }
    [JsonPropertyName("cvssV2BaseScore")] public double? CvssV2 { get; set; }

    public double Cvss => CvssV3 ?? CvssV2 ?? 0d;
}

public sealed class DtAnalysis
{
    [JsonPropertyName("state")] public string? State { get; set; }
    [JsonPropertyName("isSuppressed")] public bool? IsSuppressed { get; set; }
    [JsonPropertyName("comment")] public string? Comment { get; set; }
}

/// <summary>
/// Vollstaendiges Analysis-Objekt mit Comment-Verlauf, geliefert von GET /api/v1/analysis.
/// Der Findings-Endpoint (GET /api/v1/finding/project/{uuid}) liefert keinen Comment-Text mit,
/// deshalb ist dieser separate Call die einzige Quelle fuer existierende User-Comments.
/// </summary>
public sealed class DtAnalysisDetail
{
    [JsonPropertyName("state")] public string? State { get; set; }
    [JsonPropertyName("isSuppressed")] public bool? IsSuppressed { get; set; }
    [JsonPropertyName("analysisComments")] public List<DtAnalysisComment>? AnalysisComments { get; set; }
}

public sealed class DtAnalysisComment
{
    [JsonPropertyName("comment")] public string? Comment { get; set; }
    [JsonPropertyName("commenter")] public string? Commenter { get; set; }
    [JsonPropertyName("timestamp")] public long? Timestamp { get; set; }
}

public sealed class DtFinding
{
    [JsonPropertyName("component")] public DtComponent Component { get; set; } = new();
    [JsonPropertyName("vulnerability")] public DtVulnerability Vulnerability { get; set; } = new();
    [JsonPropertyName("analysis")] public DtAnalysis? Analysis { get; set; }
}

public sealed class AnalysisRequest
{
    [JsonPropertyName("project")] public string Project { get; set; } = "";
    [JsonPropertyName("component")] public string Component { get; set; } = "";
    [JsonPropertyName("vulnerability")] public string Vulnerability { get; set; } = "";
    [JsonPropertyName("analysisState")] public string AnalysisState { get; set; } = "NOT_AFFECTED";

    [JsonPropertyName("comment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Comment { get; set; }

    [JsonPropertyName("suppressed")] public bool Suppressed { get; set; }
}

// ---------------------------------------------------------------------------
// Interne Aggregations- und CSV-Modelle
// ---------------------------------------------------------------------------

/// <summary>
/// Eindeutiger Schluessel fuer Dedup: (vuln_source, vuln_id, comp_name) — bewusst OHNE Version.
/// Hintergrund: System-Komponenten (musl, openssl, …) haben zwischen Projekten unterschiedliche
/// Patch-Versionen, je nach Base-Image-Alter. Eine Triage-Entscheidung gilt fuer die Komponente,
/// nicht fuer eine konkrete Version — sonst zerfaellt eine Bewertung in mehrere CSV-Zeilen.
/// </summary>
public readonly record struct FindingKey(string VulnSource, string VulnId, string ComponentName);

public sealed class AggregatedFinding
{
    public FindingKey Key { get; init; }
    public string VulnSource => Key.VulnSource;
    public string VulnId => Key.VulnId;
    public string ComponentName => Key.ComponentName;
    public SortedSet<string> ComponentVersions { get; } = new(StringComparer.Ordinal);
    public SortedSet<string> ComponentPurls { get; } = new(StringComparer.Ordinal);
    public string Severity { get; set; } = "";
    public double CvssScore { get; set; }
    public string Title { get; set; } = "";
    public SortedSet<string> AffectedProjects { get; } = new();
    public SortedSet<string> CurrentlySuppressedIn { get; } = new();
    public List<string> ExistingComments { get; } = new();
    public List<string> ExistingStates { get; } = new();
}

/// <summary>Eintrag im CSV-Template (Spaltennamen via CsvHelper-Attribut steuerbar).</summary>
public sealed class CsvTemplateRow
{
    public string VulnSource { get; set; } = "";
    public string VulnId { get; set; } = "";
    public string Severity { get; set; } = "";
    public string CvssScore { get; set; } = "";
    public string ComponentName { get; set; } = "";
    public string ComponentVersion { get; set; } = "";
    public string ComponentPurl { get; set; } = "";
    public string Title { get; set; } = "";
    public int AffectedProjectsCount { get; set; }
    public string AffectedProjects { get; set; } = "";
    public string CurrentlySuppressedIn { get; set; } = "";

    // Vom Nutzer auszufuellen:
    public string Suppress { get; set; } = "";
    public string AnalysisState { get; set; } = "";
    public string Comment { get; set; } = "";
}

/// <summary>Gefundenes Match einer CSV-Zeile in einem konkreten Projekt (genau eine Komponenten-Version).</summary>
public sealed class FindingMatch
{
    public string ProjectUuid { get; init; } = "";
    public string ProjectLabel { get; init; } = "";
    public string ComponentUuid { get; init; } = "";
    public string ComponentVersion { get; init; } = "";
    public string VulnerabilityUuid { get; init; } = "";
    public bool CurrentSuppressed { get; init; }
    public string? CurrentState { get; init; }
    public string CurrentComment { get; init; } = "";
}
