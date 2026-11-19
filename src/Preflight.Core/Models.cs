using System.Text.Json;
using System.Text.Json.Serialization;

namespace Preflight.Core;

public enum EventKind
{
    FileRead, FileWrite, FileEnumerate, RegistryRead, RegistryWrite,
    NetworkConnect, DnsQuery, ProcessStart, Other
}

public record ActivityEvent(string Id, DateTimeOffset Timestamp, EventKind Kind,
                            string Target, bool Granted, string? Detail);

public enum Severity { Info, Low, Medium, High }

public record Finding(string Id, string RuleId, Severity Severity, string Category,
                      string Title, IReadOnlyList<string> EvidenceEventIds);

public enum VerdictLevel { LooksSafe, Caution, Risky }

public enum Certainty { Confident, Uncertain }

public record ExplainedFinding(string FindingId, string PlainLanguage);

public record Verdict(VerdictLevel Level, Certainty Certainty, string Headline,
                      IReadOnlyList<ExplainedFinding> Findings,
                      string ExplainerUsed, long LatencyMs);

public enum SubjectKind { Script, Executable, Command, Other }

public record Subject(string DisplayName, string Sha256, SubjectKind Kind, string? Source);

/// <summary>Preflight's own normalized activity report (the pipeline never depends on MXC's schema).</summary>
public record ActivityReport(Subject Subject, long DurationMs, int ExitCode,
                             string WorkingFolder, IReadOnlyList<ActivityEvent> Events);

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
}
