using System.Text.Json;

namespace Preflight.Core;

/// <summary>Loads normalized activity reports (fixtures now; MXC adapter output in Phase 2).</summary>
public static class Normalizer
{
    public static ActivityReport Parse(string json)
    {
        ActivityReport? report;
        try { report = JsonSerializer.Deserialize<ActivityReport>(json, JsonDefaults.Options); }
        catch (JsonException ex) { throw new InvalidDataException($"Invalid report JSON: {ex.Message}", ex); }

        if (report is null || report.Subject is null || report.Events is null)
            throw new InvalidDataException("Report must contain 'subject' and 'events'.");
        return report;
    }

    public static async Task<ActivityReport> LoadAsync(string path, CancellationToken ct = default)
        => Parse(await File.ReadAllTextAsync(path, ct));
}

/// <summary>Windows-style path helpers (case-insensitive, backslash-normalized, platform independent).</summary>
public static class PathUtil
{
    public static string Norm(string path) => path.Replace('/', '\\').ToLowerInvariant();

    public static bool IsUnder(string path, string folder)
    {
        var p = Norm(path);
        var f = Norm(folder).TrimEnd('\\');
        return p == f || p.StartsWith(f + "\\", StringComparison.Ordinal);
    }

    public static string FileName(string path)
    {
        var p = path.Replace('/', '\\').TrimEnd('\\');
        var i = p.LastIndexOf('\\');
        return i < 0 ? p : p[(i + 1)..];
    }
}
