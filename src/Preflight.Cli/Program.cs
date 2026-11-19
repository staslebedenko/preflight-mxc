using System.Text;
using System.Text.Json;
using Preflight.Core;
using Preflight.Explain;

namespace Preflight.Cli;

public static class Program
{
    private const string Usage = "Usage: preflight explain <report.json> [--json]";

    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Length == 0 || args[0] is "-h" or "--help") { Console.WriteLine(Usage); return args.Length == 0 ? 2 : 0; }
        if (args[0] != "explain") { Console.Error.WriteLine($"Unknown command '{args[0]}'. {Usage}"); return 2; }

        var asJson = args.Contains("--json");
        var path = args.Skip(1).FirstOrDefault(a => !a.StartsWith("--"));
        if (path is null) { Console.Error.WriteLine(Usage); return 2; }

        ActivityReport report;
        try { report = await Normalizer.LoadAsync(path); }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        { Console.Error.WriteLine($"Cannot load report: {ex.Message}"); return 1; }

        var engine = new RuleEngine();
        var findings = engine.Evaluate(report);
        var level = VerdictLogic.Level(findings);
        var certainty = VerdictLogic.AssessCertainty(report, findings, engine.Options);

        IExplainer explainer = new TemplateExplainer();
        var verdict = await explainer.ExplainAsync(report.Subject, findings, level, certainty);

        Console.WriteLine(asJson ? RenderJson(report, findings, verdict) : RenderText(report, findings, verdict));
        return 0;
    }

    private static Dictionary<string, ActivityEvent> Index(ActivityReport r) => r.Events.ToDictionary(e => e.Id);

    private static string RenderText(ActivityReport report, IReadOnlyList<Finding> findings, Verdict v)
    {
        var events = Index(report);
        var sb = new StringBuilder();
        sb.AppendLine($"Subject:   {report.Subject.DisplayName}  [{report.Subject.Kind}]");
        sb.AppendLine($"SHA-256:   {report.Subject.Sha256}");
        sb.AppendLine($"Verdict:   {v.Level.ToString().ToUpperInvariant()} ({v.Certainty})");
        sb.AppendLine($"Explainer: {v.ExplainerUsed} ({v.LatencyMs} ms)");
        sb.AppendLine();
        sb.AppendLine(v.Headline);
        if (v.Certainty == Certainty.Uncertain)
            sb.AppendLine("Not sure: a second opinion would help (available in a later phase).");
        sb.AppendLine();

        foreach (var f in findings.OrderByDescending(f => f.Severity))
        {
            var text = v.Findings.FirstOrDefault(x => x.FindingId == f.Id)?.PlainLanguage ?? f.Title;
            sb.AppendLine($"[{f.Severity.ToString().ToUpperInvariant()}] {f.RuleId} ({f.Id})");
            sb.AppendLine($"  {text}");
            foreach (var id in f.EvidenceEventIds)
                if (events.TryGetValue(id, out var e))
                    sb.AppendLine($"    - {e.Kind}: {UserRedactor.Redact(e.Target)} [{(e.Granted ? "allowed" : "blocked")}]");
            sb.AppendLine();
        }
        return sb.ToString().TrimEnd();
    }

    private static string RenderJson(ActivityReport report, IReadOnlyList<Finding> findings, Verdict v)
    {
        var events = Index(report);
        var output = new
        {
            subject = report.Subject with { },
            verdict = new { level = v.Level, certainty = v.Certainty, headline = v.Headline,
                            explainer = v.ExplainerUsed, latencyMs = v.LatencyMs },
            findings = findings.Select(f => new
            {
                f.Id, f.RuleId, f.Severity, f.Category, f.Title,
                plainLanguage = v.Findings.FirstOrDefault(x => x.FindingId == f.Id)?.PlainLanguage,
                evidence = f.EvidenceEventIds.Where(events.ContainsKey).Select(id => new
                {
                    events[id].Id, events[id].Kind, target = UserRedactor.Redact(events[id].Target), events[id].Granted
                })
            })
        };
        return JsonSerializer.Serialize(output, JsonDefaults.Options);
    }
}
