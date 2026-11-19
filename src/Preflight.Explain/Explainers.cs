using System.Diagnostics;
using Preflight.Core;

namespace Preflight.Explain;

public interface IExplainer
{
    string Name { get; }
    Task<Verdict> ExplainAsync(Subject subject, IReadOnlyList<Finding> findings,
                               VerdictLevel level, Certainty certainty, CancellationToken ct = default);
}

/// <summary>Deterministic sentences per rule ID. Fallback, test baseline, and works with no model.</summary>
public sealed class TemplateExplainer : IExplainer
{
    public string Name => "template";

    private static readonly Dictionary<string, string> Why = new()
    {
        ["SENS-BROWSER"] = "Browser profiles hold saved passwords, cookies and login sessions.",
        ["SENS-CREDS"] = "These locations hold passwords, keys or wallets that could let someone act as you.",
        ["SENS-GAME-ACCOUNTS"] = "Game launcher data can be used to take over your gaming accounts.",
        ["PERSIST-RUNKEY"] = "This would make it run again every time you sign in.",
        ["PERSIST-STARTUP"] = "This would make it run again every time you sign in.",
        ["PERSIST-TASK"] = "This would make it run again on a schedule without you noticing.",
        ["NET-OUTBOUND"] = "Contacting the internet is how programs send data out or fetch more code.",
        ["PROC-LOLBIN"] = "Built-in Windows tools like this are often used to hide what a program is doing.",
        ["PROC-DOWNLOAD-EXEC"] = "Running downloaded code means you cannot know in advance what it will do.",
        ["FS-OUTSIDE-SCOPE"] = "Programs normally stay in their own folder; writing elsewhere can change your system.",
        ["FS-MASS-ENUM"] = "Listing many personal folders can be a first step towards finding files to take.",
        ["INFO-NOTHING"] = "Nothing suspicious was observed."
    };

    public Task<Verdict> ExplainAsync(Subject subject, IReadOnlyList<Finding> findings,
                                      VerdictLevel level, Certainty certainty, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var explained = findings
            .Select(f => new ExplainedFinding(f.Id,
                Why.TryGetValue(f.RuleId, out var why) ? $"{f.Title}. {why}" : $"{f.Title}."))
            .ToList();

        var high = findings.Count(f => f.Severity == Severity.High);
        var headline = level switch
        {
            VerdictLevel.Risky => $"Risky. {subject.DisplayName} showed {high} serious behaviour(s); review the evidence before running it for real.",
            VerdictLevel.Caution => $"Caution. {subject.DisplayName} did things worth a closer look.",
            _ => $"Looks safe. {subject.DisplayName} stayed inside its own working folder."
        };

        sw.Stop();
        return Task.FromResult(new Verdict(level, certainty, headline, explained, Name, sw.ElapsedMilliseconds));
    }
}
