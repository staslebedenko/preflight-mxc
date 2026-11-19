using System.Text.RegularExpressions;

namespace Preflight.Core;

/// <summary>Replaces user names in profile paths with &lt;user&gt; (used for titles now; the egress guard later).</summary>
public static class UserRedactor
{
    private static readonly Regex Profile = new(@"(?<=[A-Za-z]:[\\/]Users[\\/])[^\\/]+", RegexOptions.IgnoreCase);

    public static string Redact(string s) => Profile.Replace(s, "<user>");
}

public static class VerdictLogic
{
    /// <summary>Any High -> Risky, any Medium -> Caution, otherwise LooksSafe.</summary>
    public static VerdictLevel Level(IReadOnlyList<Finding> findings)
        => findings.Any(f => f.Severity == Severity.High) ? VerdictLevel.Risky
         : findings.Any(f => f.Severity == Severity.Medium) ? VerdictLevel.Caution
         : VerdictLevel.LooksSafe;

    /// <summary>
    /// Uncertain when: only Medium findings across different categories; the run was too short or exited
    /// with an error; network was the only signal; or the explainer fell back to the template.
    /// </summary>
    public static Certainty AssessCertainty(ActivityReport report, IReadOnlyList<Finding> findings,
                                      RuleOptions options, bool explainerFellBack = false)
    {
        if (explainerFellBack) return Core.Certainty.Uncertain;
        if (report.DurationMs < options.MinRuntimeMs || report.ExitCode != 0) return Core.Certainty.Uncertain;

        var real = findings.Where(f => f.Severity != Severity.Info).ToList();
        if (real.Count > 0 && real.All(f => f.Severity == Severity.Medium) &&
            real.Select(f => f.Category).Distinct().Count() > 1)
            return Core.Certainty.Uncertain;
        if (real.Count > 0 && real.All(f => f.RuleId == "NET-OUTBOUND"))
            return Core.Certainty.Uncertain;

        return Core.Certainty.Confident;
    }
}
