using Preflight.Explain;
using Xunit;

namespace Preflight.Core.Tests;

public class GoldenTests
{
    public static TheoryData<string, VerdictLevel, Certainty, string> Cases => new()
    {
        { "clean-script.json",       VerdictLevel.LooksSafe, Certainty.Confident, "INFO-NOTHING" },
        { "fps-booster.json",        VerdictLevel.Risky,     Certainty.Confident, "NET-OUTBOUND,PERSIST-RUNKEY,SENS-BROWSER" },
        { "mod-installer.json",      VerdictLevel.Caution,   Certainty.Uncertain, "FS-OUTSIDE-SCOPE,NET-OUTBOUND" },
        { "encoded-powershell.json", VerdictLevel.Risky,     Certainty.Confident, "FS-OUTSIDE-SCOPE,PERSIST-STARTUP,PROC-LOLBIN" },
        { "folder-crawler.json",     VerdictLevel.Caution,   Certainty.Confident, "FS-MASS-ENUM" },
        { "readme-installer.json",   VerdictLevel.Risky,     Certainty.Confident, "NET-OUTBOUND,PROC-DOWNLOAD-EXEC" },
    };

    [Theory, MemberData(nameof(Cases))]
    public async Task Fixture_produces_expected_verdict(string file, VerdictLevel level, Certainty certainty, string rules)
    {
        var report = await Normalizer.LoadAsync(T.FixturePath(file));
        var engine = new RuleEngine();
        var findings = engine.Evaluate(report);

        Assert.Equal(rules.Split(','), findings.Select(f => f.RuleId).OrderBy(x => x, StringComparer.Ordinal).ToArray());
        Assert.Equal(level, VerdictLogic.Level(findings));
        Assert.Equal(certainty, VerdictLogic.AssessCertainty(report, findings, engine.Options));
    }

    [Theory, MemberData(nameof(Cases))]
    public async Task Template_explainer_covers_every_finding(string file, VerdictLevel level, Certainty certainty, string _)
    {
        var report = await Normalizer.LoadAsync(T.FixturePath(file));
        var findings = new RuleEngine().Evaluate(report);
        var verdict = await new TemplateExplainer().ExplainAsync(report.Subject, findings, level, certainty);

        Assert.Equal(findings.Select(f => f.Id), verdict.Findings.Select(f => f.FindingId));
        Assert.All(verdict.Findings, f => Assert.False(string.IsNullOrWhiteSpace(f.PlainLanguage)));
        Assert.DoesNotContain(@"\Users\demo", string.Join(" ", verdict.Findings.Select(f => f.PlainLanguage)));
    }

    [Fact]
    public void Normalizer_rejects_garbage() =>
        Assert.Throws<InvalidDataException>(() => Normalizer.Parse("{ not json"));
}
