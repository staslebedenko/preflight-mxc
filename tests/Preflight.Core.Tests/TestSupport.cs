using Preflight.Core;

namespace Preflight.Core.Tests;

internal static class T
{
    public const string Work = @"C:\Users\demo\AppData\Local\Temp\preflight\work";
    private static int _n;

    public static ActivityEvent E(EventKind kind, string target, bool granted = false, string? detail = null)
        => new((++_n).ToString(), DateTimeOffset.Parse("2026-01-10T10:00:00Z").AddSeconds(_n), kind, target, granted, detail);

    public static ActivityReport R(params ActivityEvent[] events)
        => new(new Subject("test.ps1", "00", SubjectKind.Script, "test"), 2000, 0, Work, events);

    public static Finding? Run(string ruleId, ActivityReport report, RuleOptions? o = null)
        => Rules.Default().Single(r => r.Id == ruleId).Evaluate(report, o ?? new RuleOptions());

    public static string FixturePath(string name)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "samples", "fixtures")))
            dir = dir.Parent;
        return dir is null
            ? throw new DirectoryNotFoundException("samples/fixtures not found")
            : Path.Combine(dir.FullName, "samples", "fixtures", name);
    }
}
