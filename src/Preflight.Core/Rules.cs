using System.Text.RegularExpressions;

namespace Preflight.Core;

public sealed record RuleOptions
{
    /// <summary>FS-MASS-ENUM fires when MORE than this many distinct user folders are enumerated.</summary>
    public int MassEnumThreshold { get; init; } = 5;

    /// <summary>Runs shorter than this are treated as inconclusive (Uncertain).</summary>
    public long MinRuntimeMs { get; init; } = 500;

    public IReadOnlyList<string> GameAccountPaths { get; init; } = new[]
    {
        @"\steam\config", @"\steam\ssfn", @"\epic\epicgameslauncher\saved",
        @"\battle.net", @"\riot games\riot client\data", @"\ubisoft game launcher",
        @"\ea desktop", @"\gog.com\galaxy"
    };
}

public interface IRule
{
    string Id { get; }
    /// <summary>Returns one aggregated finding (Id left empty; the engine assigns it) or null.</summary>
    Finding? Evaluate(ActivityReport report, RuleOptions options);
}

internal static class RuleHelpers
{
    public static bool IsFile(EventKind k) => k is EventKind.FileRead or EventKind.FileWrite or EventKind.FileEnumerate;

    public static bool InWork(ActivityReport r, string target) => PathUtil.IsUnder(target, r.WorkingFolder);

    public static string Redact(string s) => UserRedactor.Redact(s);

    public static string Outcome(IEnumerable<ActivityEvent> ev)
    {
        var list = ev.ToList();
        if (list.All(e => !e.Granted)) return "blocked";
        if (list.All(e => e.Granted)) return "allowed";
        return "partly blocked";
    }

    public static string Targets(IEnumerable<ActivityEvent> ev, int max = 3)
    {
        var t = ev.Select(e => Redact(e.Target)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var shown = string.Join("; ", t.Take(max));
        return t.Count > max ? $"{shown}; +{t.Count - max} more" : shown;
    }

    public static Finding Make(string ruleId, Severity sev, string category, string what, List<ActivityEvent> ev)
        => new("", ruleId, sev, category, $"{what}: {Targets(ev)} ({Outcome(ev)})",
               ev.Select(e => e.Id).ToList());
}

/// <summary>Generic "file access matching a path pattern table" rule.</summary>
internal sealed class PathAccessRule : IRule
{
    private readonly Severity _severity;
    private readonly string _category, _what;
    private readonly Func<ActivityReport, RuleOptions, string, bool> _match;

    public PathAccessRule(string id, Severity severity, string category, string what,
                          Func<ActivityReport, RuleOptions, string, bool> match)
    { Id = id; _severity = severity; _category = category; _what = what; _match = match; }

    public string Id { get; }

    public Finding? Evaluate(ActivityReport r, RuleOptions o)
    {
        var ev = r.Events.Where(e => RuleHelpers.IsFile(e.Kind) && _match(r, o, PathUtil.Norm(e.Target))).ToList();
        return ev.Count == 0 ? null : RuleHelpers.Make(Id, _severity, _category, _what, ev);
    }
}

internal sealed class SimpleRule : IRule
{
    private readonly Func<ActivityReport, RuleOptions, Finding?> _eval;
    public SimpleRule(string id, Func<ActivityReport, RuleOptions, Finding?> eval) { Id = id; _eval = eval; }
    public string Id { get; }
    public Finding? Evaluate(ActivityReport r, RuleOptions o) => _eval(r, o);
}

public static class Rules
{
    private const string Sensitive = "Sensitive data", Persistence = "Persistence",
                         Network = "Network", Process = "Process", Filesystem = "Filesystem";

    private static readonly string[] BrowserPaths =
    {
        @"\google\chrome\user data", @"\microsoft\edge\user data", @"\mozilla\firefox\profiles",
        @"\brave-software\brave-browser\user data", @"\opera software\opera stable"
    };

    private static readonly string[] CredPaths =
    {
        @"\microsoft\credentials", @"\microsoft\vault", @"\.ssh", @"\.aws", @"\.azure",
        @"\.config\gcloud", @"\gcloud", @"\.kube",
        @"\bitcoin\wallet", @"\electrum\wallets", @"\exodus\exodus.wallet", @"\ethereum\keystore"
    };

    private static readonly string[] ExecExtensions = { ".exe", ".dll", ".ps1", ".bat", ".cmd", ".msi", ".vbs", ".js" };
    private static readonly string[] Lolbins = { "certutil", "bitsadmin", "mshta", "rundll32", "regsvr32" };

    private static readonly Regex EncodedPs = new(@"(^|\s)-e(nc(odedcommand)?)?(\s|$)", RegexOptions.IgnoreCase);
    private static readonly Regex PipeToIex = new(
        @"(iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget|downloadstring)[^|]*\|\s*(iex|invoke-expression)",
        RegexOptions.IgnoreCase);

    public static IReadOnlyList<IRule> Default() => new IRule[]
    {
        new PathAccessRule("SENS-BROWSER", Severity.High, Sensitive, "Tried to access browser profile data",
            (_, _, p) => BrowserPaths.Any(p.Contains)),
        new PathAccessRule("SENS-CREDS", Severity.High, Sensitive, "Tried to access saved credentials or keys",
            (_, _, p) => CredPaths.Any(p.Contains) || p.EndsWith(@"\.env") || p.Contains(@"\.env."))
        ,
        new PathAccessRule("SENS-GAME-ACCOUNTS", Severity.High, Sensitive, "Tried to access game account data",
            (_, o, p) => o.GameAccountPaths.Any(g => p.Contains(g.ToLowerInvariant()))),
        PersistRunKey(), PersistStartup(), PersistTask(),
        NetOutbound(), ProcLolbin(), ProcDownloadExec(),
        FsOutsideScope(), FsMassEnum(), InfoNothing()
    };

    private static IRule PersistRunKey() => new SimpleRule("PERSIST-RUNKEY", (r, _) =>
    {
        var ev = r.Events.Where(e => e.Kind == EventKind.RegistryWrite &&
                                     PathUtil.Norm(e.Target).Contains(@"\currentversion\run")).ToList();
        return ev.Count == 0 ? null
            : RuleHelpers.Make("PERSIST-RUNKEY", Severity.High, Persistence, "Tried to start itself at every login (Run key)", ev);
    });

    private static IRule PersistStartup() => new SimpleRule("PERSIST-STARTUP", (r, _) =>
    {
        var ev = r.Events.Where(e => e.Kind == EventKind.FileWrite &&
                                     PathUtil.Norm(e.Target).Contains(@"\start menu\programs\startup")).ToList();
        return ev.Count == 0 ? null
            : RuleHelpers.Make("PERSIST-STARTUP", Severity.High, Persistence, "Tried to add itself to the Startup folder", ev);
    });

    private static IRule PersistTask() => new SimpleRule("PERSIST-TASK", (r, _) =>
    {
        var ev = r.Events.Where(e => e.Kind == EventKind.ProcessStart &&
                                     PathUtil.FileName(e.Target).StartsWith("schtasks", StringComparison.OrdinalIgnoreCase) &&
                                     (e.Detail ?? "").Contains("/create", StringComparison.OrdinalIgnoreCase)).ToList();
        return ev.Count == 0 ? null
            : RuleHelpers.Make("PERSIST-TASK", Severity.High, Persistence, "Tried to create a scheduled task", ev);
    });

    private static IRule NetOutbound() => new SimpleRule("NET-OUTBOUND", (r, _) =>
    {
        var ev = r.Events.Where(e => e.Kind is EventKind.NetworkConnect or EventKind.DnsQuery).ToList();
        return ev.Count == 0 ? null
            : RuleHelpers.Make("NET-OUTBOUND", Severity.Medium, Network, "Tried to contact the network", ev);
    });

    private static IRule ProcLolbin() => new SimpleRule("PROC-LOLBIN", (r, _) =>
    {
        var ev = r.Events.Where(e =>
        {
            if (e.Kind != EventKind.ProcessStart) return false;
            var name = Path.GetFileNameWithoutExtension(PathUtil.FileName(e.Target)).ToLowerInvariant();
            if (Lolbins.Contains(name)) return true;
            return name is "powershell" or "pwsh" && EncodedPs.IsMatch(e.Detail ?? "");
        }).ToList();
        return ev.Count == 0 ? null
            : RuleHelpers.Make("PROC-LOLBIN", Severity.Medium, Process, "Started a system tool often abused to hide activity", ev);
    });

    private static IRule ProcDownloadExec() => new SimpleRule("PROC-DOWNLOAD-EXEC", (r, _) =>
    {
        var hits = new List<ActivityEvent>();

        // Pattern 1: "download | iex" style command lines.
        hits.AddRange(r.Events.Where(e => e.Kind == EventKind.ProcessStart && PipeToIex.IsMatch(e.Detail ?? "")));

        // Pattern 2: network -> write executable content -> start that same file (in event order).
        var ev = r.Events;
        for (var i = 0; i < ev.Count; i++)
        {
            if (ev[i].Kind != EventKind.NetworkConnect) continue;
            for (var j = i + 1; j < ev.Count; j++)
            {
                if (ev[j].Kind != EventKind.FileWrite ||
                    !ExecExtensions.Contains(Path.GetExtension(ev[j].Target).ToLowerInvariant())) continue;
                var k = ev.Skip(j + 1).ToList().FindIndex(e => e.Kind == EventKind.ProcessStart &&
                    PathUtil.Norm(e.Target) == PathUtil.Norm(ev[j].Target));
                if (k < 0) continue;
                hits.AddRange(new[] { ev[i], ev[j], ev[j + 1 + k] });
                goto done;
            }
        }
        done:
        hits = hits.DistinctBy(e => e.Id).ToList();
        return hits.Count == 0 ? null
            : RuleHelpers.Make("PROC-DOWNLOAD-EXEC", Severity.High, Process, "Downloaded content and then ran it", hits);
    });

    private static IRule FsOutsideScope() => new SimpleRule("FS-OUTSIDE-SCOPE", (r, _) =>
    {
        var ev = r.Events.Where(e => e.Kind == EventKind.FileWrite && !RuleHelpers.InWork(r, e.Target)).ToList();
        return ev.Count == 0 ? null
            : RuleHelpers.Make("FS-OUTSIDE-SCOPE", Severity.Medium, Filesystem, "Tried to write outside its own folder", ev);
    });

    private static IRule FsMassEnum() => new SimpleRule("FS-MASS-ENUM", (r, o) =>
    {
        var ev = r.Events.Where(e => e.Kind == EventKind.FileEnumerate && !RuleHelpers.InWork(r, e.Target) &&
                                     PathUtil.Norm(e.Target).Contains(@"\users\")).ToList();
        var distinct = ev.Select(e => PathUtil.Norm(e.Target)).Distinct().Count();
        return distinct <= o.MassEnumThreshold ? null
            : RuleHelpers.Make("FS-MASS-ENUM", Severity.Medium, Filesystem, $"Tried to list {distinct} of your folders", ev);
    });

    private static IRule InfoNothing() => new SimpleRule("INFO-NOTHING", (r, _) =>
    {
        var outside = r.Events.Any(e => !(RuleHelpers.IsFile(e.Kind) && RuleHelpers.InWork(r, e.Target)));
        return outside ? null
            : new Finding("", "INFO-NOTHING", Severity.Info, "Info",
                          "Stayed inside its own working folder", Array.Empty<string>());
    });
}

public sealed class RuleEngine
{
    private readonly IReadOnlyList<IRule> _rules;
    private readonly RuleOptions _options;

    public RuleEngine(IReadOnlyList<IRule>? rules = null, RuleOptions? options = null)
    { _rules = rules ?? Rules.Default(); _options = options ?? new RuleOptions(); }

    public RuleOptions Options => _options;

    public IReadOnlyList<Finding> Evaluate(ActivityReport report)
    {
        var result = new List<Finding>();
        foreach (var rule in _rules)
        {
            var f = rule.Evaluate(report, _options);
            if (f is not null) result.Add(f with { Id = $"F{result.Count + 1}" });
        }
        return result;
    }
}
