using Xunit;
using static Preflight.Core.Tests.T;

namespace Preflight.Core.Tests;

public class RuleTests
{
    private const string Home = @"C:\Users\demo";

    [Fact] public void Browser_positive() =>
        Assert.NotNull(Run("SENS-BROWSER", R(E(EventKind.FileRead, Home + @"\AppData\Local\Google\Chrome\User Data\Default\Login Data"))));
    [Fact] public void Browser_negative() =>
        Assert.Null(Run("SENS-BROWSER", R(E(EventKind.FileRead, Work + @"\a.txt"))));

    [Fact] public void Creds_positive_ssh() =>
        Assert.NotNull(Run("SENS-CREDS", R(E(EventKind.FileRead, Home + @"\.ssh\id_rsa"))));
    [Fact] public void Creds_positive_env() =>
        Assert.NotNull(Run("SENS-CREDS", R(E(EventKind.FileRead, Home + @"\project\.env"))));
    [Fact] public void Creds_negative() =>
        Assert.Null(Run("SENS-CREDS", R(E(EventKind.FileRead, Home + @"\Documents\notes.txt"))));

    [Fact] public void GameAccounts_positive() =>
        Assert.NotNull(Run("SENS-GAME-ACCOUNTS", R(E(EventKind.FileRead, @"C:\Program Files (x86)\Steam\config\loginusers.vdf"))));
    [Fact] public void GameAccounts_negative() =>
        Assert.Null(Run("SENS-GAME-ACCOUNTS", R(E(EventKind.FileRead, Work + @"\a.txt"))));

    [Fact] public void RunKey_positive() =>
        Assert.NotNull(Run("PERSIST-RUNKEY", R(E(EventKind.RegistryWrite, @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\X"))));
    [Fact] public void RunKey_negative_read() =>
        Assert.Null(Run("PERSIST-RUNKEY", R(E(EventKind.RegistryRead, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"))));

    [Fact] public void Startup_positive() =>
        Assert.NotNull(Run("PERSIST-STARTUP", R(E(EventKind.FileWrite, Home + @"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk"))));
    [Fact] public void Startup_negative() =>
        Assert.Null(Run("PERSIST-STARTUP", R(E(EventKind.FileWrite, Work + @"\a.lnk"))));

    [Fact] public void Task_positive() =>
        Assert.NotNull(Run("PERSIST-TASK", R(E(EventKind.ProcessStart, @"C:\Windows\System32\schtasks.exe", true, "schtasks /create /tn x /tr y"))));
    [Fact] public void Task_negative_query() =>
        Assert.Null(Run("PERSIST-TASK", R(E(EventKind.ProcessStart, @"C:\Windows\System32\schtasks.exe", true, "schtasks /query"))));

    [Fact] public void Net_positive_lists_distinct()
    {
        var f = Run("NET-OUTBOUND", R(E(EventKind.NetworkConnect, "a.invalid:443"), E(EventKind.DnsQuery, "b.invalid")));
        Assert.NotNull(f);
        Assert.Contains("a.invalid", f!.Title);
        Assert.Contains("b.invalid", f.Title);
    }
    [Fact] public void Net_negative() =>
        Assert.Null(Run("NET-OUTBOUND", R(E(EventKind.FileWrite, Work + @"\a.txt", true))));

    [Fact] public void Lolbin_certutil() =>
        Assert.NotNull(Run("PROC-LOLBIN", R(E(EventKind.ProcessStart, @"C:\Windows\System32\certutil.exe", true, "certutil -urlcache"))));
    [Fact] public void Lolbin_encoded_powershell() =>
        Assert.NotNull(Run("PROC-LOLBIN", R(E(EventKind.ProcessStart, @"C:\Windows\System32\powershell.exe", true, "powershell -enc AAAA"))));
    [Fact] public void Lolbin_negative_plain_powershell() =>
        Assert.Null(Run("PROC-LOLBIN", R(E(EventKind.ProcessStart, @"C:\Windows\System32\powershell.exe", true, "powershell -File a.ps1"))));

    [Fact] public void DownloadExec_pipe_to_iex() =>
        Assert.NotNull(Run("PROC-DOWNLOAD-EXEC", R(E(EventKind.ProcessStart, "powershell.exe", true, "iwr https://example.com/a.ps1 | iex"))));
    [Fact] public void DownloadExec_sequence() =>
        Assert.NotNull(Run("PROC-DOWNLOAD-EXEC", R(
            E(EventKind.NetworkConnect, "example.com:443"),
            E(EventKind.FileWrite, Work + @"\setup.exe", true),
            E(EventKind.ProcessStart, Work + @"\setup.exe", true))));
    [Fact] public void DownloadExec_negative_download_only() =>
        Assert.Null(Run("PROC-DOWNLOAD-EXEC", R(
            E(EventKind.NetworkConnect, "example.com:443"),
            E(EventKind.FileWrite, Work + @"\data.txt", true))));

    [Fact] public void OutsideScope_positive() =>
        Assert.NotNull(Run("FS-OUTSIDE-SCOPE", R(E(EventKind.FileWrite, Home + @"\Documents\x.txt"))));
    [Fact] public void OutsideScope_negative_inside_work() =>
        Assert.Null(Run("FS-OUTSIDE-SCOPE", R(E(EventKind.FileWrite, Work + @"\sub\x.txt", true))));

    [Fact] public void MassEnum_positive() =>
        Assert.NotNull(Run("FS-MASS-ENUM", R(Enumerate(6))));
    [Fact] public void MassEnum_negative_at_threshold() =>
        Assert.Null(Run("FS-MASS-ENUM", R(Enumerate(5))));
    [Fact] public void MassEnum_respects_configured_threshold() =>
        Assert.NotNull(Run("FS-MASS-ENUM", R(Enumerate(3)), new RuleOptions { MassEnumThreshold = 2 }));

    [Fact] public void InfoNothing_positive() =>
        Assert.NotNull(Run("INFO-NOTHING", R(E(EventKind.FileWrite, Work + @"\a.txt", true))));
    [Fact] public void InfoNothing_negative() =>
        Assert.Null(Run("INFO-NOTHING", R(E(EventKind.NetworkConnect, "a.invalid:443"))));

    private static ActivityEvent[] Enumerate(int n) =>
        Enumerable.Range(0, n).Select(i => E(EventKind.FileEnumerate, $@"C:\Users\demo\Folder{i}")).ToArray();
}

public class VerdictLogicTests
{
    private static Finding F(string rule, Severity s, string cat) => new("F", rule, s, cat, "t", Array.Empty<string>());
    private static readonly RuleOptions O = new();

    [Fact] public void Level_high_is_risky() =>
        Assert.Equal(VerdictLevel.Risky, VerdictLogic.Level(new[] { F("A", Severity.High, "x"), F("B", Severity.Medium, "y") }));
    [Fact] public void Level_medium_is_caution() =>
        Assert.Equal(VerdictLevel.Caution, VerdictLogic.Level(new[] { F("B", Severity.Medium, "y") }));
    [Fact] public void Level_info_only_is_safe() =>
        Assert.Equal(VerdictLevel.LooksSafe, VerdictLogic.Level(new[] { F("I", Severity.Info, "Info") }));

    [Fact] public void Certainty_medium_across_categories_is_uncertain() =>
        Assert.Equal(Certainty.Uncertain, VerdictLogic.AssessCertainty(T.R(),
            new[] { F("A", Severity.Medium, "x"), F("B", Severity.Medium, "y") }, O));
    [Fact] public void Certainty_single_category_medium_is_confident() =>
        Assert.Equal(Certainty.Confident, VerdictLogic.AssessCertainty(T.R(),
            new[] { F("A", Severity.Medium, "x") }, O));
    [Fact] public void Certainty_network_only_is_uncertain() =>
        Assert.Equal(Certainty.Uncertain, VerdictLogic.AssessCertainty(T.R(),
            new[] { F("NET-OUTBOUND", Severity.Medium, "Network") }, O));
    [Fact] public void Certainty_short_run_is_uncertain() =>
        Assert.Equal(Certainty.Uncertain, VerdictLogic.AssessCertainty(T.R() with { DurationMs = 10 }, Array.Empty<Finding>(), O));
    [Fact] public void Certainty_nonzero_exit_is_uncertain() =>
        Assert.Equal(Certainty.Uncertain, VerdictLogic.AssessCertainty(T.R() with { ExitCode = 1 }, Array.Empty<Finding>(), O));
    [Fact] public void Certainty_explainer_fallback_is_uncertain() =>
        Assert.Equal(Certainty.Uncertain, VerdictLogic.AssessCertainty(T.R(), Array.Empty<Finding>(), O, explainerFellBack: true));
    [Fact] public void Certainty_high_finding_is_confident() =>
        Assert.Equal(Certainty.Confident, VerdictLogic.AssessCertainty(T.R(),
            new[] { F("A", Severity.High, "x"), F("B", Severity.Medium, "y") }, O));
}
