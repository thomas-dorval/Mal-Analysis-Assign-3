using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;

const string usage = "Usage: dotnet run -- <executable-path>\n" +
                     "Example: dotnet run -- ./sample-malware-binary";

if (args.Length != 1 || args[0] == "-h" || args[0] == "--help")
{
    Console.WriteLine(usage);
    return;
}

var targetPath = args[0];
if (!File.Exists(targetPath))
{
    Console.Error.WriteLine($"Error: executable not found: {targetPath}");
    return;
}

var stracePath = FindExecutable("strace");
if (stracePath is null)
{
    Console.Error.WriteLine("Error: 'strace' is not installed or not available in PATH.");
    Console.Error.WriteLine("Install strace and retry.");
    return;
}

var traceFile = Path.Combine(Path.GetTempPath(), $"strace-{Guid.NewGuid():N}.log");
try
{
    var straceResult = RunStrace(stracePath, targetPath, traceFile);
    if (!straceResult.Success)
    {
        Console.Error.WriteLine("Error: failed to execute strace.");
        Console.Error.WriteLine(straceResult.ErrorOutput);
        return;
    }

    var (traceLines, tracePid) = GatherTraceFiles(traceFile);
    var report = AnalyzeTrace(Path.GetFileName(targetPath), traceLines);
    if (report.Pid is null && tracePid is not null)
        report.Pid = tracePid;
    PrintReport(report);
}
finally
{
    try
    {
        var dir = Path.GetDirectoryName(traceFile) ?? Path.GetTempPath();
        var baseName = Path.GetFileName(traceFile);

        if (File.Exists(traceFile))
            File.Delete(traceFile);

        if (Directory.Exists(dir))
        {
            foreach (var extraFile in Directory.GetFiles(dir, baseName + ".*"))
            {
                try
                {
                    File.Delete(extraFile);
                }
                catch
                {
                    // ignore cleanup errors for extra trace files.
                }
            }
        }
    }
    catch
    {
        // Best effort cleanup; ignore cleanup errors.
    }
}

static (string[] Lines, string? Pid) GatherTraceFiles(string traceFile)
{
    var dir = Path.GetDirectoryName(traceFile) ?? Path.GetTempPath();
    var baseName = Path.GetFileName(traceFile);
    var traceFiles = Directory.Exists(dir)
        ? Directory.GetFiles(dir, baseName + ".*")
        : Array.Empty<string>();

    if (File.Exists(traceFile))
        traceFiles = traceFiles.Concat(new[] { traceFile }).ToArray();

    string? pid = null;
    foreach (var path in traceFiles)
    {
        var ext = Path.GetExtension(path).TrimStart('.');
        if (int.TryParse(ext, out _) && pid is null)
            pid = ext;
    }

    var uniqueLines = new HashSet<string>();
    const int maxLines = 50000; // Limit to prevent excessive processing
    foreach (var path in traceFiles.Distinct())
    {
        if (uniqueLines.Count >= maxLines) break;
        foreach (var line in File.ReadLines(path))
        {
            uniqueLines.Add(line.Trim());
            if (uniqueLines.Count >= maxLines) break;
        }
    }

    return (uniqueLines.ToArray(), pid);
}

static string? FindExecutable(string name)
{
    try
    {
        var psi = new ProcessStartInfo
        {
            FileName = "which",
            ArgumentList = { name },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var proc = Process.Start(psi);
        if (proc is null)
            return null;

        var output = proc.StandardOutput.ReadToEnd().Trim();
        proc.WaitForExit();
        return string.IsNullOrWhiteSpace(output) ? null : output.Split('\n')[0].Trim();
    }
    catch
    {
        return null;
    }
}

static (bool Success, string ErrorOutput) RunStrace(string stracePath, string targetPath, string traceFile)
{
    var psi = new ProcessStartInfo
    {
        FileName = "sudo",
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true,
    };

    psi.ArgumentList.Add(stracePath);
    psi.ArgumentList.Add("-ff");
    psi.ArgumentList.Add("-e");
    psi.ArgumentList.Add("trace=openat,read,write,unlink,chmod,chown,connect,file,network,process");
    psi.ArgumentList.Add("-o");
    psi.ArgumentList.Add(traceFile);
    psi.ArgumentList.Add("--");
    psi.ArgumentList.Add(targetPath);

    using var proc = Process.Start(psi);
    if (proc is null)
        return (false, "Unable to start strace process.");

    var error = proc.StandardError.ReadToEnd();
    const int timeoutMs = 10000; // 10 seconds
    if (!proc.WaitForExit(timeoutMs))
    {
        try
        {
            proc.Kill(true); // Force kill entire process tree
            if (!proc.WaitForExit(2000))
            {
                proc.Kill(); // Try again
                proc.WaitForExit(1000);
            }
        }
        catch
        {
            // Kill may fail; best effort
        }
    }

    return (proc.ExitCode == 0 || proc.ExitCode == 1, error);
}

static TraceReport AnalyzeTrace(string processName, string[] traceLines)
{
    var report = new TraceReport(processName);
    var readSecretsRegex = new Regex("\\b(open|stat|access|read|lstat)\\(.*\\\"(?<path>/etc/(passwd|shadow|group|sudoers))\\\"", RegexOptions.Compiled);
    var reverseShellFileRegex = new Regex("\\b(open|stat|access|read|execve)\\(.*\\\"(?<path>(/dev/tty|/dev/pts/[^\\\"]+|/root/\\.bash(rc|_history)|/home/[^/]+/\\.bash(rc|_history)|/etc/(bash\\.bashrc|profile|bashrc)))\\\"", RegexOptions.Compiled);
    var cronEditRegex = new Regex("\\b(open|openat|creat|write|truncate|unlink|unlinkat|link|symlink)\\(.*\\\"(?<path>/(etc/crontab|etc/cron\\.d/[^\\\"]+|var/spool/cron/[^\\\"]+|var/spool/cron/crontabs/[^\\\"]+))\\\"", RegexOptions.Compiled);
    var sensitiveTempCopyRegex = new Regex("\\b(openat|open|read|write|creat|execve)\\(.*\\\"(?<path>(/tmp|/var/tmp|/dev/shm|/run/user/[^/]+/tmp)/[^\\\"]+)\\\"", RegexOptions.Compiled);
    var tempCreateRegex = new Regex("\\b(openat|open|creat)\\(.*\\\"(?<path>(/tmp|/var/tmp|/dev/shm|/run/user/[^/]+/tmp)/[^\\\"]+)\\\".*\\b(O_CREAT|O_TRUNC|O_WRONLY|O_RDWR)\\b", RegexOptions.Compiled);
    var tempUnlinkRegex = new Regex("\\b(unlink|unlinkat|remove|rmdir)\\(.*\\\"(?<path>(/tmp|/var/tmp|/dev/shm|/run/user/[^/]+/tmp)/[^\\\"]+)\\\"", RegexOptions.Compiled);
    var browserTraverseRegex = new Regex("\\b(open|stat|access|read|lstat)\\(.*\\\"(?<path>/((root|home/[^/]+)/(\\.(mozilla/firefox|config/google-chrome|config/chromium|config/BraveSoftware/Brave-Browser)|\\.cache/(mozilla/firefox|google-chrome|chromium))/[^\\\"]*))\\\"", RegexOptions.Compiled);
    var textDataRegex = new Regex("\\b(open|read)\\(.*\\\"(?<path>[^\\\"]+\\.(txt|log|json|csv|html|htm|md|ini|conf|sqlite|db))\\\"", RegexOptions.Compiled);
    var recentFileRegex = new Regex("execve\\(\\\".*\\/(find|ls)\\\".*-mmin", RegexOptions.Compiled);
    var writeRootRegex = new Regex("\\b(open|creat|rename|truncate|unlink|link|symlink)\\(.*\\\"(?<path>/((sbin|bin|usr/bin|usr/sbin|usr/local/bin|opt)/[^\\\"]+))\\\"", RegexOptions.Compiled);
    var connectRegex = new Regex("\\bconnect\\([^,]+, \\{[^}]*sin_addr=inet_addr\\(\\\"(?<ip>[^\\\"]+)\\\"\\)", RegexOptions.Compiled);
    var sendRegex = new Regex("\\b(sendto|sendmsg|write|writev)\\([^,]+, .*\\)", RegexOptions.Compiled);
    var pidRegex = new Regex("^\\s*\\[(?<pid>\\d+)\\]", RegexOptions.Compiled);

    var sawSensitiveTemp = false;
    var sawTempLifeCycle = false;
    var sawBrowserTraversal = false;
    var sawTextDataScan = false;

    for (var index = 0; index < traceLines.Length; index++)
    {
        var line = traceLines[index];
        if (report.Pid == null)
        {
            var pidMatch = pidRegex.Match(line);
            if (pidMatch.Success)
                report.Pid = pidMatch.Groups["pid"].Value;
        }

        var readMatch = readSecretsRegex.Match(line);
        if (readMatch.Success)
        {
            report.AddFinding("spyware", line.Trim(), $"Accessed sensitive file {readMatch.Groups["path"].Value}");
        }

        var reverseMatch = reverseShellFileRegex.Match(line);
        if (reverseMatch.Success)
        {
            report.AddFinding("reverse shell", line.Trim(), $"Accessed terminal or shell-related file {reverseMatch.Groups["path"].Value}");
        }

        var cronMatch = cronEditRegex.Match(line);
        if (cronMatch.Success && !line.Contains("O_RDONLY", StringComparison.Ordinal))
        {
            report.AddFinding("rootkit", line.Trim(), $"Modified cron scheduling file {cronMatch.Groups["path"].Value}");
        }

        var writeRootMatch = writeRootRegex.Match(line);
        if (writeRootMatch.Success && !line.Contains("O_RDONLY", StringComparison.Ordinal))
        {
            report.AddFinding("rootkit", line.Trim(), $"Attempted to write or copy into system binary path {writeRootMatch.Groups["path"].Value}");
        }

        var connectMatch = connectRegex.Match(line);
        if (connectMatch.Success)
        {
            var ipValue = connectMatch.Groups["ip"].Value;
            if (IPAddress.TryParse(ipValue, out var ip) && !IsLocalOrPrivateIp(ip))
            {
                report.AddFinding("reverse shell", line.Trim(), $"Connected to external IP {ipValue}");
            }
            else if (IPAddress.TryParse(ipValue, out _))
            {
                report.AddFinding("spyware", line.Trim(), $"Opened connection to {ipValue}");
            }
        }

        if ((sendRegex.IsMatch(line) && line.Contains("socket", StringComparison.OrdinalIgnoreCase)) || line.Contains("sendto(", StringComparison.Ordinal) || line.Contains("sendmsg(", StringComparison.Ordinal))
        {
            report.AddFinding("spyware", line.Trim(), "Detected suspicious data send or socket activity");
        }

        if (tempCreateRegex.IsMatch(line))
        {
            report.AddFlag("created a temporary file in a runtime scratch directory", line.Trim(), string.Empty);
            sawTempLifeCycle = true;
        }

        if (tempUnlinkRegex.IsMatch(line))
        {
            report.AddFlag("removed a temporary file from a runtime scratch directory", line.Trim(), string.Empty);
            sawTempLifeCycle = true;
        }

        var sensitiveTempMatch = sensitiveTempCopyRegex.Match(line);
        if (sensitiveTempMatch.Success)
        {
            sawSensitiveTemp = true;
        }

        if (browserTraverseRegex.IsMatch(line))
        {
            sawBrowserTraversal = true;
            report.AddFinding("spyware", line.Trim(), "Traversed browser or user profile directories to examine stored browser data");
        }

        if (textDataRegex.IsMatch(line))
        {
            sawTextDataScan = true;
            report.AddFlag("accessed a text or data file that may contain user information", line.Trim(), string.Empty);
        }

        if (recentFileRegex.IsMatch(line))
        {
            report.AddFlag("detected use of find or ls with -mmin flag to identify recently modified files", line.Trim(), string.Empty);
        }

        if (line.Contains("openat(") && (line.Contains("/etc/cron.weekly/") || line.Contains("/bin/")) && line.Contains("write") && line.Contains("ELF"))
        {
            report.AddFinding("rootkit", line.Trim(), "Detected self-replication by writing executable files to system directories and cron jobs");
        }
    }

    if (sawSensitiveTemp && sawTempLifeCycle)
    {
        report.AddFlag("detected sensitive data exfiltration through temporary files", string.Empty, "Copied sensitive or temporary data into temp files and later removed them, which may indicate exfiltration preparation");
    }

    if (sawBrowserTraversal && sawTextDataScan)
    {
        report.AddFlag("detected browser profile data scanning behavior", string.Empty, "Scanned browser-related directories and opened text/data files, which is often associated with spyware behavior");
    }

    if (!report.FoundFindings)
    {
        report.AddFinding("no obvious malicious pattern detected", "No strong heuristic match found in strace output.", "The traced execution did not reveal the specific suspicious behaviors this tool is looking for.");
    }

    return report;
}

static bool IsLocalOrPrivateIp(IPAddress ip)
{
    if (IPAddress.IsLoopback(ip))
        return true;

    var bytes = ip.GetAddressBytes();
    return bytes.Length == 4 &&
           ((bytes[0] == 10) ||
            (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
            (bytes[0] == 192 && bytes[1] == 168));
}

static void PrintReport(TraceReport report)
{
    Console.WriteLine("Process name: " + report.ProcessName);
    Console.WriteLine("PID: " + (report.Pid ?? "unknown"));
    Console.WriteLine("Categories: " + string.Join(", ", report.Categories.Distinct()));
    if (report.Flags.Any())
    {
        Console.WriteLine("Flags: " + string.Join(", ", report.Flags.Distinct()));
    }
    Console.WriteLine();
    Console.WriteLine("Behavior summary:");
    foreach (var summary in report.Summaries)
    {
        Console.WriteLine("- " + summary);
    }
}

class TraceReport
{
    public string ProcessName { get; }
    public string? Pid { get; set; }
    public List<string> Categories { get; } = new();
    public List<string> Flags { get; } = new();
    public List<string> Summaries { get; } = new();
    public bool FoundFindings { get; private set; }

    public TraceReport(string processName)
    {
        ProcessName = processName;
    }

    public void AddFinding(string category, string line, string summary)
    {
        FoundFindings = true;
        Categories.Add(category);
        Summaries.Add($"{summary} -> {line}");
    }

    public void AddFlag(string flag, string line, string summary)
    {
        FoundFindings = true;
        Flags.Add(flag);
        if (!string.IsNullOrEmpty(summary))
            Summaries.Add($"{summary}" + (string.IsNullOrEmpty(line) ? string.Empty : $" -> {line}"));
        else if (!string.IsNullOrEmpty(line))
            Summaries.Add($"Flag: {flag} -> {line}");
        else
            Summaries.Add($"Flag: {flag}");
    }

    public void AddSuspiciousLine(string line)
    {
        FoundFindings = true;
        Categories.Add("suspicious network/data flow");
        Summaries.Add($"Detected a suspicious network/data operation: {line}");
    }
}
