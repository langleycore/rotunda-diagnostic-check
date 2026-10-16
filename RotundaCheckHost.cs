using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Reflection;
using System.Text;

[assembly: AssemblyTitle("Rotunda Diagnostic Check")]
[assembly: AssemblyDescription("Laptop check for IDS, FDRS, FJDS, VCI Manager, and VMS.")]
[assembly: AssemblyCompany("Rotunda")]
[assembly: AssemblyProduct("Rotunda Diagnostic Check")]
[assembly: AssemblyFileVersion("1.0.0.0")]

internal sealed class RotundaHost : PSHost
{
    private readonly Guid _id = Guid.NewGuid();
    private readonly RotundaUI _ui = new RotundaUI();
    public int ExitCode;

    public override string Name { get { return "Rotunda Diagnostic Check"; } }
    public override Version Version { get { return new Version(1, 0); } }
    public override Guid InstanceId { get { return _id; } }
    public override PSHostUserInterface UI { get { return _ui; } }
    public override CultureInfo CurrentCulture { get { return CultureInfo.CurrentCulture; } }
    public override CultureInfo CurrentUICulture { get { return CultureInfo.CurrentUICulture; } }
    public override void SetShouldExit(int exitCode) { ExitCode = exitCode; }
    public override void EnterNestedPrompt() { }
    public override void ExitNestedPrompt() { }
    public override void NotifyBeginApplication() { }
    public override void NotifyEndApplication() { }
}

internal sealed class RotundaUI : PSHostUserInterface
{
    private readonly RotundaRaw _raw = new RotundaRaw();

    public override PSHostRawUserInterface RawUI { get { return _raw; } }
    public override bool SupportsVirtualTerminal { get { return true; } }

    public override void Write(string value) { Console.Write(value); }
    public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
    {
        if (foregroundColor == backgroundColor) foregroundColor = ConsoleColor.Gray;
        var fg = Console.ForegroundColor;
        var bg = Console.BackgroundColor;
        Console.ForegroundColor = foregroundColor;
        Console.BackgroundColor = backgroundColor;
        Console.Write(value);
        Console.ForegroundColor = fg;
        Console.BackgroundColor = bg;
    }
    public override void WriteLine(string value) { Console.WriteLine(value); }
    public override void WriteLine(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
    {
        Write(foregroundColor, backgroundColor, value);
        Console.WriteLine();
    }
    public override void WriteDebugLine(string message) { }
    public override void WriteErrorLine(string value) { WriteLine(ConsoleColor.Red, Console.BackgroundColor, value); }
    public override void WriteVerboseLine(string message) { }
    public override void WriteWarningLine(string message) { WriteLine(ConsoleColor.Yellow, Console.BackgroundColor, message); }
    public override void WriteProgress(long sourceId, ProgressRecord record) { }
    public override string ReadLine() { return Console.ReadLine(); }
    public override System.Security.SecureString ReadLineAsSecureString() { throw new NotSupportedException(); }

    public override Dictionary<string, PSObject> Prompt(string caption, string message, Collection<FieldDescription> descriptions)
    {
        if (!string.IsNullOrEmpty(message)) Console.WriteLine(message);
        var result = new Dictionary<string, PSObject>();
        foreach (FieldDescription field in descriptions)
        {
            string entered = Console.ReadLine();
            result[field.Name] = PSObject.AsPSObject(entered ?? "");
        }
        return result;
    }

    public override int PromptForChoice(string caption, string message, Collection<ChoiceDescription> choices, int defaultChoice)
    {
        return defaultChoice;
    }

    public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName)
    {
        throw new NotSupportedException();
    }

    public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName, PSCredentialTypes allowedCredentialTypes, PSCredentialUIOptions options)
    {
        throw new NotSupportedException();
    }
}

internal sealed class RotundaRaw : PSHostRawUserInterface
{
    public RotundaRaw()
    {
        ForegroundColor = ConsoleColor.Gray;
        BackgroundColor = ConsoleColor.Black;
    }

    public override ConsoleColor BackgroundColor { get; set; }
    public override ConsoleColor ForegroundColor { get; set; }
    public override Size BufferSize { get { return new Size(Console.BufferWidth, Console.BufferHeight); } set { } }
    public override Coordinates CursorPosition { get; set; }
    public override int CursorSize { get; set; }
    public override bool KeyAvailable { get { return Console.KeyAvailable; } }
    public override Size MaxPhysicalWindowSize { get { return new Size(Console.LargestWindowWidth, Console.LargestWindowHeight); } }
    public override Size MaxWindowSize { get { return MaxPhysicalWindowSize; } }
    public override Coordinates WindowPosition { get; set; }
    public override Size WindowSize { get { return new Size(Console.WindowWidth, Console.WindowHeight); } set { } }
    public override string WindowTitle { get { return Console.Title; } set { Console.Title = value; } }
    public override void FlushInputBuffer() { }
    public override KeyInfo ReadKey(ReadKeyOptions options) { throw new NotSupportedException(); }
    public override void ScrollBufferContents(Rectangle source, Coordinates destination, Rectangle clip, BufferCell fill) { }
    public override BufferCell[,] GetBufferContents(Rectangle rectangle) { return new BufferCell[0, 0]; }
    public override void SetBufferContents(Coordinates origin, BufferCell[,] contents) { }
    public override void SetBufferContents(Rectangle rectangle, BufferCell fill) { }
}

internal static class Program
{
    private static int Main()
    {
        Console.Title = "Rotunda Diagnostic Check";
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.BackgroundColor = ConsoleColor.Black;
        string exeDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        Environment.SetEnvironmentVariable("ROTUNDA_DIR", exeDir);

        Console.WriteLine("Rotunda diagnostic check");
        Console.WriteLine();

        string script = LoadScript(exeDir);
        if (script == null)
        {
            WaitForEnter();
            return 1;
        }

        var host = new RotundaHost();
        try
        {
            using (var runspace = System.Management.Automation.Runspaces.RunspaceFactory.CreateRunspace(host))
            {
                runspace.Open();
                using (var ps = PowerShell.Create())
                {
                    ps.Runspace = runspace;
                    ps.AddScript(script);
                    try { ps.Invoke(); }
                    catch (Exception ex)
                    {
                        if (host.ExitCode == 0) Console.WriteLine(ex.Message);
                    }
                    foreach (var err in ps.Streams.Error)
                    {
                        Console.WriteLine(err.ToString());
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            WaitForEnter();
            return 1;
        }

        // The script only waits when PowerShell itself is the host. From this exe the window was closing on its own.
        WaitForEnter();
        return host.ExitCode;
    }

    private static void WaitForEnter()
    {
        Console.WriteLine();
        Console.WriteLine("Press Enter to close.");
        try { Console.ReadLine(); }
        catch { }
    }

    // Script stays in its own file, same folder as the exe.
    // Packing it inside the exe was a mistake. Defender read that build as a trojan.
    private static string LoadScript(string exeDir)
    {
        string path = Path.Combine(exeDir, "RotundaDiagnosticCheck.ps1");
        if (!File.Exists(path))
        {
            Console.WriteLine("RotundaDiagnosticCheck.ps1 has to be in the same folder as this program.");
            return null;
        }

        var sb = new StringBuilder();
        foreach (string line in File.ReadAllLines(path))
        {
            if (line.StartsWith("#Requires", StringComparison.OrdinalIgnoreCase)) continue;
            sb.AppendLine(line);
        }
        return sb.ToString();
    }
}
