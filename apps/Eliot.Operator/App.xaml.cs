using Eliot.Operator.Protocol;
using Eliot.Operator.Services;
using Microsoft.UI.Xaml;

namespace Eliot.Operator;

public partial class App : Application
{
    private Window? _window;

    public App()
    {
        UnhandledException += OnUnhandledException;
        WriteStartupDiagnostic("app-constructor:begin");
        try
        {
            InitializeComponent();
            WriteStartupDiagnostic("app-constructor:xaml-ready");
        }
        catch (Exception exception)
        {
            WriteStartupDiagnostic("app-constructor:failed", exception);
            throw;
        }
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        WriteStartupDiagnostic("launch:begin");
        // Bounded redacted record of the wire adapter this process pinned:
        // schema, contract hash, single consumer, proof ceiling and removal
        // condition. No endpoint, nonce, credential or payload.
        WriteAdapterDiagnostic(LegacyOperatorAdapter.Describe());
        try
        {
            // The UI is a broker-owned user-session child (I1.3): it launches
            // only inside an authenticated interactive Windows user session.
            // The identity proof runs eagerly at launch so a sessionless
            // process fails closed before any window opens, instead of opening
            // a window whose every request then fails at the transport.
            ProveInteractiveSession();
            _window = new MainWindow();
            WriteStartupDiagnostic("launch:window-created");
            _window.Activate();
            WriteStartupDiagnostic("launch:window-active");
        }
        catch (Exception exception)
        {
            WriteStartupDiagnostic("launch:failed", exception);
            throw;
        }
    }

    private static void ProveInteractiveSession()
    {
        // Fail-closed: without a proven installation, user SID and logon
        // session there is no handoff binding and therefore no UI. The
        // exception carries a closed reason, never identity values.
        _ = OperatorProcessIdentityProvider.Current;
    }

    private static void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs args)
    {
        WriteStartupDiagnostic("application-unhandled", args.Exception);
    }

    private static void WriteAdapterDiagnostic(string description)
    {
        try
        {
            AppendStartupRecord(OperatorDiagnostics.FormatAdapterRecord(description));
        }
        catch
        {
            // Startup diagnostics must never mask the original WinUI failure.
        }
    }

    private static void WriteStartupDiagnostic(string stage, Exception? exception = null)
    {
        try
        {
            // Bounded redacted record: stage, exception type, and HRESULT
            // only. Messages, stack traces, pipe names, nonces, endpoints,
            // credentials, and command/query bodies never enter the log.
            AppendStartupRecord(OperatorDiagnostics.FormatStartupRecord(
                stage, exception?.GetType().FullName, exception?.HResult));
        }
        catch
        {
            // Startup diagnostics must never mask the original WinUI failure.
        }
    }

    private static void AppendStartupRecord(string record)
    {
        var directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Eliot",
            "logs");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "operator-startup.log");
        var info = new FileInfo(path);
        if (info.Exists && OperatorDiagnostics.ShouldRotate(info.Length))
        {
            File.Delete(path);
        }
        File.AppendAllText(path, $"{record}{Environment.NewLine}");
    }
}
