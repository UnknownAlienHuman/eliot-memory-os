using Eliot.Operator.Protocol;
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
        try
        {
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

    private static void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs args)
    {
        WriteStartupDiagnostic("application-unhandled", args.Exception);
    }

    private static void WriteStartupDiagnostic(string stage, Exception? exception = null)
    {
        try
        {
            var directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Eliot",
                "logs");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "operator-startup.log");
            // Bounded redacted record: stage, exception type, and HRESULT
            // only. Messages, stack traces, pipe names, nonces, endpoints,
            // credentials, and command/query bodies never enter the log.
            var record = OperatorDiagnostics.FormatStartupRecord(
                stage, exception?.GetType().FullName, exception?.HResult);
            var info = new FileInfo(path);
            if (info.Exists && OperatorDiagnostics.ShouldRotate(info.Length))
            {
                File.Delete(path);
            }
            File.AppendAllText(path, $"{record}{Environment.NewLine}");
        }
        catch
        {
            // Startup diagnostics must never mask the original WinUI failure.
        }
    }
}
