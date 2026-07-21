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
            var details = exception is null
                ? string.Empty
                : $" hresult=0x{exception.HResult:X8} type={exception.GetType().FullName} message={exception.Message}{Environment.NewLine}{exception}";
            File.AppendAllText(
                Path.Combine(directory, "operator-startup.log"),
                $"{DateTimeOffset.UtcNow:O} {stage}{details}{Environment.NewLine}");
        }
        catch
        {
            // Startup diagnostics must never mask the original WinUI failure.
        }
    }
}
