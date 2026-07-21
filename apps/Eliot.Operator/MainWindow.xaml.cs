using Eliot.Operator.Services;
using Eliot.Operator.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;

namespace Eliot.Operator;

public sealed partial class MainWindow : Window
{
    private readonly GovernorPipeClient _client;
    public MainViewModel ViewModel { get; }

    public MainWindow()
    {
        _client = new GovernorPipeClient(new RuntimeDiscoveryService());
        ViewModel = new MainViewModel(_client);
        InitializeComponent();
        ViewModel.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(MainViewModel.StatusSeverity)) SyncBannerSeverity();
        };
        SyncBannerSeverity();
        Navigation.SelectedItem = Navigation.MenuItems[0];
        Closed += MainWindow_OnClosed;
        _ = RefreshProjectionAsync();
    }

    private async void Navigation_OnSelectionChanged(
        NavigationView sender,
        NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItemContainer?.Tag is string section)
        {
            await ViewModel.SelectSectionAsync(section);
            RenderGraph();
        }
    }

    private async void CommandPalette_OnQuerySubmitted(
        AutoSuggestBox sender,
        AutoSuggestBoxQuerySubmittedEventArgs args)
    {
        await ViewModel.ExecutePaletteAsync(args.ChosenSuggestion?.ToString() ?? args.QueryText);
        RenderGraph();
    }

    private void CommandPaletteAccelerator_OnInvoked(
        KeyboardAccelerator sender,
        KeyboardAcceleratorInvokedEventArgs args)
    {
        CommandPalette.Focus(FocusState.Keyboard);
        args.Handled = true;
    }

    private async void Refresh_OnClick(object sender, RoutedEventArgs e) => await RefreshProjectionAsync();
    private void Cancel_OnClick(object sender, RoutedEventArgs e) => ViewModel.CancelActiveRequest();
    private async void ApplyFilter_OnClick(object sender, RoutedEventArgs e) => await RefreshProjectionAsync();
    private void SaveFilter_OnClick(object sender, RoutedEventArgs e) => ViewModel.SaveCurrentFilter();

    private async void ApplySavedFilter_OnClick(object sender, RoutedEventArgs e)
    {
        await ViewModel.ApplySavedFilterAsync();
        SyncNavigationSelection();
        RenderGraph();
    }

    private async void ClearFilter_OnClick(object sender, RoutedEventArgs e)
    {
        await ViewModel.ClearFiltersAsync();
        RenderGraph();
    }

    private async void LoadMore_OnClick(object sender, RoutedEventArgs e)
    {
        await ViewModel.LoadMoreAsync();
        RenderGraph();
    }

    private async void ExecuteAction_OnClick(object sender, RoutedEventArgs e)
    {
        await ViewModel.ExecuteSelectedActionAsync();
        RenderGraph();
    }

    private async void ExecuteQuery_OnClick(object sender, RoutedEventArgs e)
    {
        await RefreshProjectionAsync();
    }

    private void ProjectionList_OnSelectionChanged(object sender, SelectionChangedEventArgs e) => RenderGraph();
    private void Action_OnSelectionChanged(object sender, SelectionChangedEventArgs e) => RenderGraph();
    private async void Start_OnClick(object sender, RoutedEventArgs e) => await ViewModel.RunCommandAsync("start_run");
    private async void Pause_OnClick(object sender, RoutedEventArgs e) => await ViewModel.RunCommandAsync("pause_run");
    private async void Resume_OnClick(object sender, RoutedEventArgs e) => await ViewModel.RunCommandAsync("resume_run");
    private async void CancelRun_OnClick(object sender, RoutedEventArgs e) => await ViewModel.RunCommandAsync("cancel_run");

    private async Task RefreshProjectionAsync()
    {
        await ViewModel.RefreshAsync();
        RenderGraph();
    }

    private void SyncNavigationSelection()
    {
        Navigation.SelectedItem = Navigation.MenuItems
            .OfType<NavigationViewItem>()
            .FirstOrDefault(item => Equals(item.Tag, ViewModel.CurrentPage.Tag));
    }

    private void RenderGraph()
    {
        QueryLabPanel.Visibility = ViewModel.IsQueryPage ? Visibility.Visible : Visibility.Collapsed;
        RunControls.Visibility = ViewModel.CurrentPage.Tag == "autonomy"
            ? Visibility.Visible
            : Visibility.Collapsed;
        CandidateDispositionBox.Visibility = ViewModel.SelectedAction?.Command == "review_candidate"
            ? Visibility.Visible
            : Visibility.Collapsed;
        GraphCanvas.Children.Clear();
        GraphCanvas.Visibility = ViewModel.IsGraphPage ? Visibility.Visible : Visibility.Collapsed;
        if (!ViewModel.IsGraphPage) return;

        var nodes = ViewModel.Records
            .Select(record => record.RecordRef)
            .Concat(ViewModel.Records.SelectMany(record => record.Relationships.Select(edge => edge.TargetRef)))
            .Distinct(StringComparer.Ordinal)
            .Take(30)
            .ToArray();
        if (nodes.Length == 0) return;

        var width = Math.Max(GraphCanvas.ActualWidth, 680);
        const double height = 220;
        var centerX = width / 2;
        var centerY = height / 2;
        var radiusX = Math.Max(180, width / 2 - 100);
        const double radiusY = 78;
        var positions = nodes
            .Select((node, index) =>
            {
                var angle = (Math.PI * 2 * index / nodes.Length) - Math.PI / 2;
                return new KeyValuePair<string, (double X, double Y)>(
                    node,
                    (centerX + radiusX * Math.Cos(angle), centerY + radiusY * Math.Sin(angle)));
            })
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);

        var edgeBrush = ResourceBrush("CardStrokeColorDefaultBrush");
        foreach (var record in ViewModel.Records.Take(30))
        {
            if (!positions.TryGetValue(record.RecordRef, out var source)) continue;
            foreach (var relationship in record.Relationships)
            {
                if (!positions.TryGetValue(relationship.TargetRef, out var target)) continue;
                GraphCanvas.Children.Add(new Line
                {
                    X1 = source.X,
                    Y1 = source.Y,
                    X2 = target.X,
                    Y2 = target.Y,
                    Stroke = edgeBrush,
                    StrokeThickness = 2,
                    IsHitTestVisible = false
                });
                var edgeLabel = new TextBlock
                {
                    Text = string.Join(
                        " · ",
                        new[] { relationship.Relation, relationship.EvidenceRef, relationship.ObservedAt }
                            .Where(value => !string.IsNullOrWhiteSpace(value))),
                    FontSize = 10,
                    TextWrapping = TextWrapping.Wrap,
                    MaxWidth = 180,
                    IsHitTestVisible = false
                };
                AutomationProperties.SetName(edgeLabel, $"Edge {relationship.Relation} provenance");
                Canvas.SetLeft(edgeLabel, (source.X + target.X) / 2);
                Canvas.SetTop(edgeLabel, (source.Y + target.Y) / 2);
                GraphCanvas.Children.Add(edgeLabel);
            }
        }

        var nodeBackground = ResourceBrush("CardBackgroundFillColorSecondaryBrush");
        var nodeBorder = ResourceBrush("AccentFillColorDefaultBrush");
        foreach (var node in nodes)
        {
            var position = positions[node];
            var label = new TextBlock
            {
                Text = ShortLabel(node),
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 132,
                FontSize = 12,
                IsTextSelectionEnabled = true
            };
            var button = new Button
            {
                Content = label,
                Background = nodeBackground,
                BorderBrush = nodeBorder,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(7),
                MaxWidth = 145,
                Tag = node
            };
            button.Click += GraphNode_OnClick;
            AutomationProperties.SetName(button, $"Expand graph node {node}");
            Canvas.SetLeft(button, position.X - 62);
            Canvas.SetTop(button, position.Y - 22);
            GraphCanvas.Children.Add(button);
        }
    }

    private async void GraphNode_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string nodeRef })
        {
            await ViewModel.ExpandGraphNodeAsync(nodeRef);
            RenderGraph();
        }
    }

    private static Brush ResourceBrush(string key) =>
        Application.Current.Resources.TryGetValue(key, out var value) && value is Brush brush
            ? brush
            : new SolidColorBrush(Microsoft.UI.Colors.Gray);

    private static string ShortLabel(string value) => value.Length <= 34 ? value : $"{value[..31]}…";

    private void SyncBannerSeverity()
    {
        StatusBanner.Severity = ViewModel.StatusSeverity switch
        {
            OperatorBannerSeverity.Success => InfoBarSeverity.Success,
            OperatorBannerSeverity.Warning => InfoBarSeverity.Warning,
            OperatorBannerSeverity.Error => InfoBarSeverity.Error,
            _ => InfoBarSeverity.Informational
        };
    }

    private async void MainWindow_OnClosed(object sender, WindowEventArgs args) => await _client.DisposeAsync();
}
