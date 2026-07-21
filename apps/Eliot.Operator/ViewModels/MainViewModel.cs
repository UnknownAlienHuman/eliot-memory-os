using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Eliot.Operator.Protocol;
using Eliot.Operator.Services;

namespace Eliot.Operator.ViewModels;

public enum OperatorBannerSeverity
{
    Informational,
    Success,
    Warning,
    Error
}

public sealed record OperatorPageDefinition(string Tag, string Title, string Description, bool RequiresTask);
public sealed record SavedFilterViewModel(string Name, string PageTag, string Search, string? Kind, string? Status, string? Authority);
public sealed record OperatorTaskContext(string ProjectId, string TaskId, ulong Revision);

public static class OperatorPageCatalog
{
    public static readonly IReadOnlyList<OperatorPageDefinition> All =
    [
        new("overview", "Overview", "Runtime, queues, projects, approvals, incidents and storage pressure.", false),
        new("tasks_work", "Tasks and Work", "Contracts, acceptance, work dependencies, leases, budgets and finish state.", true),
        new("task_cognition", "Task Cognition", "Epistemic state, causal bridge, memory decisions, next action and verifier gaps.", true),
        new("memory_explorer", "Memory Explorer", "Governor-mediated memory records, provenance, lifecycle and influence.", true),
        new("causal_provenance", "Causal and Provenance Graph", "Bounded native graph expansion with evidence-bearing edges.", true),
        new("schema_contracts", "Schema and Contracts", "Read-only canonical families, ownership, authority and migration surface.", false),
        new("query_lab", "Query and Inspection Lab", "Saved semantic queries over bounded Governor read operations.", false),
        new("experience_skills", "Experience and Skills", "Cases, patterns, transfer evidence, procedures and curator candidates.", true),
        new("sleep_meta", "Sleep and Meta Lab", "Replay, holdout, baseline/candidate comparison and promotion evidence.", true),
        new("agents_routing", "Agents and Routing", "Hosts, capability envelopes, leases, contours and route decisions.", true),
        new("autonomy", "Autonomy Runs", "Bounded contracts, budgets, assignments, tripwires and completion proof.", true),
        new("approvals", "Approvals", "Exact action hash, risk, write set, verifier, rollback and decision receipts.", true),
        new("timeline_operations", "Timeline, Incidents and Operations", "Transitions, receipts, incidents, recovery, backups and logs.", true),
    ];
}

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly IGovernorClient _client;
    private OperatorTaskContext? _taskContext;
    private CancellationTokenSource? _requestCancellation;
    private OperatorPageDefinition _currentPage = OperatorPageCatalog.All[0];
    private OperatorRecordView? _selectedRecord;
    private OperatorActionView? _selectedAction;
    private SavedFilterViewModel? _selectedSavedFilter;
    private bool _isBusy;
    private string _projectId = string.Empty;
    private string _taskId = string.Empty;
    private string _filterText = string.Empty;
    private string _kindFilter = string.Empty;
    private string _statusFilter = string.Empty;
    private string _authorityFilter = string.Empty;
    private string _actionInput = string.Empty;
    private string _queryOperation = "health_report";
    private string _queryParametersText = "{}";
    private string _resultMode = "human";
    private string _candidateDisposition = "promote";
    private string? _graphSelectedRef;
    private int _graphDepth = 1;
    private string _resultPayloadText = string.Empty;
    private string? _nextCursor;
    private string _resultSummary = "No projection loaded.";
    private string _statusTitle = "Disconnected";
    private string _statusMessage = "Waiting for the active ELIOT runtime.";
    private OperatorBannerSeverity _statusSeverity = OperatorBannerSeverity.Informational;

    public MainViewModel(IGovernorClient client)
    {
        _client = client;
        foreach (var page in OperatorPageCatalog.All)
        {
            PaletteSuggestions.Add($"Go: {page.Title}");
        }
        PaletteSuggestions.Add("Refresh current projection");
        PaletteSuggestions.Add("Cancel active request");
        PaletteSuggestions.Add("Load next page");
    }

    public ObservableCollection<OperatorRecordView> Records { get; } = [];
    public ObservableCollection<SavedFilterViewModel> SavedFilters { get; } = [];
    public ObservableCollection<string> PaletteSuggestions { get; } = [];
    public IReadOnlyList<string> QueryOperations { get; } =
        ["current_state", "recall_preview", "exact_evidence", "relationship_slice", "trace_replay", "health_report"];
    public IReadOnlyList<string> ResultModes { get; } = ["human", "json", "graph"];
    public IReadOnlyList<string> CandidateDispositions { get; } = ["promote", "reject", "demote", "archive"];

    public OperatorPageDefinition CurrentPage
    {
        get => _currentPage;
        private set
        {
            if (Set(ref _currentPage, value))
            {
                OnPropertyChanged(nameof(SectionTitle));
                OnPropertyChanged(nameof(SectionDescription));
                OnPropertyChanged(nameof(IsGraphPage));
                OnPropertyChanged(nameof(IsQueryPage));
            }
        }
    }

    public string SectionTitle => CurrentPage.Title;
    public string SectionDescription => CurrentPage.Description;
    public bool IsQueryPage => CurrentPage.Tag == "query_lab";
    public bool IsGraphPage => CurrentPage.Tag == "causal_provenance" || (IsQueryPage && ResultMode == "graph");
    public bool IsBusy { get => _isBusy; private set => Set(ref _isBusy, value); }
    public string ProjectId { get => _projectId; set => Set(ref _projectId, value.Trim()); }
    public string TaskId { get => _taskId; set => Set(ref _taskId, value.Trim()); }
    public string FilterText { get => _filterText; set => Set(ref _filterText, value); }
    public string KindFilter { get => _kindFilter; set => Set(ref _kindFilter, value); }
    public string StatusFilter { get => _statusFilter; set => Set(ref _statusFilter, value); }
    public string AuthorityFilter { get => _authorityFilter; set => Set(ref _authorityFilter, value); }
    public string ActionInput { get => _actionInput; set => Set(ref _actionInput, value); }
    public string QueryOperation { get => _queryOperation; set => Set(ref _queryOperation, value); }
    public string QueryParametersText { get => _queryParametersText; set => Set(ref _queryParametersText, value); }
    public string ResultMode
    {
        get => _resultMode;
        set
        {
            if (Set(ref _resultMode, value)) OnPropertyChanged(nameof(IsGraphPage));
        }
    }
    public string CandidateDisposition { get => _candidateDisposition; set => Set(ref _candidateDisposition, value); }
    public int GraphDepth { get => _graphDepth; set => Set(ref _graphDepth, Math.Clamp(value, 1, 3)); }
    public string ResultPayloadText { get => _resultPayloadText; private set => Set(ref _resultPayloadText, value); }
    public string ResultSummary { get => _resultSummary; private set => Set(ref _resultSummary, value); }
    public string StatusTitle { get => _statusTitle; private set => Set(ref _statusTitle, value); }
    public string StatusMessage { get => _statusMessage; private set => Set(ref _statusMessage, value); }
    public OperatorBannerSeverity StatusSeverity { get => _statusSeverity; private set => Set(ref _statusSeverity, value); }
    public int ItemCount => Records.Count;
    public bool CanLoadMore => !IsBusy && _nextCursor is not null;

    public OperatorRecordView? SelectedRecord
    {
        get => _selectedRecord;
        set
        {
            if (Set(ref _selectedRecord, value))
            {
                SelectedAction = value?.Actions.FirstOrDefault();
            }
        }
    }

    public OperatorActionView? SelectedAction
    {
        get => _selectedAction;
        set => Set(ref _selectedAction, value);
    }

    public SavedFilterViewModel? SelectedSavedFilter
    {
        get => _selectedSavedFilter;
        set => Set(ref _selectedSavedFilter, value);
    }

    public async Task RefreshAsync() => await LoadPageAsync(append: false);
    public async Task ExpandGraphNodeAsync(string nodeRef)
    {
        _graphSelectedRef = nodeRef;
        await LoadPageAsync(append: false);
    }
    public async Task LoadMoreAsync()
    {
        if (_nextCursor is not null) await LoadPageAsync(append: true);
    }

    public void CancelActiveRequest() => _requestCancellation?.Cancel();

    public async Task SelectSectionAsync(string section)
    {
        CurrentPage = OperatorPageCatalog.All.FirstOrDefault(page => page.Tag == section)
            ?? OperatorPageCatalog.All[0];
        _nextCursor = null;
        _graphSelectedRef = null;
        await RefreshAsync();
    }

    public void SaveCurrentFilter(string? name = null)
    {
        var saved = new SavedFilterViewModel(
            string.IsNullOrWhiteSpace(name) ? $"{SectionTitle} filter {SavedFilters.Count + 1}" : name.Trim(),
            CurrentPage.Tag,
            FilterText.Trim(),
            NullIfBlank(KindFilter),
            NullIfBlank(StatusFilter),
            NullIfBlank(AuthorityFilter));
        SavedFilters.Add(saved);
        SelectedSavedFilter = saved;
        SetBanner("Filter saved", $"Saved local inspection filter '{saved.Name}'.", OperatorBannerSeverity.Success);
    }

    public async Task ApplySavedFilterAsync()
    {
        if (SelectedSavedFilter is not { } saved) return;
        FilterText = saved.Search;
        KindFilter = saved.Kind ?? string.Empty;
        StatusFilter = saved.Status ?? string.Empty;
        AuthorityFilter = saved.Authority ?? string.Empty;
        await SelectSectionAsync(saved.PageTag);
    }

    public async Task ClearFiltersAsync()
    {
        FilterText = string.Empty;
        KindFilter = string.Empty;
        StatusFilter = string.Empty;
        AuthorityFilter = string.Empty;
        await RefreshAsync();
    }

    public async Task ExecutePaletteAsync(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return;
        if (command.StartsWith("Go: ", StringComparison.OrdinalIgnoreCase))
        {
            var title = command[4..].Trim();
            var page = OperatorPageCatalog.All.FirstOrDefault(
                item => item.Title.Equals(title, StringComparison.OrdinalIgnoreCase));
            if (page is not null) await SelectSectionAsync(page.Tag);
            return;
        }
        if (command.Equals("Cancel active request", StringComparison.OrdinalIgnoreCase))
        {
            CancelActiveRequest();
        }
        else if (command.Equals("Load next page", StringComparison.OrdinalIgnoreCase))
        {
            await LoadMoreAsync();
        }
        else
        {
            await RefreshAsync();
        }
    }

    public async Task ExecuteSelectedActionAsync()
    {
        if (SelectedAction is null || SelectedRecord is null)
        {
            SetBanner("No action selected", "Select a record and one typed action.", OperatorBannerSeverity.Warning);
            return;
        }
        if (_taskContext is not { } task)
        {
            SetBanner("Task scope required", "Load a canonical project/task before issuing commands.", OperatorBannerSeverity.Warning);
            return;
        }
        if (SelectedAction.RequiresReason && string.IsNullOrWhiteSpace(ActionInput))
        {
            SetBanner("Reason required", "This governed action requires a reason or exact evidence reference.", OperatorBannerSeverity.Warning);
            return;
        }

        var command = BuildCommand(
            SelectedAction.Command,
            SelectedRecord,
            task,
            ActionInput.Trim(),
            CandidateDisposition);
        await ExecuteCommandAsync(command, task, SelectedAction.Command);
    }

    public async Task RunCommandAsync(string command)
    {
        var run = Records.FirstOrDefault(record => record.RecordKind == "autonomy_run");
        var runId = run?.Fields.FirstOrDefault(field => field.Label == "run_id")?.Value;
        if (_taskContext is not { } task || string.IsNullOrWhiteSpace(runId))
        {
            SetBanner("No active run", "Load a task-scoped projection with an autonomy run.", OperatorBannerSeverity.Warning);
            return;
        }
        object payload = command switch
        {
            "pause_run" => new { command, autonomy_run_id = runId, reason = "operator pause" },
            "cancel_run" => new { command, autonomy_run_id = runId, reason = "operator cancel" },
            "start_run" or "resume_run" => new { command, autonomy_run_id = runId },
            _ => throw new InvalidOperationException($"Unsupported operator run command: {command}")
        };
        await ExecuteCommandAsync(payload, task, command);
    }

    private async Task LoadPageAsync(bool append)
    {
        _requestCancellation?.Cancel();
        _requestCancellation?.Dispose();
        _requestCancellation = new CancellationTokenSource();
        var cancellationToken = _requestCancellation.Token;
        IsBusy = true;
        NotifyCounts();
        try
        {
            ValidateScope();
            var projectId = NullIfBlank(ProjectId);
            var taskId = NullIfBlank(TaskId);
            JsonElement? queryParameters = IsQueryPage
                ? ParseJsonObject(QueryParametersText)
                : null;
            var page = await _client.QueryAsync(new OperatorQueryRequest(
                CurrentPage.Tag,
                projectId,
                taskId,
                new OperatorProjectionFilter(
                    NullIfBlank(FilterText),
                    NullIfBlank(KindFilter),
                    NullIfBlank(StatusFilter),
                    Authority: NullIfBlank(AuthorityFilter)),
                append ? _nextCursor : null,
                50,
                IsQueryPage ? QueryOperation : null,
                queryParameters,
                IsQueryPage ? ResultMode : "human",
                IsGraphPage ? _graphSelectedRef : null,
                GraphDepth), cancellationToken);
            _taskContext = page.ProjectId is not null
                && page.TaskId is not null
                && page.TaskRevision is not null
                    ? new OperatorTaskContext(page.ProjectId, page.TaskId, page.TaskRevision.Value)
                    : null;
            if (!append)
            {
                Records.Clear();
                SelectedRecord = null;
            }
            foreach (var record in page.Records) Records.Add(record);
            _nextCursor = page.NextCursor;
            SelectedRecord ??= Records.FirstOrDefault();
            ResultPayloadText = page.ResultPayload?.GetRawText() ?? string.Empty;
            var totalQualifier = page.TotalIsExact ? string.Empty : "at least ";
            ResultSummary = $"Showing {Records.Count} of {totalQualifier}{page.TotalMatching}; page generated {page.GeneratedAt.LocalDateTime:g}.";
            SetBanner(
                "Connected",
                $"Runtime {page.RuntimeId}; auth generation {page.AuthGeneration}; typed {page.Projection} projection.",
                OperatorBannerSeverity.Success);
        }
        catch (OperationCanceledException)
        {
            SetBanner("Request cancelled", "The nonblocking Governor request was cancelled.", OperatorBannerSeverity.Informational);
        }
        catch (Exception error)
        {
            SetBanner("Degraded / reconnect required", error.Message, OperatorBannerSeverity.Error);
        }
        finally
        {
            IsBusy = false;
            NotifyCounts();
        }
    }

    private async Task ExecuteCommandAsync(object command, OperatorTaskContext task, string action)
    {
        IsBusy = true;
        NotifyCounts();
        try
        {
            var receipt = await _client.CommandAsync(new
            {
                project_id = task.ProjectId,
                task_id = task.TaskId,
                expected_revision = task.Revision,
                idempotency_key = Guid.NewGuid().ToString("N"),
                command
            }, _requestCancellation?.Token ?? CancellationToken.None);
            var accepted = receipt.GetProperty("accepted").GetBoolean();
            var executed = receipt.GetProperty("executed").GetBoolean();
            var outcome = receipt.GetProperty("outcome").GetString() ?? "unknown";
            var receiptId = receipt.TryGetProperty("canonical_receipt", out var canonicalReceipt)
                && canonicalReceipt.ValueKind == JsonValueKind.Object
                && canonicalReceipt.TryGetProperty("receipt_id", out var canonicalReceiptId)
                    ? canonicalReceiptId.GetString()
                    : null;
            if (accepted && executed && receiptId is null)
            {
                throw new InvalidOperationException("Governor accepted a durable mutation without a canonical receipt.");
            }
            if (executed) await RefreshAsync();
            SetBanner(
                accepted ? "Command accepted" : "Command rejected",
                receiptId is null
                    ? $"{action}: {outcome}; no durable mutation executed."
                    : $"{action}: {outcome}; canonical receipt {receiptId}.",
                accepted ? OperatorBannerSeverity.Success : OperatorBannerSeverity.Warning);
        }
        catch (Exception error)
        {
            SetBanner("Command failed", error.Message, OperatorBannerSeverity.Error);
        }
        finally
        {
            IsBusy = false;
            NotifyCounts();
        }
    }

    private static object BuildCommand(
        string command,
        OperatorRecordView record,
        OperatorTaskContext task,
        string input,
        string candidateDisposition)
    {
        var field = (string label) => record.Fields.FirstOrDefault(item => item.Label == label)?.Value;
        return command switch
        {
            "request_revalidation" => new { command, task_id = task.TaskId, memory_handle = record.RecordRef },
            "refresh_packet" => new { command, task_id = task.TaskId },
            "contest_memory" => new { command, task_id = task.TaskId, memory_handle = record.RecordRef, evidence_refs = new[] { input } },
            "suppress_memory" or "archive_memory" => new { command, task_id = task.TaskId, memory_handle = record.RecordRef, reason = input },
            "restore_memory" => new { command, task_id = task.TaskId, memory_handle = record.RecordRef, evidence_refs = new[] { input } },
            "review_candidate" => new { command, task_id = task.TaskId, candidate_ref = record.RecordRef, disposition = candidateDisposition, evidence_refs = new[] { input } },
            "disposition_agent_result" => new { command, result_id = record.RecordRef, disposition = input },
            "create_autonomy_run" => new { command, contract = ParseJsonObject(input) },
            "preview_autonomy_edit" => new { command, autonomy_run_id = field("run_id"), proposed_contract = ParseJsonObject(input) },
            "start_run" or "resume_run" => new { command, autonomy_run_id = field("run_id") ?? record.RecordRef.Replace("autonomy-run:", string.Empty, StringComparison.Ordinal) },
            "pause_run" or "cancel_run" => new { command, autonomy_run_id = field("run_id") ?? record.RecordRef.Replace("autonomy-run:", string.Empty, StringComparison.Ordinal), reason = input },
            "grant_approval" => new { command, approval_id = field("approval_id"), exact_action_hash = field("exact_action_hash") },
            "deny_approval" => new { command, approval_id = field("approval_id"), exact_action_hash = field("exact_action_hash"), reason = input },
            "finish_gap_preview" => new { command, task_id = task.TaskId },
            "trigger_backup_validation" => new { command, task_id = task.TaskId },
            "request_import_preview" => new { command, task_id = task.TaskId, source_ref = input },
            _ => throw new InvalidOperationException($"Unsupported typed operator action: {command}")
        };
    }

    private static JsonElement ParseJsonObject(string value)
    {
        using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(value) ? "{}" : value);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("Typed Operator parameters must be one JSON object.");
        }
        return document.RootElement.Clone();
    }

    private void ValidateScope()
    {
        var hasProject = !string.IsNullOrWhiteSpace(ProjectId);
        var hasTask = !string.IsNullOrWhiteSpace(TaskId);
        if (hasProject != hasTask)
        {
            throw new InvalidOperationException("Project ID and task ID must be provided together.");
        }
        if (CurrentPage.RequiresTask && !hasTask)
        {
            throw new InvalidOperationException($"{CurrentPage.Title} requires a canonical project/task scope.");
        }
    }

    private void SetBanner(string title, string message, OperatorBannerSeverity severity)
    {
        StatusTitle = title;
        StatusMessage = message;
        StatusSeverity = severity;
    }

    private void NotifyCounts()
    {
        OnPropertyChanged(nameof(ItemCount));
        OnPropertyChanged(nameof(CanLoadMore));
    }

    private static string? NullIfBlank(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    public event PropertyChangedEventHandler? PropertyChanged;

    private bool Set<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
