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
        new("user_automation", "User Automation", "Authenticated create, inspect and lifecycle operations over canonical UserAutomation revisions.", false),
        new("approvals", "Approvals", "Exact action hash, risk, write set, verifier, rollback and decision receipts.", true),
        new("timeline_operations", "Timeline, Incidents and Operations", "Transitions, receipts, incidents, recovery, backups and logs.", true),
    ];
}

public sealed class MainViewModel : INotifyPropertyChanged
{
    /// The owner's own reason code for a State Fence that no longer admits the
    /// submitted revision (I7.20 reason registry, state/conflict class). It is
    /// used verbatim, never invented, and it distinguishes a proven refusal
    /// from an unknown outcome.
    public const string StaleFenceReasonCode = "STALE_STATE_FENCE";

    private readonly IGovernorClient _client;
    private readonly OperatorPendingOperationJournal? _pendingJournal;
    private OperatorTaskContext? _taskContext;
    private CancellationTokenSource? _requestCancellation;
    private OperatorPageDefinition _currentPage = OperatorPageCatalog.All[0];
    private OperatorRecordView? _selectedRecord;
    private OperatorActionView? _selectedAction;
    private SavedFilterViewModel? _selectedSavedFilter;
    private readonly List<OperatorPendingOperation> _pendingOperations = [];
    private OperatorProjectionBinding? _projectionBinding;
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
    private string _userAutomationId = string.Empty;
    private string _userAutomationRevision = string.Empty;
    private string _userAutomationNonce = string.Empty;
    private string _userAutomationRevisionJson = "{}";
    private string _userAutomationPreviousRevisionJson = "{}";
    private string _userAutomationOperation = "list";
    private bool _includeRetired;
    private string? _graphSelectedRef;
    private int _graphDepth = 1;
    private string _resultPayloadText = string.Empty;
    private string? _nextCursor;
    private string _resultSummary = "No projection loaded.";
    private string _statusTitle = "Disconnected";
    private string _statusMessage = "Waiting for the active ELIOT runtime.";
    private OperatorBannerSeverity _statusSeverity = OperatorBannerSeverity.Informational;
    private bool _pendingJournalUnavailable;

    public MainViewModel(
        IGovernorClient client,
        OperatorPendingOperationJournal? pendingJournal = null)
    {
        _client = client;
        _pendingJournal = pendingJournal;
        if (_pendingJournal is not null)
        {
            try
            {
                _pendingOperations.AddRange(_pendingJournal.LoadForRecovery());
                if (_pendingOperations.Count > 0)
                {
                    _statusTitle = "Reconciliation required";
                    _statusMessage = $"{_pendingOperations.Count} operator operation(s) survived a restart and require same-operation reconciliation.";
                    _statusSeverity = OperatorBannerSeverity.Warning;
                }
            }
            catch (OperatorPendingOperationJournalException error)
            {
                // Do not overwrite or discard an unreadable journal. The UI
                // remains available for reads, but no new mutation can be
                // sent until the owner-local recovery artifact is readable.
                _pendingJournalUnavailable = true;
                _statusTitle = "Recovery journal unavailable";
                _statusMessage = error.Message;
                _statusSeverity = OperatorBannerSeverity.Error;
            }
        }
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
    /// Retained operations awaiting a terminal receipt. Unknown-outcome
    /// entries reconcile under the same identity; they are never resubmitted
    /// as new mutations.
    public IReadOnlyList<OperatorPendingOperation> PendingOperations => _pendingOperations.AsReadOnly();
    public bool HasUnknownOperations =>
        _pendingOperations.Any(operation => operation.Phase is
            OperatorOperationPhase.UnknownReconciling
            or OperatorOperationPhase.PossiblyExecuted);
    public IReadOnlyList<string> QueryOperations { get; } =
        ["current_state", "recall_preview", "exact_evidence", "relationship_slice", "trace_replay", "health_report"];
    public IReadOnlyList<string> ResultModes { get; } = ["human", "json", "graph"];
    public IReadOnlyList<string> CandidateDispositions { get; } = ["promote", "reject", "demote", "archive"];
    public IReadOnlyList<string> UserAutomationOperations => UserAutomationContract.OperationKinds;

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
                OnPropertyChanged(nameof(IsUserAutomationPage));
            }
        }
    }

    public string SectionTitle => CurrentPage.Title;
    public string SectionDescription => CurrentPage.Description;
    public bool IsQueryPage => CurrentPage.Tag == "query_lab";
    public bool IsGraphPage => CurrentPage.Tag == "causal_provenance" || (IsQueryPage && ResultMode == "graph");
    public bool IsUserAutomationPage => CurrentPage.Tag == "user_automation";
    public bool IsBusy { get => _isBusy; private set => Set(ref _isBusy, value); }
    public string ProjectId { get => _projectId; set => Set(ref _projectId, BoundInput(value)); }
    public string TaskId { get => _taskId; set => Set(ref _taskId, BoundInput(value)); }
    public string FilterText { get => _filterText; set => Set(ref _filterText, BoundInput(value)); }
    public string KindFilter { get => _kindFilter; set => Set(ref _kindFilter, BoundInput(value)); }
    public string StatusFilter { get => _statusFilter; set => Set(ref _statusFilter, BoundInput(value)); }
    public string AuthorityFilter { get => _authorityFilter; set => Set(ref _authorityFilter, BoundInput(value)); }
    public string ActionInput { get => _actionInput; set => Set(ref _actionInput, BoundInput(value)); }
    public string QueryOperation { get => _queryOperation; set => Set(ref _queryOperation, BoundInput(value)); }
    // Retained operator input is bounded before it is stored, so no typed
    // parameter or filter buffer can grow without limit.
    public string QueryParametersText { get => _queryParametersText; set => Set(ref _queryParametersText, BoundInput(value)); }
    public string ResultMode
    {
        get => _resultMode;
        set
        {
            if (Set(ref _resultMode, value)) OnPropertyChanged(nameof(IsGraphPage));
        }
    }
    public string CandidateDisposition { get => _candidateDisposition; set => Set(ref _candidateDisposition, value); }
    public string UserAutomationId { get => _userAutomationId; set => Set(ref _userAutomationId, BoundInput(value).Trim()); }
    public string UserAutomationRevision { get => _userAutomationRevision; set => Set(ref _userAutomationRevision, BoundInput(value).Trim()); }
    public string UserAutomationNonce { get => _userAutomationNonce; set => Set(ref _userAutomationNonce, BoundInput(value)); }
    public string UserAutomationRevisionJson { get => _userAutomationRevisionJson; set => Set(ref _userAutomationRevisionJson, BoundInput(value)); }
    public string UserAutomationPreviousRevisionJson { get => _userAutomationPreviousRevisionJson; set => Set(ref _userAutomationPreviousRevisionJson, BoundInput(value)); }
    public string UserAutomationOperation { get => _userAutomationOperation; set => Set(ref _userAutomationOperation, BoundInput(value)); }
    public bool IncludeRetired { get => _includeRetired; set => Set(ref _includeRetired, value); }
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
        // One identity per user action: the typed envelope mints the
        // operation id once and the exact bytes are retained until a terminal
        // receipt. A retry of this action reconciles the same identity.
        var envelope = OperatorIntentEnvelope.Create(
            task.ProjectId,
            task.TaskId,
            task.Revision,
            JsonSerializer.SerializeToElement(command));
        await SubmitIntentAsync(envelope, SelectedAction.Command, isReconcile: false);
    }

    /// Reconciles every pending unknown-outcome operation under its retained
    /// identity and on its own owner route. No second logical mutation is ever
    /// minted here.
    public async Task ReconcilePendingAsync()
    {
        var unknown = _pendingOperations
            .Where(operation => operation.Phase is
                OperatorOperationPhase.UnknownReconciling
                or OperatorOperationPhase.PossiblyExecuted)
            .ToList();
        if (unknown.Count == 0)
        {
            SetBanner("Nothing to reconcile", "No operation is waiting for unknown-outcome reconciliation.", OperatorBannerSeverity.Informational);
            return;
        }
        foreach (var pending in unknown)
        {
            if (pending.Route == OperatorMutationRoute.OperatorCommand)
            {
                // Resend the retained operation: same identity, same expected
                // revision, same command bytes. No new identity is minted here.
                using var document = JsonDocument.Parse(pending.EnvelopeJson);
                var reconciling = new OperatorIntentEnvelope(
                    document.RootElement.GetProperty("project_id").GetString()!,
                    document.RootElement.GetProperty("task_id").GetString()!,
                    document.RootElement.GetProperty("expected_revision").GetUInt64(),
                    pending.OperationId,
                    document.RootElement.GetProperty("command").Clone());
                reconciling.Validate();
                await SubmitIntentAsync(reconciling, pending.CommandName, isReconcile: true);
                continue;
            }
            await ReconcileUserAutomationAsync(pending);
        }
    }

    /// Reconciles a retained typed UserAutomation effect under its ORIGINAL
    /// identity.
    ///
    /// The retained bytes are authoritative and are never rewritten. The
    /// recorded identity is the one the bytes already carry and is never
    /// re-derived: today's serializer no longer produces the bytes that were
    /// hashed when the key was minted, so re-deriving would rename a pending
    /// request instead of retrying it. A mismatch between the retained
    /// metadata and the retained request is refused, not repaired.
    ///
    /// A retained envelope written by the superseded generation also encodes
    /// the local read/effect classifier, which the closed owner contract
    /// refuses. Resending those bytes would be refused; re-encoding them
    /// without the classifier under the retained key would be a DIFFERENT
    /// request commitment. Neither is allowed, so the record is preserved
    /// visibly and execution is withheld for its actual owner to resolve.
    private async Task ReconcileUserAutomationAsync(OperatorPendingOperation pending)
    {
        UserAutomationRetainedRequest retained;
        try
        {
            retained = UserAutomationRetainedRequest.Read(pending.EnvelopeJson);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException)
        {
            WithholdUserAutomation(pending, $"the retained typed request is not a closed UserAutomation envelope ({error.Message});");
            return;
        }

        if (!string.Equals(retained.Request.IdempotencyKey, pending.OperationId, StringComparison.Ordinal)
            || pending.ExpectedRevision is not null)
        {
            WithholdUserAutomation(pending, "the retained typed request does not bind to its own recorded operation identity;");
            return;
        }

        if (retained.CarriesSupersededLocalClassifier)
        {
            WithholdUserAutomation(pending, "the retained request was encoded by the superseded local serializer and carries the local effect classifier, which the closed UserAutomation owner contract does not accept; it is neither resent nor re-encoded under its own identity;");
            return;
        }

        try
        {
            retained.Request.Validate();
        }
        catch (InvalidOperationException error)
        {
            WithholdUserAutomation(pending, $"the retained typed request is no longer valid ({error.Message});");
            return;
        }

        await TransmitUserAutomationAsync(retained.Request, pending, pending.CommandName);
    }

    /// Keeps an incompatible retained record visible and reconciling. The
    /// journal is never emptied and no unrelated pending item is removed to
    /// unblock a button: a fresh strict-decoder refusal, a missing local field
    /// or a failed reconnection does not establish the outcome of the earlier
    /// attempt, so only the actual owner of that attempt may resolve this
    /// record. A genuinely new corrected operation needs the existing explicit
    /// new-operation decision once that uncertainty is resolved; nothing here
    /// makes that decision automatically.
    private void WithholdUserAutomation(OperatorPendingOperation pending, string reason)
    {
        ReplacePending(pending.OperationId, OperatorOperationPhase.UnknownReconciling);
        RefreshPendingState();
        SetBanner(
            "Withheld — retained request is not recoverable from this build",
            $"{pending.CommandName}: {reason} The record stays reconciling under {pending.OperationId}; "
            + "nothing was sent and no pending item was removed. Issue a new operation explicitly once this record is resolved.",
            OperatorBannerSeverity.Warning);
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
        // One identity per user action, retained for reconciliation.
        var envelope = OperatorIntentEnvelope.Create(
            task.ProjectId,
            task.TaskId,
            task.Revision,
            JsonSerializer.SerializeToElement(payload));
        await SubmitIntentAsync(envelope, command, isReconcile: false);
    }

    /// Sends one closed UserAutomation operator operation through the existing
    /// authenticated Governor client. The UI never supplies identity, fence,
    /// schedule authority, provider credentials, or Store receipt fields.
    public async Task RunUserAutomationAsync()
    {
        UserAutomationOperation operation;
        try
        {
            operation = BuildUserAutomationOperation();
        }
        catch (Exception error) when (error is InvalidOperationException or JsonException)
        {
            SetBanner("UserAutomation command not sent", error.Message, OperatorBannerSeverity.Warning);
            return;
        }
        await SubmitUserAutomationAsync(operation, UserAutomationOperation);
    }

    /// Sends one new closed UserAutomation operator operation.
    ///
    /// A read executes immediately inside existing authority and retains
    /// nothing. An effect mints ONE retry-stable identity from the exact
    /// canonical operation bytes, journals the very request that is then
    /// transmitted, and keeps it until a terminal owner receipt, so a lost
    /// response reconciles the same typed operation instead of creating a
    /// second logical mutation.
    private async Task SubmitUserAutomationAsync(UserAutomationOperation operation, string action)
    {
        IsBusy = true;
        NotifyCounts();
        operation.Validate();

        if (!operation.IsEffect())
        {
            try
            {
                var read = await _client.UserAutomationAsync(
                    UserAutomationOperatorRequest.Create(operation),
                    _requestCancellation?.Token ?? CancellationToken.None);
                ShowUserAutomationResult(action, read);
            }
            catch (Exception error)
            {
                SetBanner("UserAutomation read failed", error.Message, OperatorBannerSeverity.Error);
            }
            finally
            {
                IsBusy = false;
                NotifyCounts();
            }
            return;
        }

        if (_pendingJournalUnavailable)
        {
            SetBanner(
                "Command not sent",
                "The user-local pending-operation journal is unavailable; recover it before sending another mutation.",
                OperatorBannerSeverity.Error);
            IsBusy = false;
            NotifyCounts();
            return;
        }

        // One prepared request. The same object is journaled and transmitted,
        // so the retained identity and the wire identity cannot diverge and
        // the key is minted exactly once.
        var request = UserAutomationOperatorRequest.Create(operation);
        request.Validate();
        var pending = new OperatorPendingOperation(
            request.IdempotencyKey,
            OperatorMutationRoute.UserAutomation,
            JsonSerializer.Serialize(request, OperatorJson.Writer),
            ExpectedRevision: null,
            action,
            OperatorOperationPhase.Submitted,
            DateTimeOffset.UtcNow);
        _pendingOperations.Add(pending);
        if (!TryPersistPendingState())
        {
            _pendingOperations.RemoveAll(entry => entry.OperationId == pending.OperationId);
            RefreshPendingState();
            SetBanner(
                "Command not sent",
                "The pending typed operation could not be durably journaled; no owner request was sent.",
                OperatorBannerSeverity.Error);
            IsBusy = false;
            NotifyCounts();
            return;
        }
        RefreshPendingState();
        await TransmitUserAutomationAsync(request, pending, action);
    }

    /// Transmits one prepared typed UserAutomation request under the identity it
    /// already carries. A first send journals that same request; recovery
    /// resends the retained one unchanged. No identity is minted or renamed
    /// here, and no outcome short of an owner-bound terminal disposition may
    /// compact the record.
    private async Task TransmitUserAutomationAsync(
        UserAutomationOperatorRequest request,
        OperatorPendingOperation pending,
        string action)
    {
        try
        {
            var answer = await _client.UserAutomationAsync(
                request,
                _requestCancellation?.Token ?? CancellationToken.None);
            ShowUserAutomationResult(action, answer);
            // The owner answered. This route reports admission, not a canonical
            // write receipt, so the effect stays reconcilable under the same
            // identity until the owner proves its terminal disposition.
            ReplacePending(pending.OperationId, OperatorOperationPhase.UnknownReconciling);
            RefreshPendingState();
        }
        catch (OperatorUnknownOutcomeException unknown)
        {
            // Possibly executed: retain the same identity for reconciliation.
            ReplacePending(pending.OperationId, OperatorOperationPhase.PossiblyExecuted);
            RefreshPendingState();
            SetBanner(
                "Unknown outcome — reconcile, do not resubmit",
                $"{action}: {unknown.OperationId} may have executed at stage {unknown.Stage} ({unknown.Message}); use Reconcile before any retry.",
                OperatorBannerSeverity.Warning);
        }
        catch (OperatorCleanupIncompleteException cleanup)
        {
            // The owner side is settled: only the local teardown of the
            // transport that carried it was limited. That is NOT an unknown
            // owner result, so the record is never promoted to possibly
            // executed, and it is never compacted either.
            ReplacePending(pending.OperationId, OperatorOperationPhase.UnknownReconciling);
            RefreshPendingState();
            SetBanner(
                "Owner answered — transport cleanup incomplete",
                $"{action}: {cleanup.OperationId} was answered by the Governor, but the local transport cleanup was limited at stage {cleanup.Stage} ({cleanup.Message}). The record stays reconcilable under the same operation identity.",
                OperatorBannerSeverity.Warning);
        }
        catch (OperatorRestartRequiredException restart)
        {
            ReplacePending(pending.OperationId, OperatorOperationPhase.PossiblyExecuted);
            RefreshPendingState();
            SetBanner(
                "Restart required",
                $"{action}: {restart.Message} Obtain a fresh broker handoff; the pending operation is retained.",
                OperatorBannerSeverity.Warning);
        }
        catch (OperatorNotAttemptedException notSent)
        {
            // Proven never sent. A FIRST send records exactly that under the
            // identity it already minted. A recovery send of an older retained
            // operation is different: failing before the new send says nothing
            // about the previous execution, so that record keeps its unknown
            // phase. Neither case clears the journal or mints a new identity.
            var notSentPhase = NotSentPhase(pending);
            ReplacePending(pending.OperationId, notSentPhase);
            RefreshPendingState();
            SetBanner(
                notSentPhase == OperatorOperationPhase.NotAttempted
                    ? "Command not sent"
                    : "Reconciliation not sent — earlier execution still unknown",
                notSentPhase == OperatorOperationPhase.NotAttempted
                    ? $"{action}: {notSent.OperationId} was not attempted; it failed at stage {notSent.Stage} ({notSent.Message}). No owner effect is possible for this attempt and the retained record is kept under the same identity."
                    : $"{action}: {notSent.OperationId} was not re-sent; it failed at stage {notSent.Stage} ({notSent.Message}). That says nothing about the earlier attempt, which stays reconcilable under the same identity.",
                OperatorBannerSeverity.Warning);
        }
        catch (Exception error)
        {
            ReplacePending(pending.OperationId, OperatorOperationPhase.UnknownReconciling);
            RefreshPendingState();
            SetBanner(
                "Command outcome unproven — recovery retained",
                $"{action}: {error.Message}; use Reconcile before any retry.",
                OperatorBannerSeverity.Warning);
        }
        finally
        {
            IsBusy = false;
            NotifyCounts();
        }
    }

    private void ShowUserAutomationResult(string action, JsonElement answer)
    {
        ResultPayloadText = OperatorProjectionGuard.BoundRetainedResult(answer) ?? string.Empty;
        ResultSummary = $"UserAutomation {action} response received from the authenticated Governor route.";
        SetBanner(
            "UserAutomation response received",
            $"The typed {action} operation was sent under one retry-stable operation identity; the owner response is shown below.",
            OperatorBannerSeverity.Success);
    }

    private UserAutomationOperation BuildUserAutomationOperation() => UserAutomationOperation switch
    {
        "create" => new UserAutomationCreateOperation(ParseRevision(UserAutomationRevisionJson)),
        "list" => new UserAutomationListOperation(IncludeRetired),
        "status" => new UserAutomationStatusOperation(RequiredUserAutomationId()),
        "history" => new UserAutomationHistoryOperation(RequiredUserAutomationId()),
        "pause" => new UserAutomationPauseOperation(RequiredUserAutomationId(), RequiredUserAutomationRevision()),
        "resume" => new UserAutomationResumeOperation(RequiredUserAutomationId(), RequiredUserAutomationRevision()),
        "edit" => new UserAutomationEditOperation(
            ParseRevision(UserAutomationPreviousRevisionJson),
            ParseRevision(UserAutomationRevisionJson)),
        "run_now" => new UserAutomationRunNowOperation(
            RequiredUserAutomationId(),
            RequiredUserAutomationRevision(),
            UserAutomationNonce),
        "remove" => new UserAutomationRemoveOperation(RequiredUserAutomationId(), RequiredUserAutomationRevision()),
        "inspect_last_failure" => new UserAutomationInspectLastFailureOperation(RequiredUserAutomationId()),
        _ => throw new InvalidOperationException("UserAutomation operation is not in the closed operation catalogue.")
    };

    private string RequiredUserAutomationId()
    {
        UserAutomationContract.RequireText(UserAutomationId, "automation_id");
        return UserAutomationId;
    }

    private string RequiredUserAutomationRevision()
    {
        UserAutomationContract.RequireText(UserAutomationRevision, "automation_revision");
        return UserAutomationRevision;
    }

    private static UserAutomationRevision ParseRevision(string value)
    {
        var revision = JsonSerializer.Deserialize<UserAutomationRevision>(value)
            ?? throw new InvalidOperationException("owner-normalized UserAutomation revision JSON is required.");
        revision.Validate();
        return revision;
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
                ? ParseJsonObject(QueryParametersText, "query_parameters")
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
                PageRequestSize,
                IsQueryPage ? QueryOperation : null,
                queryParameters,
                IsQueryPage ? ResultMode : "human",
                IsGraphPage ? _graphSelectedRef : null,
                GraphDepth), cancellationToken);
            // Rows, selection, cursor, graph focus, result payload and the task
            // context are rebuildable views of one owner binding. Any change to
            // runtime, auth generation, owner task revision, projection or
            // scope clears every dependent piece of state BEFORE the new page
            // is used, so no view can outlive the owner state it came from.
            var binding = OperatorProjectionBinding.From(page, DateTimeOffset.UtcNow);
            var rotated = InvalidateOnRotation(binding);
            if (!append || rotated)
            {
                Records.Clear();
                SelectedRecord = null;
            }
            foreach (var record in page.Records) Records.Add(record);
            _nextCursor = page.NextCursor;
            SelectedRecord ??= Records.FirstOrDefault();
            _taskContext = page.ProjectId is not null
                && page.TaskId is not null
                && page.TaskRevision is not null
                    ? new OperatorTaskContext(page.ProjectId, page.TaskId, page.TaskRevision.Value)
                    : null;
            // The retained result payload is bounded as a whole. An oversized
            // payload is refused, never clipped into a valid-looking object.
            ResultPayloadText = OperatorProjectionGuard.BoundRetainedResult(page.ResultPayload) ?? string.Empty;
            var totalQualifier = page.TotalIsExact ? string.Empty : "at least ";
            ResultSummary = $"Showing {Records.Count} of {totalQualifier}{page.TotalMatching}; page generated {page.GeneratedAt.LocalDateTime:g}.";
            SetBanner(
                "Connected",
                rotated
                    ? $"Runtime {page.RuntimeId}; auth generation {page.AuthGeneration}; typed {page.Projection} projection. Runtime rotated: dependent state was invalidated before use."
                    : $"Runtime {page.RuntimeId}; auth generation {page.AuthGeneration}; typed {page.Projection} projection.",
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

    /// Sends one typed intent: first send mints nothing (the envelope already
    /// carries the per-action identity); reconciliation resends the retained
    /// identity. Unknown transport outcomes retain the pending operation for
    /// exact reconciliation instead of a second mutation.
    private async Task SubmitIntentAsync(OperatorIntentEnvelope envelope, string action, bool isReconcile)
    {
        IsBusy = true;
        NotifyCounts();
        if (!isReconcile && _pendingJournalUnavailable)
        {
            SetBanner(
                "Command not sent",
                "The user-local pending-operation journal is unavailable; recover it before sending another mutation.",
                OperatorBannerSeverity.Error);
            IsBusy = false;
            NotifyCounts();
            return;
        }

        var pending = new OperatorPendingOperation(
            envelope.OperationId,
            OperatorMutationRoute.OperatorCommand,
            JsonSerializer.Serialize(envelope, OperatorJson.Writer),
            envelope.ExpectedRevision,
            action,
            OperatorOperationPhase.Submitted,
            DateTimeOffset.UtcNow);
        if (!isReconcile)
        {
            _pendingOperations.Add(pending);
            if (!TryPersistPendingState())
            {
                _pendingOperations.RemoveAll(operation => operation.OperationId == pending.OperationId);
                RefreshPendingState();
                SetBanner(
                    "Command not sent",
                    "The pending operation could not be durably journaled; no owner request was sent.",
                    OperatorBannerSeverity.Error);
                IsBusy = false;
                NotifyCounts();
                return;
            }
            RefreshPendingState();
        }
        try
        {
            var requestEnvelope = isReconcile
                ? ParseRetainedEnvelope(pending.EnvelopeJson)
                : JsonSerializer.SerializeToElement(envelope);
            JsonElement receipt = isReconcile
                ? await _client.ReconcileAsync(
                    requestEnvelope,
                    _requestCancellation?.Token ?? CancellationToken.None)
                : await _client.CommandAsync(
                    requestEnvelope,
                    _requestCancellation?.Token ?? CancellationToken.None);
            bool accepted;
            bool executed;
            bool staleFence;
            string outcome;
            string? receiptId;
            try
            {
                var parsed = ReadCommandReceipt(receipt, pending);
                accepted = parsed.Accepted;
                executed = parsed.Executed;
                staleFence = parsed.StaleFence;
                outcome = parsed.Outcome;
                receiptId = parsed.ReceiptId;
            }
            catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException or JsonException)
            {
                // The owner answered but the receipt shape proves nothing:
                // retain the same identity for reconciliation.
                ReplacePending(pending.OperationId, OperatorOperationPhase.UnknownReconciling);
                RefreshPendingState();
                SetBanner(
                    "Unknown outcome — reconcile, do not resubmit",
                    $"{action}: {pending.OperationId} returned an unreadable receipt; use Reconcile before any retry.",
                    OperatorBannerSeverity.Warning);
                return;
            }
            if (accepted && executed && receiptId is null)
            {
                // The owner claims a durable mutation but proves nothing:
                // retain the same identity for reconciliation, never resubmit.
                ReplacePending(pending.OperationId, OperatorOperationPhase.UnknownReconciling);
                RefreshPendingState();
                SetBanner(
                    "Unknown outcome — reconcile, do not resubmit",
                    $"{action}: {pending.OperationId} was accepted without a canonical receipt; use Reconcile before any retry.",
                    OperatorBannerSeverity.Warning);
                return;
            }
            if (accepted && executed)
            {
                if (!RemovePending(pending.OperationId, OperatorOperationPhase.Receipted))
                {
                    RefreshPendingState();
                    SetBanner(
                        "Receipt received — recovery retained",
                        $"{action}: the owner returned a receipt, but the local journal could not be compacted; reconcile the retained operation after recovery.",
                        OperatorBannerSeverity.Warning);
                    return;
                }
            }
            else if (!accepted)
            {
                // An owner-bound refusal is terminal and distinct from a
                // stale-fence answer, which proves the mutation was not
                // admitted at the current State Fence.
                var terminal = staleFence ? OperatorOperationPhase.StaleFence : OperatorOperationPhase.Rejected;
                if (!RemovePending(pending.OperationId, terminal))
                {
                    RefreshPendingState();
                    SetBanner(
                        "Rejection received — recovery retained",
                        $"{action}: the owner rejected the command, but the local journal could not be compacted; retain the exact operation for reconciliation.",
                        OperatorBannerSeverity.Warning);
                    return;
                }
            }
            else
            {
                // An accepted-but-not-yet-executed response is still an
                // owner-pending effect. Keep it durable and make the UI
                // reconcile the same identity rather than treating the
                // provisional answer as a terminal success.
                ReplacePending(pending.OperationId, OperatorOperationPhase.UnknownReconciling);
            }
            RefreshPendingState();
            if (executed) await RefreshAsync();
            var bannerTitle = accepted && !executed
                ? "Command accepted — reconcile pending owner work"
                : staleFence
                    ? "Command refused — stale State Fence"
                    : accepted
                        ? "Command accepted"
                        : "Command rejected";
            var bannerSeverity = accepted && !executed
                ? OperatorBannerSeverity.Warning
                : accepted
                    ? OperatorBannerSeverity.Success
                    : OperatorBannerSeverity.Warning;
            SetBanner(
                bannerTitle,
                receiptId is null
                    ? $"{action}: {outcome}; no durable mutation executed."
                    : $"{action}: {outcome}; canonical receipt {receiptId}.",
                bannerSeverity);
        }
        catch (OperatorUnknownOutcomeException unknown)
        {
            // Possibly executed: a transport loss after the request was written.
            // The same identity is retained for reconciliation; it is never
            // resubmitted as a new mutation. First sends update the entry added
            // above in place; reconciliations leave the retained entry untouched.
            ReplacePending(pending.OperationId, OperatorOperationPhase.PossiblyExecuted);
            RefreshPendingState();
            SetBanner(
                "Unknown outcome — reconcile, do not resubmit",
                $"{action}: {unknown.OperationId} may have executed at stage {unknown.Stage} ({unknown.Message}); use Reconcile before any retry.",
                OperatorBannerSeverity.Warning);
        }
        catch (OperatorCleanupIncompleteException cleanup)
        {
            // The owner side is settled and only the local teardown of the
            // transport that carried it was limited. That is distinct from an
            // unknown owner result, so the record is never promoted to possibly
            // executed, and it is never compacted either.
            ReplacePending(pending.OperationId, OperatorOperationPhase.UnknownReconciling);
            RefreshPendingState();
            SetBanner(
                "Owner answered — transport cleanup incomplete",
                $"{action}: {cleanup.OperationId} was answered by the Governor, but the local transport cleanup was limited at stage {cleanup.Stage} ({cleanup.Message}); the retained operation stays reconcilable under the same identity.",
                OperatorBannerSeverity.Warning);
        }
        catch (OperatorRestartRequiredException restart)
        {
            ReplacePending(pending.OperationId, OperatorOperationPhase.PossiblyExecuted);
            RefreshPendingState();
            SetBanner(
                "Restart required",
                $"{action}: {restart.Message} Obtain a fresh broker handoff; the pending operation is retained.",
                OperatorBannerSeverity.Warning);
        }
        catch (OperatorNotAttemptedException notSent)
        {
            // Proven never sent. A FIRST send records exactly that, under the
            // identity it already minted. A RECONCILIATION of an older retained
            // operation is different: failing before the new send says nothing
            // about the previous execution, so that record keeps its unknown
            // phase and nothing is cleared.
            var notSentPhase = NotSentPhase(pending);
            ReplacePending(pending.OperationId, notSentPhase);
            RefreshPendingState();
            SetBanner(
                notSentPhase == OperatorOperationPhase.NotAttempted
                    ? "Command not sent"
                    : "Reconciliation not sent — earlier execution still unknown",
                notSentPhase == OperatorOperationPhase.NotAttempted
                    ? $"{action}: {notSent.OperationId} was not attempted; it failed at stage {notSent.Stage} ({notSent.Message}). No owner effect is possible for this attempt and the retained record is kept under the same identity."
                    : $"{action}: {notSent.OperationId} was not re-sent; it failed at stage {notSent.Stage} ({notSent.Message}). That says nothing about the earlier attempt, which stays reconcilable under the same identity.",
                OperatorBannerSeverity.Warning);
        }
        catch (OperationCanceledException)
        {
            // Transport cancelled: the effect may still have committed, so the
            // same identity stays reconciliable instead of a terminal cancel.
            ReplacePending(pending.OperationId, OperatorOperationPhase.UnknownReconciling);
            RefreshPendingState();
            SetBanner("Command cancelled", "The nonblocking Governor request was cancelled; a possibly committed effect stays reconciliable under the same operation identity.", OperatorBannerSeverity.Informational);
        }
        catch (Exception error)
        {
            // A local, reconnect, handshake, or decode failure does not prove
            // that the original owner request was never committed. This also
            // covers reconciliation attempts: a fresh handshake refusal cannot
            // compact the older operation. Only the exact owner-bound receipt
            // branches above may remove a retained operation.
            ReplacePending(pending.OperationId, OperatorOperationPhase.UnknownReconciling);
            RefreshPendingState();
            SetBanner(
                "Command outcome unproven — recovery retained",
                $"{action}: {error.Message}; use Reconcile before any retry.",
                OperatorBannerSeverity.Warning);
        }
        finally
        {
            IsBusy = false;
            NotifyCounts();
        }
    }

    /// Reads one owner-bound command receipt. The receipt is accepted only when
    /// it is bound to this exact operation identity, this exact expected
    /// revision, carries a typed terminal disposition, and — when it claims a
    /// durable mutation — carries a canonical receipt. A refusal whose outcome
    /// is the owner's `STALE_STATE_FENCE` reason code is terminal and distinct
    /// from a plain rejection and from an unknown outcome.
    private static (bool Accepted, bool Executed, bool StaleFence, string Outcome, string? ReceiptId) ReadCommandReceipt(
        JsonElement receipt,
        OperatorPendingOperation pending)
    {
        if (receipt.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("operator command receipt must be one JSON object");
        }

        if (!receipt.TryGetProperty("operation_id", out var operationId)
            || operationId.ValueKind != JsonValueKind.String
            || !string.Equals(operationId.GetString(), pending.OperationId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("operator command receipt is bound to a different operation");
        }

        if (pending.ExpectedRevision is not { } expectedOperationRevision)
        {
            throw new InvalidOperationException("operator command receipt has no expected owner revision to bind to");
        }

        if (!receipt.TryGetProperty("expected_revision", out var expectedRevision)
            || expectedRevision.ValueKind != JsonValueKind.Number
            || !expectedRevision.TryGetUInt64(out var receiptExpectedRevision)
            || receiptExpectedRevision != expectedOperationRevision)
        {
            throw new InvalidOperationException("operator command receipt is bound to a different expected revision");
        }

        if (!receipt.TryGetProperty("accepted", out var acceptedValue)
            || (acceptedValue.ValueKind != JsonValueKind.True && acceptedValue.ValueKind != JsonValueKind.False)
            || !receipt.TryGetProperty("executed", out var executedValue)
            || (executedValue.ValueKind != JsonValueKind.True && executedValue.ValueKind != JsonValueKind.False))
        {
            throw new InvalidOperationException("operator command receipt has no typed terminal disposition");
        }

        if (!receipt.TryGetProperty("outcome", out var outcomeValue)
            || outcomeValue.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(outcomeValue.GetString())
            || string.Equals(outcomeValue.GetString(), "unknown", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("operator command receipt has no proven outcome");
        }

        var accepted = acceptedValue.GetBoolean();
        var executed = executedValue.GetBoolean();
        var outcome = outcomeValue.GetString()!;
        // A stale State Fence is an owner-bound refusal proving the mutation was
        // not admitted at the submitted revision. It never carries a produced
        // revision, so the produced-revision binding below applies only to an
        // accepted operation.
        var staleFence = !accepted
            && (string.Equals(outcome, StaleFenceReasonCode, StringComparison.Ordinal)
                || string.Equals(outcome, StaleFenceReasonCode.ToLowerInvariant(), StringComparison.Ordinal));

        if (!staleFence
            && (!receipt.TryGetProperty("revision", out var revision)
                || revision.ValueKind != JsonValueKind.Number
                || !revision.TryGetUInt64(out var receiptRevision)
                || receiptRevision != expectedOperationRevision))
        {
            throw new InvalidOperationException("operator command receipt has an unbound task revision");
        }

        string? receiptId = null;
        if (receipt.TryGetProperty("canonical_receipt", out var canonicalReceipt)
            && canonicalReceipt.ValueKind == JsonValueKind.Object
            && canonicalReceipt.TryGetProperty("receipt_id", out var canonicalReceiptId)
            && canonicalReceiptId.ValueKind == JsonValueKind.String)
        {
            receiptId = canonicalReceiptId.GetString();
            if (string.IsNullOrWhiteSpace(receiptId)) receiptId = null;
        }

        if (executed != (receiptId is not null) || (executed && !accepted))
        {
            throw new InvalidOperationException("operator command receipt has an inconsistent canonical disposition");
        }

        return (accepted, executed, staleFence, outcome, receiptId);
    }

    /// The phase a proven-never-sent attempt may record.
    ///
    /// `NotAttempted` is truthful only for a record that has never claimed to
    /// have reached the owner. A record carried over a process boundary, and a
    /// recovery send of it, already claim that uncertainty: a failure before
    /// the new send says nothing about the previous execution, so those stay
    /// `UnknownReconciling` and are never compacted.
    private static OperatorOperationPhase NotSentPhase(OperatorPendingOperation pending) =>
        pending.Phase is OperatorOperationPhase.Created or OperatorOperationPhase.Submitted
            ? OperatorOperationPhase.NotAttempted
            : OperatorOperationPhase.UnknownReconciling;

    private bool ReplacePending(string operationId, OperatorOperationPhase phase)
    {
        var index = _pendingOperations.FindIndex(operation => operation.OperationId == operationId);
        if (index < 0) return true;
        var original = _pendingOperations[index];
        _pendingOperations[index] = original.WithPhase(phase);
        if (TryPersistPendingState()) return true;
        _pendingOperations[index] = original;
        return false;
    }

    /// Compacts a retained operation only after its terminal owner-bound phase
    /// has been observed. The terminal phase is journalled first, so a crash or
    /// a failed second write leaves a durably terminal record rather than
    /// silently dropping an unproven operation.
    private bool RemovePending(string operationId, OperatorOperationPhase terminalPhase)
    {
        var index = _pendingOperations.FindIndex(operation => operation.OperationId == operationId);
        if (index < 0) return true;
        var original = _pendingOperations[index];
        _pendingOperations[index] = original.WithPhase(terminalPhase);
        if (TryPersistPendingState())
        {
            _pendingOperations.RemoveAll(operation => operation.OperationId == operationId);
            if (TryPersistPendingState()) return true;
        }
        _pendingOperations[index] = original;
        return false;
    }

    private bool TryPersistPendingState()
    {
        if (_pendingJournal is null) return true;
        try
        {
            _pendingJournal.Save(_pendingOperations);
            return true;
        }
        catch (OperatorPendingOperationJournalException)
        {
            _pendingJournalUnavailable = true;
            return false;
        }
    }

    private static JsonElement ParseRetainedEnvelope(string envelopeJson)
    {
        using var document = JsonDocument.Parse(envelopeJson);
        return document.RootElement.Clone();
    }

    private void RefreshPendingState()
    {
        OnPropertyChanged(nameof(PendingOperations));
        OnPropertyChanged(nameof(HasUnknownOperations));
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
            "create_autonomy_run" => new { command, contract = ParseJsonObject(input, "create_autonomy_run.contract") },
            "preview_autonomy_edit" => new { command, autonomy_run_id = field("run_id"), proposed_contract = ParseJsonObject(input, "preview_autonomy_edit.proposed_contract") },
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

    /// Parses one operator-typed JSON parameter object. It carries its own
    /// independent caps: total characters, member count, nesting depth, token
    /// count, string length and array item count. Over-limit input is refused
    /// whole; it is never truncated into an object that still parses.
    private static JsonElement ParseJsonObject(string value, string field)
    {
        var raw = string.IsNullOrWhiteSpace(value) ? "{}" : value;
        if (raw.Length > OperatorProtocol.MaxLocalParameterChars)
        {
            throw new OperatorProtocolException(field, "parameter_chars_cap");
        }
        OperatorResponseGuard.ValidateLocalParameter(raw, field);
        using var document = JsonDocument.Parse(raw);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("Typed Operator parameters must be one JSON object.");
        }
        return document.RootElement.Clone();
    }

    /// Tracks the exact owner binding of the last applied page. Returns true
    /// when the binding rotated: the caller must discard cached rows, cursor,
    /// selection, graph focus, result payload and task context before use.
    /// Pending unknown-outcome operations are retained under their own
    /// identities for reconciliation; they are not dependent UI state.
    private bool InvalidateOnRotation(OperatorProjectionBinding binding)
    {
        var previous = _projectionBinding;
        var rotated = binding.DiffersFrom(previous);
        _projectionBinding = binding;
        if (rotated)
        {
            // Every rebuildable view of the previous owner state is cleared
            // before the new page is applied. The task context in particular
            // carries the owner task revision used as `expected_revision`, so
            // keeping it would send a mutation against a rotated revision.
            _nextCursor = null;
            _graphSelectedRef = null;
            _taskContext = null;
            ResultPayloadText = string.Empty;
            ResultSummary = "No projection loaded.";
        }
        return rotated;
    }

    /// One bounded page request size, pinned to the owner's declared page
    /// ceiling so the client can never ask for an unbounded page.
    private static int PageRequestSize => OperatorProtocol.MaxPageSize / 2;

    /// Retained operator input is bounded before it is stored on the view
    /// model. An over-limit value is refused outright, never clipped into a
    /// valid-looking parameter.
    private static string BoundInput(string value)
    {
        if (value is null) return string.Empty;
        if (value.Length > OperatorProtocol.MaxRetainedInputChars)
        {
            throw new OperatorProtocolException("operator_input", "retained_buffer_cap");
        }
        return value;
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
