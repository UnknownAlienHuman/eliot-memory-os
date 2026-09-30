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
    /// The owner-issued session binding the currently displayed projection was
    /// built under, read off the live transport at the moment the page was
    /// applied. Rows, selection, cursor, graph focus, task context and the
    /// retained result payload are views of ONE grant; a grant that rotates or
    /// goes away is a runtime-identity change that invalidates all of them
    /// before any of them is read again. A null value is a real observation
    /// (no established binding), never a "matches anything" wildcard.
    private OperatorRoleBinding? _projectionGrant;
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
    private OperatorRoleBinding? _roleBinding;
    private string _bindingSummary = "Session binding not yet established.";

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
                OnPropertyChanged(nameof(IsUserAutomationOperable));
            }
        }
    }

    public string SectionTitle => CurrentPage.Title;
    public string SectionDescription => CurrentPage.Description;
    public bool IsQueryPage => CurrentPage.Tag == "query_lab";
    public bool IsGraphPage => CurrentPage.Tag == "causal_provenance" || (IsQueryPage && ResultMode == "graph");
    public bool IsUserAutomationPage => CurrentPage.Tag == "user_automation";
    /// Role-filtered rendering of the command-only UserAutomation view: the
    /// typed command panel is shown only on its page AND under a grant that
    /// carries the command capability. A known binding that withholds commands
    /// gets the withheld explanation instead of an operable-looking panel.
    public bool IsUserAutomationOperable => IsUserAutomationPage && CanIssueCommands;
    public bool IsBusy { get => _isBusy; private set => Set(ref _isBusy, value); }
    public string ProjectId
    {
        get => _projectId;
        set
        {
            if (Set(ref _projectId, BoundInput(value))) InvalidateForScopeChange();
        }
    }
    public string TaskId
    {
        get => _taskId;
        set
        {
            if (Set(ref _taskId, BoundInput(value))) InvalidateForScopeChange();
        }
    }
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
    /// The broker-granted role of the live binding, or null before the first
    /// established binding. Views render under this grant (I11.3 role
    /// authority, I11.8 session binding); it names the grant, never a secret.
    public string? GrantedRole => _roleBinding?.Role;
    /// Human-readable grant description: role, capability set, and — after a
    /// page loads — the runtime and auth generation it was redeemed against.
    /// A withheld command capability is stated here, so a disabled action is
    /// never unexplained.
    public string BindingSummary { get => _bindingSummary; private set => Set(ref _bindingSummary, value); }
    /// A null (never-established) binding is unknown, not denied: the
    /// transport authenticates every request, so reads proceed until the
    /// broker proves otherwise. A KNOWN binding that withholds the read
    /// capability withholds its views.
    public bool CanReadProjection => _roleBinding is null || _roleBinding.GrantsReads;
    /// Same rule for effects: unknown proceeds to owner authentication, a
    /// known grant without `operator.command` refuses before anything is
    /// journaled or sent.
    public bool CanIssueCommands => _roleBinding is null || _roleBinding.GrantsCommands;
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
        InvalidateForScopeChange();
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
        if (IsBusy)
        {
            SetBanner("Projection is changing", "Wait for the current request to finish before using a selected action.", OperatorBannerSeverity.Informational);
            return;
        }
        // The selected action, the selected record and the task context are
        // rebuildable views of ONE owner-issued session binding, and the task
        // context carries the owner task revision that becomes
        // `expected_revision`. If that binding rotated, none of them may be
        // read to build a mutation: the revision would be sent against a
        // binding this process no longer holds. Invalidate first, then refuse.
        var selectedGrant = _projectionGrant;
        if (!RequireLiveBindingForRetainedState())
        {
            SetBanner(
                "Command not sent — session binding changed",
                $"The operator session binding this selection was built under ({DescribeGrant(selectedGrant)}) is no longer the live one ({DescribeGrant(_roleBinding)}), "
                + "so the selected record, action and owner task revision were invalidated before use. Nothing was journaled and nothing was sent.",
                OperatorBannerSeverity.Warning);
            return;
        }
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

        OperatorIntentEnvelope envelope;
        try
        {
            envelope = BuildCommandRegion(SelectedAction.Command, SelectedRecord, task);
        }
        catch (Exception error) when (error is InvalidOperationException or JsonException)
        {
            // A typed parameter the operator entered is still a locally
            // refusable request, not a fault. `ParseJsonObject` caps length and
            // depth and refuses a non-object root, but well-bounded malformed
            // JSON only fails here, at the parse -- so without this the
            // `JsonException` left through the `async void` click handler and
            // killed the process with no banner shown at all.
            //
            // The refusal is displayed under the same closed code the
            // transport paths use, and the framework message is never shown: a
            // serializer message can carry a JSON path, an offset and a
            // character lifted from the bytes the operator typed.
            //
            // The containment point is BEFORE `SubmitIntentAsync`, which is
            // where the first send and the first journal write happen. So this
            // refusal sends nothing, journals nothing and leaves no pending
            // operation to reconcile -- the same terminal disposition as the
            // refusals above, and no partially sent write to recover from.
            SetBanner(
                "Command not sent",
                $"{SelectedAction.Command}: the typed command was refused before submission "
                    + $"({BoundedRefusalReason(error)}); nothing was journaled and nothing was sent.",
                OperatorBannerSeverity.Warning);
            return;
        }
        await SubmitIntentAsync(envelope, SelectedAction.Command, isReconcile: false);
    }

    /// Mints the exact typed envelope one user action sends. Split out of the
    /// caller so the whole build-and-mint region sits inside a single guard:
    /// the operator's typed buffer reaches JSON parsing here, and this is the
    /// only place it does before a send.
    private OperatorIntentEnvelope BuildCommandRegion(
        string commandName,
        OperatorRecordView record,
        OperatorTaskContext task)
    {
        var command = BuildCommand(
            commandName,
            record,
            task,
            ActionInput.Trim(),
            CandidateDisposition);
        // One identity per user action: the typed envelope mints the
        // operation id once and the exact bytes are retained until a terminal
        // receipt. A retry of this action reconciles the same identity.
        return OperatorIntentEnvelope.Create(
            task.ProjectId,
            task.TaskId,
            task.Revision,
            JsonSerializer.SerializeToElement(command));
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
            WithholdUserAutomation(pending, $"the retained typed request is not a closed UserAutomation envelope ({BoundedRefusalReason(error)});");
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
        // Same runtime identity axis as every other use of the retained
        // projection: the autonomy run row and the owner task revision that
        // becomes `expected_revision` are views of the session binding the
        // projection was built under. A rotated or gone binding drops both
        // before they are read, so no mutation is built from a stale revision.
        var runGrant = _projectionGrant;
        if (!RequireLiveBindingForRetainedState())
        {
            SetBanner(
                "Command not sent — session binding changed",
                $"The operator session binding this projection was built under ({DescribeGrant(runGrant)}) is no longer the live one ({DescribeGrant(_roleBinding)}), "
                + $"so the retained run row and owner task revision were invalidated before use. {command} was not journaled and not sent.",
                OperatorBannerSeverity.Warning);
            return;
        }
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
    ///
    /// Create/edit revisions are parsed and validated for local inspection, then
    /// refused at the fresh submission boundary because the owner contract exposes
    /// no normalization result or migration action bound to the immutable
    /// revision. The local projection is shown with the refusal and is never
    /// treated as owner evidence. Read/inspect operations remain usable.
    public async Task RunUserAutomationAsync()
    {
        // A create or edit needs a caller-supplied schedule revision. The
        // Operator checks its closed shape but cannot prove its normalization
        // provenance; with no revision, it has no schedule data to submit. It
        // never derives or rewrites an immutable revision in place.
        if (UserAutomationOperation is "create" or "edit"
            && string.IsNullOrWhiteSpace(UserAutomationRevisionJson))
        {
            var absent = UserAutomationOutcomeClassifier.OwnerAbsent(
                UserAutomationOperation,
                "no schedule revision payload was supplied.");
            SetBanner(absent.Title, absent.Detail, OperatorBannerSeverity.Warning);
            return;
        }

        UserAutomationOperation operation;
        UserAutomationScheduleProjection? scheduleProjection = null;
        try
        {
            operation = BuildUserAutomationOperation();
            scheduleProjection = operation switch
            {
                UserAutomationCreateOperation create => create.Revision.Schedule.ReadLocalProjection(),
                UserAutomationEditOperation edit => edit.Revision.Schedule.ReadLocalProjection(),
                _ => null
            };
            operation.Validate();
            if (operation is UserAutomationCreateOperation)
            {
                UserAutomationScheduleMirror.RequireOwnerIssuedNormalizationForFreshSubmission("create");
            }
            else if (operation is UserAutomationEditOperation)
            {
                UserAutomationScheduleMirror.RequireOwnerIssuedNormalizationForFreshSubmission("edit");
            }
        }
        catch (UserAutomationScheduleContractException refusal)
        {
            var refused = UserAutomationOutcomeClassifier.RefusedBeforeSubmission(refusal);
            SetBanner(
                refused.Title,
                AppendLocalProjectionInspection(refused.Detail, scheduleProjection),
                OperatorBannerSeverity.Warning);
            return;
        }
        catch (Exception error) when (error is InvalidOperationException or JsonException)
        {
            SetBanner(
                "UserAutomation command not sent",
                AppendLocalProjectionInspection(BoundedRefusalReason(error), scheduleProjection),
                OperatorBannerSeverity.Warning);
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
                var readRequest = UserAutomationOperatorRequest.Create(operation);
                var read = await _client.UserAutomationAsync(
                    readRequest,
                    _requestCancellation?.Token ?? CancellationToken.None);
                ShowUserAutomationResult(action, read, readRequest);
            }
            catch (Exception error)
            {
                SetBanner(
                    "UserAutomation read failed",
                    $"The UserAutomation read did not complete ({OperatorFaultReason.ForException(error)}); "
                    + "a read has no owner effect, so it can be retried once the session is restored.",
                    OperatorBannerSeverity.Error);
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
        // Effects need the command grant; reads already returned above and
        // execute inside existing authority (I11.4). The refusal lands before
        // the retry-stable identity is minted or journaled.
        if (!RequireCommandCapability($"user_automation:{action}"))
        {
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
            ShowUserAutomationResult(action, answer, request);
            // A typed attempt refusal can prove that this attempt stopped before
            // Store, but it does not settle an earlier attempt of the same
            // retained identity. Preserve an already-unknown phase; a first
            // structured answer becomes reconcilable under this exact identity.
            var unresolvedPhase = pending.Phase is
                OperatorOperationPhase.UnknownReconciling
                or OperatorOperationPhase.PossiblyExecuted
                    ? pending.Phase
                    : OperatorOperationPhase.UnknownReconciling;
            ReplacePending(pending.OperationId, unresolvedPhase);
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
            // Same rule as the operator-command path: a proven session-binding
            // loss drops the rebuildable views at the moment it is observed, so
            // no retained result payload or task context outlives the binding it
            // was read under. The retained operation keeps its own identity.
            ClearRetainedProjectionState(
                "The operator session binding is gone; retained projection state was invalidated.");
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
                $"{action}: the transport did not prove an owner outcome ({OperatorFaultReason.ForException(error)}); use Reconcile before any retry.",
                OperatorBannerSeverity.Warning);
        }
        finally
        {
            IsBusy = false;
            NotifyCounts();
        }
    }

    /// <summary>
    /// Shows one owner answer for a typed UserAutomation operation.
    /// </summary>
    /// <remarks>
    /// The answer is decoded into a typed outcome instead of being reported as an
    /// undifferentiated success. A typed Kernel refusal is shown as its own
    /// actionable reason — unsupported contract version, legacy encoding, stale
    /// normalization revision, owner unavailability, invalid or moved receipt,
    /// or semantic rejection —
    /// and the retained response bytes stay available for exact inspection. When the
    /// owner answer itself carries the versioned occurrence projection, the zone
    /// database revision, the resolved instant and offset and the applied fold or
    /// gap disposition are decoded and displayed as inspection data. A Store
    /// transition can echo caller-authored revision bytes, so that projection
    /// alone never proves fresh owner normalization; it is reported as UNVERIFIED
    /// with a warning. The original bounded response remains available for exact
    /// inspection.
    /// </remarks>
    private void ShowUserAutomationResult(
        string action,
        JsonElement answer,
        UserAutomationOperatorRequest request)
    {
        ResultPayloadText = OperatorProjectionGuard.BoundRetainedResult(answer) ?? string.Empty;
        var validationContext = UserAutomationResultValidationContext.FromRequest(request);
        var outcome = UserAutomationOutcomeClassifier.Read(action, answer, validationContext);
        ResultSummary = outcome.Detail;
        SetBanner(
            outcome.Title,
            outcome.Detail,
            outcome.Class switch
            {
                UserAutomationOutcomeClass.OwnerAnswered => OperatorBannerSeverity.Informational,
                _ => OperatorBannerSeverity.Warning
            });
    }

    /// <summary>
    /// Mints the one typed operation for the selected closed kind.
    /// </summary>
    /// <remarks>
    /// Create and edit both carry a caller-supplied schedule revision through the
    /// closed profile. An edit carries BOTH the previous and the new revision,
    /// preserving its supersession lineage. Since this contract has no bound
    /// owner normalization result or migration route, both create and edit fail
    /// closed before submission. No revision is rewritten here.
    /// </remarks>
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

    private static string AppendLocalProjectionInspection(
        string detail,
        UserAutomationScheduleProjection? projection)
    {
        if (projection is null) return detail;

        const int maxPreviewOccurrences = 4;
        var shownOccurrences = Math.Min(maxPreviewOccurrences, projection.Occurrences.Count);
        var occurrencePreview = string.Join(
            Environment.NewLine,
            projection.Occurrences
                .Take(shownOccurrences)
                .Select((occurrence, index) =>
                    $"supplied V4 occurrence {index + 1}: {occurrence.Describe()}"));
        var inspection = "Local schedule projection for inspection only; no owner-issued normalization result is bound, so occurrence provenance is unverified."
            + Environment.NewLine
            + projection.ContractIdentity();
        inspection += projection.NormalizationReceipt is { } normalizationReceipt
            ? Environment.NewLine
                + "Caller-supplied normalization_receipt (identity and provenance unverified): "
                + $"receipt_id {normalizationReceipt.ReceiptId}; authority {normalizationReceipt.NormalizerAuthority}; "
                + $"source_digest {normalizationReceipt.SourceDigest}; "
                + $"occurrences_digest {normalizationReceipt.OccurrencesDigest}; "
                + $"zone_database_revision {normalizationReceipt.ZoneDatabaseRevision}."
            : Environment.NewLine + "No normalization_receipt is available in this projection.";
        if (occurrencePreview.Length != 0)
        {
            inspection += Environment.NewLine + occurrencePreview;
        }
        if (projection.Occurrences.Count > shownOccurrences)
        {
            inspection += Environment.NewLine
                + $"...{projection.Occurrences.Count - shownOccurrences} further V4 occurrence record(s) remain in the revision.";
        }
        return detail + Environment.NewLine + inspection;
    }

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

    /// <summary>
    /// Reads one caller-supplied schedule revision into the closed contract type
    /// and checks its bounded local shape for inspection.
    /// </summary>
    /// <remarks>
    /// The payload is READ, never repaired. The closed profile refuses an
    /// unmapped member, and the schedule mirror refuses the occurrence grammar
    /// and the exact supported contract version, so a legacy shape-only
    /// occurrence cannot be submitted as a current revision. Parsing does not
    /// prove owner normalization provenance. A refusal carries the owner's exact
    /// sentence and the one action that answers it — for a
    /// legacy encoding, a fresh owner normalization must be obtained before a
    /// NEW revision is supplied; this UI does not produce that normalization,
    /// and an immutable revision is never rewritten in place.
    /// <para>
    /// The exact supported contract version and the pinned zone database release
    /// are read out of the supplied occurrence bytes rather than from a second
    /// copy carried on this record: the owner side is
    /// <c>deny_unknown_fields</c>, so a member the owner does not know would make
    /// every request undecodable.
    /// </para>
    /// </remarks>
    private static UserAutomationRevision ParseRevision(string value)
    {
        // This is operator-typed JSON, so apply its independent structural caps
        // and duplicate-key rejection before allocating the typed revision. The
        // shared closed reader then rejects unknown fields at every schema level
        // and matches member names exactly; that is stated once, on
        // `OperatorJson.Reader`, and is not restated as a local copy here.
        OperatorResponseGuard.ValidateLocalParameter(value, "user_automation_revision");
        var revision = JsonSerializer.Deserialize<UserAutomationRevision>(value, OperatorJson.Reader)
            ?? throw new InvalidOperationException("UserAutomation schedule revision JSON is required.");
        revision.Validate();
        return revision;
    }

    private async Task LoadPageAsync(bool append)
    {
        // The runtime identity axis, checked BEFORE the request is started and
        // before anything retained is read for a scope, a cursor, an append or
        // a task revision. A projection built under one live owner-issued
        // session binding must not be consumed once that binding rotated or is
        // gone. This is a read, not a mutation: the retained state is dropped
        // and the fresh page is read immediately, so the result of the check
        // is not a refusal here. `append` is now meaningless because
        // `InvalidateForScopeChange` cleared the cursor; the load below reads
        // a first page and `InvalidateOnRotation` reports the rotation.
        RequireLiveBindingForRetainedState();
        _requestCancellation?.Cancel();
        _requestCancellation?.Dispose();
        _requestCancellation = new CancellationTokenSource();
        var cancellationToken = _requestCancellation.Token;
        IsBusy = true;
        NotifyCounts();
        try
        {
            if (IsUserAutomationPage)
            {
                // UserAutomation has a typed command route, but no canonical
                // listing projection. Clear any prior page first, including the
                // owner grant stamp it was built under, so the before-use grant
                // comparison can never find a stamp for a page that is gone. A
                // known binding that withholds the command capability gets the
                // withheld explanation (role-filtered rendering); the command
                // panel itself stays hidden until the grant allows it.
                ClearRetainedProjectionState("UserAutomation listing unavailable; no total is available.");
                if (!RequireCommandCapability("user_automation"))
                {
                    ResultSummary = "UserAutomation commands withheld for this role; no total is available.";
                    return;
                }
                SetBanner(
                    "UserAutomation listing unavailable",
                    "The listing is unavailable until its owner issues a canonical listing projection. The UserAutomation command panel remains available.",
                    OperatorBannerSeverity.Warning);
                return;
            }

            ValidateScope();
            if (!RequireReadCapability()) return;
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
            cancellationToken.ThrowIfCancellationRequested();
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
            // Owner-issued degraded capabilities are shown as degraded (I11.9):
            // a page carrying open incidents or concerning backups never keeps
            // the green connected banner.
            var degraded = OperatorDegradedSignals.FromRecords(page.Records);
            var incidentCount = degraded.Count(signal => signal.Kind == OperatorDegradedSignals.IncidentKind);
            var backupCount = degraded.Count - incidentCount;
            var totalQualifier = page.TotalIsExact ? string.Empty : "at least ";
            ResultSummary = $"Showing {Records.Count} of {totalQualifier}{page.TotalMatching}; page generated {page.GeneratedAt.LocalDateTime:g}.";
            if (degraded.Count > 0)
            {
                ResultSummary += $" {incidentCount} open incident(s), {backupCount} backup concern(s) — see the degraded banner.";
            }
            RefreshRoleBinding();
            UpdateBindingSummary(page);
            // Green means whole: a truncated projection is an incomplete
            // rendering of the canonical state, so it is shown as degraded
            // (Warning) rather than green even when no incident or backup
            // signal fired. The retained records stay visible; only the
            // completeness claim is withheld.
            if (page.Truncated)
            {
                ResultSummary += " The owner truncated this page: the rendering is incomplete.";
            }
            // The rotation notice is a statement about the binding, not about
            // completeness, so it is reported on EVERY banner. A rotation that
            // happened to arrive on a truncated or degraded page is still a
            // rotation, and withholding the word there would leave the operator
            // reading a stale page as if nothing had been dropped. The
            // invalidation itself happened above, before this page was used;
            // this only names it.
            var rotationNotice = rotated
                ? " Runtime rotated: dependent state was invalidated before use."
                : string.Empty;
            if (degraded.Count == 0 && !page.Truncated)
            {
                SetBanner(
                    "Connected",
                    $"Runtime {page.RuntimeId}; auth generation {page.AuthGeneration}; typed {page.Projection} projection."
                        + rotationNotice,
                    OperatorBannerSeverity.Success);
            }
            else if (page.Truncated && degraded.Count == 0)
            {
                SetBanner(
                    "Projection truncated",
                    $"Runtime {page.RuntimeId} truncated the {page.Projection} page: {Records.Count} record(s) shown, completeness not claimed. Narrow the scope or filters for a whole page."
                        + rotationNotice,
                    OperatorBannerSeverity.Warning);
            }
            else
            {
                const int maxShownSignals = 3;
                var shown = degraded
                    .Take(maxShownSignals)
                    .Select(signal => $"{signal.Kind}: {ClipSignalSummary(signal.Summary)}");
                var detail = string.Join(" · ", shown);
                if (degraded.Count > maxShownSignals)
                {
                    detail += $" · +{degraded.Count - maxShownSignals} more in the projection";
                }
                var severe = degraded.Any(signal => signal.Severe);
                SetBanner(
                    severe ? "Degraded backend capability" : "Operational notices need attention",
                    $"Runtime {page.RuntimeId} reports {incidentCount} open incident(s) and {backupCount} backup concern(s): {detail}. " +
                    "Full evidence and recovery references stay expandable on each record."
                        + rotationNotice,
                    OperatorBannerSeverity.Warning);
            }
        }
        catch (OperationCanceledException)
        {
            if (!cancellationToken.IsCancellationRequested || !IsUserAutomationPage)
            {
                SetBanner("Request cancelled", "The nonblocking Governor request was cancelled.", OperatorBannerSeverity.Informational);
            }
        }
        catch (OperatorRestartRequiredException restart)
        {
            // The broker session binding is gone: only a process restart under
            // a fresh owner handoff restores it. This is a lifecycle state,
            // not a backend degradation, so it never shares the degraded
            // banner. Retained unknown-outcome operations keep their phase for
            // reconciliation after restart; nothing is compacted here.
            //
            // The retained projection is dropped HERE, at the moment the loss
            // is proven, and not at the next use: I11.8 requires that a new
            // operational binding never revives anything from cached
            // application state, and a restart creates a new binding. Rows,
            // selection, cursor, graph focus, task context and result payload
            // therefore stop describing a live owner state immediately.
            ClearRetainedProjectionState(
                "The operator session binding is gone; retained projection state was invalidated.");
            if (!cancellationToken.IsCancellationRequested || !IsUserAutomationPage)
            {
                SetBanner(
                    "Session binding lost — restart required",
                    $"{restart.Message} {OperatorHandoff.ReacquisitionRequirement}. Retained operations stay reconciling.",
                    OperatorBannerSeverity.Warning);
            }
        }
        catch (Exception error)
        {
            if (!cancellationToken.IsCancellationRequested || !IsUserAutomationPage)
            {
                SetBanner(
                    "Degraded / reconnect required",
                    $"The projection read did not complete ({OperatorFaultReason.ForException(error)}); "
                    + "reconnect through a fresh broker handoff before retrying.",
                    OperatorBannerSeverity.Error);
            }
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
        // The granted binding withholds what it withholds: a mutation the
        // role cannot lawfully execute is refused before an identity is
        // minted or journaled, never after.
        if (!RequireCommandCapability(action))
        {
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
            // A first send transmits the typed envelope the action minted; a
            // reconciliation resends the exact retained envelope bytes under
            // the same operation identity, never a second mutation.
            JsonElement receipt = isReconcile
                ? await _client.ReconcileAsync(
                    ParseRetainedEnvelope(pending.EnvelopeJson),
                    _requestCancellation?.Token ?? CancellationToken.None)
                : await _client.CommandAsync(
                    envelope,
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
                if (staleFence)
                {
                    // The owner PROVED the State Fence moved: the mutation was
                    // not admitted at the submitted revision. That is a fence
                    // change this client observed directly, and the retained
                    // task context carries exactly the revision the owner just
                    // refused. Rows, selection, cursor, graph focus, task
                    // context and result payload are dropped HERE, before
                    // anything can read that revision again. The retained
                    // operation record is not dependent UI state and is
                    // compacted by the branch below as usual.
                    //
                    // The request that observed the refusal has already
                    // completed, so no in-flight response can apply state from
                    // before it; the retained state is dropped without
                    // cancelling the request token a later command still uses.
                    ClearRetainedProjectionState(
                        "The owner refused at the current State Fence; dependent UI state was invalidated before use.");
                }
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
            // The binding that carried this mutation is proven gone, so the
            // projection it was built from stops describing a live owner state
            // now rather than at the next use. The retained operation record
            // keeps its own identity and is unaffected.
            ClearRetainedProjectionState(
                "The operator session binding is gone; retained projection state was invalidated.");
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
                $"{action}: the transport did not prove an owner outcome ({OperatorFaultReason.ForException(error)}); use Reconcile before any retry.",
                OperatorBannerSeverity.Warning);
        }
        finally
        {
            IsBusy = false;
            NotifyCounts();
        }
    }

    /// Reads one owner-bound command receipt. The receipt is read only when it is
    /// bound to this exact operation identity, this exact expected revision, and
    /// carries a typed terminal disposition. A claim of an executed durable
    /// mutation must be consistent with the canonical receipt it carries, except
    /// for the one accepted-but-unproven shape — executed, accepted, and no
    /// canonical receipt — which is returned so the caller can explain it
    /// actionably; it is never treated as a success. A refusal whose outcome is
    /// the owner's `STALE_STATE_FENCE` reason code is terminal and distinct from
    /// a plain rejection and from an unknown outcome.
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

        // The receipt's `revision` is the produced post-transition task revision,
        // not the revision that was expected at submission: a committed mutation
        // advances the revision, so a successful receipt legitimately returns a
        // higher value. What this must prove is therefore monotonic — the receipt
        // is bound to a revision at least as new as the one this operation was
        // submitted against, so it cannot predate the submission. A lower
        // revision is an unbound receipt from before this command.
        if (!staleFence
            && (!receipt.TryGetProperty("revision", out var revision)
                || revision.ValueKind != JsonValueKind.Number
                || !revision.TryGetUInt64(out var receiptRevision)
                || receiptRevision < expectedOperationRevision))
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

        // A claimed durable mutation that carries no canonical receipt is not a
        // refused disposition: it is the owner's accepted-but-unproven answer,
        // and the caller turns it into an actionable reconciliation instruction
        // rather than a bare "inconsistent" refusal. Only that one shape is
        // exempted. An unexecuted operation that still carries a receipt, and an
        // executed one the owner did not accept, remain refusals — the second
        // disjunct is never exempted, so that arm refuses every executed receipt
        // the owner did not accept, with or without a receipt id.
        var executedWithoutCanonicalReceipt = executed && receiptId is null;
        if ((!executedWithoutCanonicalReceipt && executed != (receiptId is not null))
            || (executed && !accepted))
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
        if (rotated)
        {
            // Every rebuildable view of the previous owner state is cleared
            // before the new page is applied. The task context in particular
            // carries the owner task revision used as `expected_revision`, so
            // keeping it would send a mutation against a rotated revision.
            ClearDependentProjectionState("No projection loaded.");
        }
        // The page now applied is a view of the session binding that is live
        // NOW, so the retained state is stamped with it. Recording the grant
        // here is what makes the before-use comparison in
        // `RequireLiveBindingForRetainedState` an observation of the live
        // transport rather than a hard-wired pass, and it is recorded only
        // when a page is actually retained.
        _projectionBinding = binding;
        _projectionGrant = _roleBinding;
        return rotated;
    }

    /// The runtime identity axis of the retained UI state, checked before a
    /// rebuildable projection is used.
    ///
    /// The projection binding already carries the owner's runtime id, auth
    /// generation, owner task revision, projection and scope, and
    /// `InvalidateOnRotation` compares those when a NEW page arrives. That
    /// check cannot run before a USE, because it needs the new page — so between
    /// the moment the owner-issued session binding rotates (or the transport
    /// that carried it goes away) and the moment the next page lands, the
    /// retained rows, selection, cursor, graph focus, task context and result
    /// payload are still readable. The task context in particular carries the
    /// owner task revision used as `expected_revision`, and the cursor is a
    /// paging token for a binding that may no longer exist.
    ///
    /// The granted binding is read LIVE from the transport and compared against
    /// the one the retained projection was actually built under. When they
    /// differ, every dependent piece of rebuildable state is dropped HERE —
    /// before the caller reads a scope, a cursor, an append flag, a task
    /// revision or a result payload — and the caller is told to re-read.
    /// Pending unknown-outcome operations are not dependent UI state: they
    /// carry their own operation identity and stay reconcilable.
    ///
    /// Returns true when the retained state is still bound to the live grant
    /// and may be used. Returns false when it was just invalidated, so the
    /// caller must not use anything it held.
    private bool RequireLiveBindingForRetainedState()
    {
        // No page is retained, so nothing here depends on a grant. There is
        // nothing to invalidate and nothing that could be read stale. This is
        // the honest floor, not a wildcard: `_projectionBinding` is non-null
        // exactly when a page is applied and is cleared by every invalidation.
        if (_projectionBinding is null) return true;
        RefreshRoleBinding();
        if (RoleBindingEquals(_projectionGrant, _roleBinding)) return true;
        // The grant the retained projection was built under is gone or has
        // rotated. `_projectionBinding` and `_projectionGrant` go with it:
        // keeping them would let the next page's `DiffersFrom` compare against
        // a grant that no longer describes this process and report "no
        // rotation".
        InvalidateForScopeChange();
        return false;
    }

    /// Bounded, redacted description of one granted binding. It names the
    /// presence, the role and the capability count — never a credential, an
    /// endpoint, a nonce or a record body (A11).
    private static string DescribeGrant(OperatorRoleBinding? grant) =>
        grant is null
            ? "no established binding"
            : $"role {grant.Role} with {grant.Capabilities.Count} capability/capabilities";

    /// A locally changed scope or page no longer describes the currently
    /// displayed projection. Drop that rebuildable context immediately, before
    /// the next owner request starts; pending operation identities stay intact.
    private void InvalidateForScopeChange()
    {
        // A response started for the previous page or scope must not apply
        // after this local binding changes. LoadPageAsync checks this token
        // immediately after the owner call returns, before using the page.
        _requestCancellation?.Cancel();
        ClearRetainedProjectionState("No projection loaded for the current scope.");
    }

    /// Drops the retained projection and the owner grant it was stamped with,
    /// then every rebuildable view built from them. The binding and its grant
    /// stamp always go together: a stamp without a binding, or a binding
    /// without its stamp, would let the before-use grant comparison answer a
    /// question about state that is no longer retained.
    ///
    /// This does NOT cancel the in-flight request; `InvalidateForScopeChange`
    /// does that for a local change. Use this when the state is dropped from
    /// inside the request that is replacing it.
    private void ClearRetainedProjectionState(string summary)
    {
        _projectionBinding = null;
        _projectionGrant = null;
        ClearDependentProjectionState(summary);
    }

    private void ClearDependentProjectionState(string summary)
    {
        Records.Clear();
        SelectedRecord = null;
        SelectedAction = null;
        _nextCursor = null;
        _graphSelectedRef = null;
        _taskContext = null;
        ResultPayloadText = string.Empty;
        ResultSummary = summary;
        NotifyCounts();
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

    /// Pulls the broker-granted role binding off the live transport. The
    /// grant is the exact set the broker redeemed this binding for
    /// (I11.8); views and mutations gate on it, never on a constant.
    private void RefreshRoleBinding()
    {
        var binding = _client.GrantedBinding;
        if (RoleBindingEquals(_roleBinding, binding)) return;
        _roleBinding = binding;
        OnPropertyChanged(nameof(GrantedRole));
        OnPropertyChanged(nameof(CanReadProjection));
        OnPropertyChanged(nameof(CanIssueCommands));
        OnPropertyChanged(nameof(IsUserAutomationOperable));
        UpdateBindingSummary(null);
    }

    private static bool RoleBindingEquals(OperatorRoleBinding? left, OperatorRoleBinding? right)
    {
        if (left is null || right is null) return left is null && right is null;
        return string.Equals(left.Role, right.Role, StringComparison.Ordinal)
            && left.Capabilities.SequenceEqual(right.Capabilities, StringComparer.Ordinal);
    }

    private void UpdateBindingSummary(OperatorProjectionPage? page)
    {
        if (_roleBinding is null)
        {
            BindingSummary = "Session binding not yet established; the transport authenticates every request.";
            return;
        }
        var summary = $"Role {_roleBinding.Role} · capabilities ({_roleBinding.Capabilities.Count}): {string.Join(", ", _roleBinding.Capabilities)}";
        if (!_roleBinding.GrantsCommands)
        {
            summary += "; commands withheld: this role was not granted 'operator.command'";
        }
        if (page is not null)
        {
            summary += $" · runtime {page.RuntimeId} · auth generation {page.AuthGeneration}";
        }
        BindingSummary = summary;
    }

    /// Refuses a read the granted binding withholds, before any query is
    /// sent. Stale rows are cleared first so no view outlives the grant it
    /// came from; nothing is fabricated in their place.
    private bool RequireReadCapability()
    {
        RefreshRoleBinding();
        if (CanReadProjection) return true;
        // A withheld read capability is an owner-grant change, so the grant
        // stamp and the binding it describes go with the rows. The existing
        // clearing primitive is used so that "cleared" always means "nothing
        // retained", and the before-use grant comparison can never compare a
        // stamp for a page that no longer exists.
        ClearRetainedProjectionState("Projection unavailable for this role; no total is available.");
        SetBanner(
            "Projection unavailable for this role",
            $"Role '{_roleBinding?.Role}' was not granted '{OperatorCapabilityNames.ControlboardRead}'; no query was sent.",
            OperatorBannerSeverity.Warning);
        return false;
    }

    /// Refuses an effect the granted binding withholds, before anything is
    /// journaled or sent (I11.3: the UI never offers a principal an action it
    /// cannot lawfully execute). A retained pending operation keeps its phase:
    /// a refused reconciliation says nothing about the earlier attempt.
    private bool RequireCommandCapability(string action)
    {
        RefreshRoleBinding();
        if (CanIssueCommands) return true;
        SetBanner(
            "Command withheld for this role",
            $"{action}: role '{_roleBinding?.Role}' was not granted '{OperatorCapabilityNames.OperatorCommand}'; nothing was journaled and nothing was sent.",
            OperatorBannerSeverity.Warning);
        return false;
    }

    /// Bounds one owner-issued signal summary for the status banner. Banner
    /// text is presentation: the full record stays in the projection with its
    /// evidence and recovery fields expandable.
    private static string ClipSignalSummary(string value) =>
        value.Length <= 200 ? value : $"{value[..200]}…";

    /// One bounded reason for a banner that reports a locally refused typed
    /// request.
    ///
    /// A refusal raised by this application's own closed UserAutomation
    /// contract keeps its message. Every such message is assembled only from
    /// locally authored field names, the generated owner refusal table and
    /// pinned contract constants — the
    /// <see cref="UserAutomationScheduleContractException"/> shape is the
    /// generated owner Display sentence joined to a locally authored action —
    /// so it names the rule that refused the request and carries no value from
    /// the refused bytes. A framework exception message is never shown — a
    /// serializer message can carry a JSON path, a line/byte offset and a
    /// character lifted from the refused bytes — so only its closed
    /// [`OperatorFaultReason`] code is displayed, exactly as the transport
    /// paths do.
    private static string BoundedRefusalReason(Exception error) =>
        error is JsonException
            ? OperatorFaultReason.ForException(error)
            : error.Message;

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
