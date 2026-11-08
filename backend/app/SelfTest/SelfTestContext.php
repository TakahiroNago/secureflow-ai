<?php

namespace App\SelfTest;

use App\Ai\AiRequest;
use App\Ai\PromptBuilder;
use App\Ai\Providers\MockAiProvider;
use App\Ai\Providers\MockScenario;
use App\Domain\Execution\ExecutionService;
use App\Domain\Security\ScanRecorder;
use App\Domain\Workflow\WorkflowCreator;
use App\Domain\Workflow\WorkflowDecisions;
use App\Domain\Workflow\WorkflowEditor;
use App\Domain\Workflow\WorkflowSubmission;
use App\Models\AiAnalysisRequest;
use App\Models\Organization;
use App\Models\SecurityScan;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowExecution;
use App\Models\WorkflowRevision;
use App\Models\WorkflowTask;
use App\Security\Output\OutputScanner;
use App\Security\Output\ScannedOutput;
use App\Security\Scanning\InputScanner;
use App\Support\Database\SingleAttemptTransaction;
use Closure;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PDOException;

/**
 * What a case may use. Everything it creates is inside the case's transaction, which the runner rolls back. The AI
 * is always the mock, built here: the container's provider is never asked for (docs/test-strategy.md §6).
 */
final class SelfTestContext
{
    public const INPUT = '先週の問い合わせを要約して、対応が必要なものを一覧にしてください。';

    public function __construct(
        public readonly string $organizationId,
        public readonly User $admin,
        private readonly InputScanner $scanner,
        private readonly OutputScanner $outputs,
        private readonly PromptBuilder $prompts,
        private readonly ScanRecorder $recorder,
        private readonly WorkflowCreator $creator,
        private readonly WorkflowSubmission $submission,
        private readonly WorkflowDecisions $decisions,
        private readonly WorkflowEditor $editor,
        private readonly ExecutionService $executions,
    ) {}

    public function scanner(): InputScanner
    {
        return $this->scanner;
    }

    /**
     * A user that exists for this case only. The password is random and never known to anyone.
     */
    public function temporaryUser(string $role, ?string $organizationId = null): User
    {
        $user = new User;
        $user->forceFill([
            'organization_id' => $organizationId ?? $this->organizationId,
            'name' => 'self-test '.$role,
            'email' => 'self-test-'.Str::uuid7().'@invalid.example',
            'password' => Str::random(40),
            'role' => $role,
            'is_active' => true,
        ])->save();

        return $user->refresh();
    }

    /**
     * An organization that exists for this case only (for what depends on who else is in one).
     */
    public function temporaryOrganization(): Organization
    {
        return Organization::query()->create(['name' => 'self-test '.Str::uuid7()]);
    }

    /**
     * What the mock AI answers for a scenario, as the real pipeline sees it: a prompt with a canary, the answer,
     * and the output scan. No provider is resolved from the container.
     */
    public function aiOutput(MockScenario $scenario): ScannedOutput
    {
        $prompt = $this->prompts->build(self::INPUT);
        $answer = (new MockAiProvider($scenario))->generate(new AiRequest($prompt->systemPrompt, $prompt->input, 2000, 30));

        return $this->outputs->scan($answer->content, $prompt->canary);
    }

    /**
     * A draft workflow of the creator, built the way an analysis builds one: a scanned input, the mock's answer
     * through the output scan, and WorkflowCreator. Null when the scenario's answer is stopped by the scan.
     */
    public function draftWorkflow(User $creator, MockScenario $scenario = MockScenario::Normal): ?Workflow
    {
        $input = $this->scanner->scanText(self::INPUT);
        $inputScan = $this->recorder->record($creator, SecurityScan::TARGET_INPUT, null, $input);

        $analysis = new AiAnalysisRequest;
        $analysis->forceFill([
            'user_id' => $creator->id,
            'status' => AiAnalysisRequest::STATUS_PROCESSING,
            'input_masked' => $input->maskedText(),
            'input_char_count' => mb_strlen(self::INPUT),
            'input_scan_id' => $inputScan->id,
            'started_at' => now(),
            'heartbeat_at' => now(),
        ])->save();

        $scanned = $this->aiOutput($scenario);

        if ($scanned->result->blocks()) {
            return null;
        }

        $this->creator->create($analysis, $creator, $scanned->tasks, $scanned->result);
        $workflowId = AiAnalysisRequest::query()->whereKey($analysis->id)->value('workflow_id');

        return is_string($workflowId) ? $this->workflow($workflowId) : null;
    }

    public function workflow(string $id): Workflow
    {
        return Workflow::query()->whereKey($id)->firstOrFail();
    }

    public function revision(Workflow $workflow): WorkflowRevision
    {
        return WorkflowRevision::query()->whereKey($workflow->current_revision_id)->firstOrFail();
    }

    /**
     * @return Collection<int, WorkflowTask>
     */
    public function tasks(Workflow $workflow): Collection
    {
        return WorkflowTask::query()->where('workflow_id', $workflow->id)->orderBy('position')->get();
    }

    public function submit(User $creator, Workflow $workflow): void
    {
        $this->submission->submit($creator, $this->workflow($workflow->id));
    }

    public function approve(User $approver, Workflow $workflow): void
    {
        $current = $this->workflow($workflow->id);
        $revision = $this->revision($current);

        $this->decisions->approve($approver, $current, $revision->revision_no, $revision->plan_hash, true, null);
    }

    /**
     * @param  array<string, mixed>  $fields
     */
    public function editTask(User $creator, Workflow $workflow, WorkflowTask $task, array $fields): void
    {
        $current = $this->workflow($workflow->id);

        $this->editor->updateTask($creator, $current, $task, $this->revision($current)->revision_no, $fields);
    }

    public function requestExecution(User $user, Workflow $workflow, string $key): WorkflowExecution
    {
        return $this->executions->request($user, $this->workflow($workflow->id), $key);
    }

    /**
     * A statement the database is expected to refuse, in a savepoint so that the case's transaction stays usable.
     * Returns the SQLSTATE of the refusal, or null when the statement went through.
     */
    public function attempt(Closure $statement): ?string
    {
        try {
            SingleAttemptTransaction::run(DB::connection(), fn () => $statement());
        } catch (QueryException $exception) {
            $previous = $exception->getPrevious();

            return $previous instanceof PDOException ? (string) ($previous->errorInfo[0] ?? $exception->getCode()) : (string) $exception->getCode();
        }

        return null;
    }
}
