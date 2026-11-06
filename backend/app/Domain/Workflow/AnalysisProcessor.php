<?php

namespace App\Domain\Workflow;

use App\Ai\AiGateway;
use App\Ai\AiProviderException;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Domain\Security\ScanRecorder;
use App\Models\AiAnalysisRequest;
use App\Models\SecurityScan;
use App\Models\User;
use App\Security\Output\InvalidAiOutputException;
use App\Security\Output\OutputValidator;
use App\Security\Output\ValidatedTask;
use App\Security\Scanning\InputScanner;
use App\Security\Scanning\InputScanResult;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use PDOException;

/**
 * docs/architecture.md §7, the worker's part. No transaction is open during the AI call: it can take far
 * longer than the idle-in-transaction limit, and would hold a connection and locks for all of it.
 */
final readonly class AnalysisProcessor
{
    public const ERROR_FAILED = 'ANALYSIS_FAILED';

    public const ERROR_STALE = 'ANALYSIS_STALE';

    public const ERROR_USER_INACTIVE = 'USER_INACTIVE';

    public const ERROR_AI_UNAVAILABLE = 'AI_UNAVAILABLE';

    public const ERROR_OUTPUT_BLOCKED = 'AI_OUTPUT_BLOCKED';

    /** Step 2-4 builds the real prompt. Only the masked input is ever handed over, and the mock uses neither. */
    private const PROMPT_UNTIL_STEP_2_4 = 'Propose tasks as JSON.';

    public function __construct(
        private AiGateway $gateway,
        private OutputValidator $validator,
        private WorkflowCreator $creator,
        private AuditLogger $audit,
        private InputScanner $scanner,
        private ScanRecorder $recorder,
    ) {}

    public function process(string $analysisId): void
    {
        // Only one run can move the row out of queued. A job that comes back finds nothing to do.
        $claimed = AiAnalysisRequest::query()
            ->whereKey($analysisId)
            ->where('status', AiAnalysisRequest::STATUS_QUEUED)
            ->update(['status' => AiAnalysisRequest::STATUS_PROCESSING, 'started_at' => now(), 'heartbeat_at' => now()]);

        if ($claimed !== 1) {
            return;
        }

        $analysis = AiAnalysisRequest::query()->findOrFail($analysisId);
        $user = User::query()->find($analysis->user_id);

        if ($user === null || ! $user->is_active) {
            $this->fail($analysisId, self::ERROR_USER_INACTIVE);

            return;
        }

        try {
            $tasks = $this->validator->validate($this->gateway->generate(self::PROMPT_UNTIL_STEP_2_4, (string) $analysis->input_masked)->content);
            $result = $this->scanner->scanFields(PlanText::fields(array_map(self::textOf(...), $tasks)));

            if ($result->blocks()) {
                $this->block($analysisId, $user, $result);

                return;
            }

            $maskedFields = $result->maskedFields ?? [];

            // Masking made what the AI wrote too long for the plan. Cutting it could change what it says.
            if (PlanText::tooLong($maskedFields) !== []) {
                throw new InvalidAiOutputException('masked_too_long');
            }

            $this->creator->create($analysis, $user, self::maskedTasks($tasks, $maskedFields), $result);
        } catch (AiProviderException) {
            $this->fail($analysisId, self::ERROR_AI_UNAVAILABLE);
        } catch (InvalidAiOutputException|InvalidPlanException) {
            $this->fail($analysisId, InvalidAiOutputException::CODE);
        } catch (ServiceUnavailableException|QueryException|PDOException) {
            $this->fail($analysisId, self::ERROR_FAILED);
        }
    }

    /**
     * Only a row that is still unfinished changes, so a late failure cannot undo a success. Never throws:
     * it runs while something else has already gone wrong, and the recovery command tries again.
     */
    public function fail(string $analysisId, string $errorCode): void
    {
        try {
            $changed = AiAnalysisRequest::query()
                ->whereKey($analysisId)
                ->whereIn('status', [AiAnalysisRequest::STATUS_QUEUED, AiAnalysisRequest::STATUS_PROCESSING])
                ->update([
                    'status' => AiAnalysisRequest::STATUS_FAILED,
                    'error_code' => $errorCode,
                    'input_masked' => null,
                    'finished_at' => now(),
                ]);

            if ($changed === 1) {
                $this->record($analysisId, $errorCode);
            }
        } catch (QueryException|PDOException $exception) {
            Log::error('analysis.fail_not_recorded', [
                'metric' => 'analysis.fail_not_recorded',
                'analysis_id' => $analysisId,
                'error_code' => $errorCode,
                'exception' => $exception::class,
            ]);
        }
    }

    /**
     * What the AI wrote stopped the work, and none of it is kept: only that it happened (ST-35).
     *
     * @throws ServiceUnavailableException
     */
    private function block(string $analysisId, User $user, InputScanResult $result): void
    {
        SingleAttemptTransaction::run(DB::connection(), function () use ($analysisId, $user, $result): void {
            $locked = AiAnalysisRequest::query()
                ->whereKey($analysisId)
                ->where('status', AiAnalysisRequest::STATUS_PROCESSING)
                ->lockForUpdate()
                ->first();

            if ($locked === null) {
                return;
            }

            $scan = $this->recorder->record($user, SecurityScan::TARGET_OUTPUT, $analysisId, $result);

            $locked->forceFill([
                'status' => AiAnalysisRequest::STATUS_BLOCKED,
                'error_code' => self::ERROR_OUTPUT_BLOCKED,
                'output_scan_id' => $scan->id,
                'input_masked' => null,
                'finished_at' => now(),
            ])->save();
        });
    }

    /**
     * @return array{title: string, description: string, steps: list<string>, target_data: string, impact_summary: string}
     */
    private static function textOf(ValidatedTask $task): array
    {
        return [
            'title' => $task->title,
            'description' => $task->description,
            'steps' => $task->steps,
            'target_data' => $task->targetData,
            'impact_summary' => $task->impactSummary,
        ];
    }

    /**
     * @param  list<ValidatedTask>  $tasks
     * @param  array<string, string>  $maskedFields
     * @return list<ValidatedTask>
     */
    private static function maskedTasks(array $tasks, array $maskedFields): array
    {
        $masked = PlanText::withMasked(array_map(self::textOf(...), $tasks), $maskedFields);

        return array_map(fn (ValidatedTask $task, array $text) => new ValidatedTask(
            $text['title'],
            $text['description'],
            $task->actionType,
            $text['steps'],
            $task->priority,
            $task->requestedPermissions,
            $text['target_data'],
            $text['impact_summary'],
            $task->decision,
            $task->permissions,
        ), $tasks, $masked);
    }

    private function record(string $analysisId, string $errorCode): void
    {
        $analysis = AiAnalysisRequest::query()->findOrFail($analysisId);

        $this->audit->recordAfterTransaction(
            AuditEntry::system(
                AuditEventType::AnalysisFailed,
                User::query()->find($analysis->user_id),
                'failure',
                ['reason_code' => $errorCode, 'analysis_id' => $analysisId],
            ),
            'analysis_failed_unrecorded',
        );
    }
}
