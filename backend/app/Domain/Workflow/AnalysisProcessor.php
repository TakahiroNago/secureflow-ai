<?php

namespace App\Domain\Workflow;

use App\Ai\AiGateway;
use App\Ai\AiProviderException;
use App\Ai\AiResponse;
use App\Ai\BuiltPrompt;
use App\Ai\PromptBuilder;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Domain\Security\ScanRecorder;
use App\Models\AiAnalysisRequest;
use App\Models\SecurityScan;
use App\Models\User;
use App\Security\Output\InvalidAiOutputException;
use App\Security\Output\OutputScanner;
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

    public function __construct(
        private AiGateway $gateway,
        private PromptBuilder $prompts,
        private OutputScanner $outputs,
        private WorkflowCreator $creator,
        private AuditLogger $audit,
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
            $prompt = $this->prompts->build((string) $analysis->input_masked);
            $scanned = $this->outputs->scan($this->callAi($user, $analysisId, $prompt)->content, $prompt->canary);

            if ($scanned->result->blocks()) {
                $this->block($analysisId, $user, $scanned->result);

                return;
            }

            $this->creator->create($analysis, $user, $scanned->tasks, $scanned->result);
        } catch (AiProviderException) {
            $this->fail($analysisId, self::ERROR_AI_UNAVAILABLE);
        } catch (InvalidAiOutputException|InvalidPlanException) {
            $this->fail($analysisId, InvalidAiOutputException::CODE);
        } catch (ServiceUnavailableException|QueryException|PDOException) {
            $this->fail($analysisId, self::ERROR_FAILED);
        }
    }

    /**
     * ai.call says that a call was made and how it ended, with no text. If it cannot be written, the analysis goes on:
     * the critical log has it. The tokens and the limits arrive with the real provider in step 2-8.
     *
     * @throws AiProviderException
     */
    private function callAi(User $user, string $analysisId, BuiltPrompt $prompt): AiResponse
    {
        try {
            $response = $this->gateway->generate($prompt->systemPrompt, $prompt->input);
        } catch (AiProviderException $exception) {
            $this->recordCall($user, $analysisId, 'failure', $exception->failure->value);

            throw $exception;
        }

        $this->recordCall($user, $analysisId, 'success', null);

        return $response;
    }

    private function recordCall(User $user, string $analysisId, string $result, ?string $reason): void
    {
        $this->audit->recordAfterTransaction(
            AuditEntry::byUserOn(AuditEventType::AiCall, $user, 'ai_analysis', $analysisId, array_filter([
                'provider' => config()->string('ai.provider'),
                'reason_code' => $reason,
            ], fn (?string $value) => $value !== null), $result),
            'ai_call_unrecorded',
        );
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

        if ($result->blockReason === InputScanResult::REASON_CANARY) {
            // Someone may have got the prompt out of the model, which is worth looking at soon. The canary is not here.
            Log::error('security.canary_leak', ['metric' => 'security.canary_leak', 'analysis_id' => $analysisId]);
        }
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
