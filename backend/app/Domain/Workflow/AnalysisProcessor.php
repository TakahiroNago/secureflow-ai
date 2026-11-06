<?php

namespace App\Domain\Workflow;

use App\Ai\AiGateway;
use App\Ai\AiProviderException;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Models\AiAnalysisRequest;
use App\Models\User;
use App\Security\Output\InvalidAiOutputException;
use App\Security\Output\OutputValidator;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Database\QueryException;
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

    /** Step 2-4 builds the real prompt. The mock uses neither this nor the input, and none is stored. */
    private const PROMPT_UNTIL_STEP_2_4 = 'Propose tasks as JSON.';

    public function __construct(
        private AiGateway $gateway,
        private OutputValidator $validator,
        private WorkflowCreator $creator,
        private AuditLogger $audit,
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
            $tasks = $this->validator->validate($this->gateway->generate(self::PROMPT_UNTIL_STEP_2_4, '')->content);
            $this->creator->create($analysis, $user, $tasks);
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
