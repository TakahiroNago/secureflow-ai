<?php

namespace App\Domain\Workflow;

use App\Audit\AuditAvailability;
use App\Jobs\AnalyzeWorkflowJob;
use App\Models\AiAnalysisRequest;
use App\Models\User;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Support\Facades\DB;

final readonly class AnalysisService
{
    public function __construct(private AuditAvailability $availability) {}

    /**
     * The row and the job commit together, so neither can exist without the other. The input is not a
     * parameter: only its length is known here, and nothing can store it (docs/development-roadmap.md §3).
     *
     * @throws ServiceUnavailableException
     */
    public function request(User $user, int $inputCharCount): AiAnalysisRequest
    {
        $this->availability->assertAvailable();

        return SingleAttemptTransaction::run(DB::connection(), function () use ($user, $inputCharCount): AiAnalysisRequest {
            $analysis = new AiAnalysisRequest;
            $analysis->forceFill([
                'user_id' => $user->id,
                'status' => AiAnalysisRequest::STATUS_QUEUED,
                'input_char_count' => $inputCharCount,
            ])->save();

            AnalyzeWorkflowJob::dispatch($analysis->id, $analysis->organization_id);

            return $analysis;
        });
    }
}
