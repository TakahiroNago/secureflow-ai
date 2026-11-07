<?php

namespace App\Domain\Workflow;

use App\Audit\AuditAvailability;
use App\Domain\Security\InputBlockedException;
use App\Domain\Security\ScanRecorder;
use App\Jobs\AnalyzeWorkflowJob;
use App\Models\AiAnalysisRequest;
use App\Models\SecurityScan;
use App\Models\User;
use App\Security\Scanning\InputScanner;
use App\Security\Scanning\InputScanResult;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SensitiveParameter;

final readonly class AnalysisService
{
    public function __construct(
        private AuditAvailability $availability,
        private InputScanner $scanner,
        private ScanRecorder $recorder,
        private AiUsageLedger $usage,
    ) {}

    /**
     * Only the masked text goes any further. The row, its scan and the job commit together, so none can exist
     * without the others. A stop keeps the scan and nothing else: no row, no job, and so no AI call.
     *
     * @throws AiLimitExceededException before anything is looked at or kept
     * @throws InputBlockedException
     * @throws ServiceUnavailableException
     */
    public function request(User $user, #[SensitiveParameter] string $input): AiAnalysisRequest
    {
        $this->availability->assertAvailable();

        $refusal = $this->usage->refusalFor($user);

        if ($refusal !== null) {
            $this->usage->recordRefusal($user, null, $refusal);

            throw new AiLimitExceededException('AI limit exceeded');
        }

        $result = $this->scanner->scanText($input);

        if ($result->blocks()) {
            $this->recordOnly($user, $result);

            throw new InputBlockedException($result);
        }

        $characters = mb_strlen($input, 'UTF-8');

        return SingleAttemptTransaction::run(DB::connection(), function () use ($user, $result, $characters): AiAnalysisRequest {
            $id = (string) Str::uuid7();
            $scan = $this->recorder->record($user, SecurityScan::TARGET_INPUT, $id, $result);

            $analysis = new AiAnalysisRequest;
            $analysis->forceFill([
                'id' => $id,
                'user_id' => $user->id,
                'status' => AiAnalysisRequest::STATUS_QUEUED,
                'input_masked' => $result->maskedText(),
                'input_char_count' => $characters,
                'input_scan_id' => $scan->id,
            ])->save();

            AnalyzeWorkflowJob::dispatch($analysis->id, $analysis->organization_id);

            return $analysis;
        });
    }

    /**
     * The check before sending: the same scan, and a record of it, but the text is not kept in any form.
     * It decides nothing: an analysis is scanned again whatever this said.
     *
     * @throws ServiceUnavailableException
     */
    public function preview(User $user, #[SensitiveParameter] string $input): InputScanResult
    {
        $this->availability->assertAvailable();

        $result = $this->scanner->scanText($input);
        $this->recordOnly($user, $result);

        return $result;
    }

    /**
     * No excerpts: what was scanned is not being kept, so no part of it should be.
     */
    private function recordOnly(User $user, InputScanResult $result): void
    {
        SingleAttemptTransaction::run(DB::connection(), fn () => $this->recorder->record($user, SecurityScan::TARGET_INPUT, null, $result, keepExcerpts: false));
    }
}
