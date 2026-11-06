<?php

namespace App\Jobs;

use App\Domain\Workflow\AnalysisProcessor;
use App\Support\Organization\OrganizationContext;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Throwable;

/**
 * Carries ids only (docs/architecture.md §10). Running it twice is safe: AnalysisProcessor claims the
 * row with a conditional update before doing anything.
 *
 * The time limit must stay above AiGateway::worstCaseSeconds(), and the queue's retry_after above this.
 */
final class AnalyzeWorkflowJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable;

    public const QUEUE = 'ai';

    public int $tries = 1;

    public int $timeout = 120;

    public bool $failOnTimeout = true;

    public function __construct(
        public readonly string $analysisId,
        public readonly string $organizationId,
    ) {
        $this->onQueue(self::QUEUE);
    }

    public function handle(AnalysisProcessor $processor, OrganizationContext $context): void
    {
        $context->run($this->organizationId, fn () => $processor->process($this->analysisId));
    }

    /**
     * Whatever went wrong, the row must not stay unfinished. If this fails too, the recovery command acts.
     */
    public function failed(?Throwable $exception): void
    {
        app(OrganizationContext::class)->run(
            $this->organizationId,
            fn () => app(AnalysisProcessor::class)->fail($this->analysisId, AnalysisProcessor::ERROR_FAILED),
        );
    }
}
