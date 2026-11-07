<?php

namespace App\Jobs;

use App\Domain\Execution\ExecutionProcessor;
use App\Support\Organization\OrganizationContext;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Throwable;

/**
 * Carries ids only. Running it twice is safe: ExecutionProcessor claims the row with a conditional update, which is
 * what stops a second run, so ShouldBeUnique is not used (docs/architecture.md §10). Never retried: the approval has
 * been used once.
 */
final class ExecuteWorkflowJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable;

    public const QUEUE = 'execution';

    public int $tries = 1;

    public int $timeout = 60;

    public bool $failOnTimeout = true;

    public function __construct(
        public readonly string $executionId,
        public readonly string $organizationId,
    ) {
        $this->onQueue(self::QUEUE);
    }

    public function handle(ExecutionProcessor $processor, OrganizationContext $context): void
    {
        $context->run($this->organizationId, fn () => $processor->process($this->executionId));
    }

    /**
     * Whatever went wrong, the row must not stay unfinished. If this fails too, the recovery command acts.
     */
    public function failed(?Throwable $exception): void
    {
        app(OrganizationContext::class)->run(
            $this->organizationId,
            fn () => app(ExecutionProcessor::class)->fail($this->executionId, ExecutionProcessor::ERROR_FAILED),
        );
    }
}
