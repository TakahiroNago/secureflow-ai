<?php

namespace App\Jobs;

use App\SelfTest\SelfTestRuns;
use App\Support\Organization\OrganizationContext;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Throwable;

/**
 * Carries ids only (docs/architecture.md §10). Running it twice is safe: SelfTestRuns claims the row with a
 * conditional update before doing anything. One run at a time per organization is decided when the run is started.
 */
final class RunSecuritySelfTestJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable;

    public const QUEUE = 'selftest';

    public int $tries = 1;

    public int $timeout = 120;

    public bool $failOnTimeout = true;

    public function __construct(
        public readonly string $runId,
        public readonly string $organizationId,
    ) {
        $this->onQueue(self::QUEUE);
    }

    public function handle(SelfTestRuns $runs, OrganizationContext $context): void
    {
        $context->run($this->organizationId, fn () => $runs->process($this->runId));
    }

    /**
     * Whatever went wrong, the row must not stay unfinished. If this fails too, the recovery command acts.
     */
    public function failed(?Throwable $exception): void
    {
        app(OrganizationContext::class)->run(
            $this->organizationId,
            fn () => app(SelfTestRuns::class)->fail($this->runId, SelfTestRuns::ERROR_FAILED),
        );
    }
}
