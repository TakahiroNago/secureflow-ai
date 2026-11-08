<?php

namespace App\SelfTest;

/**
 * One case of docs/test-strategy.md §5 with a "self-test" mark. It is run against the service layer, the policies
 * and the detectors directly: no HTTP to itself, no real AI (docs/test-strategy.md §6).
 */
interface SelfTestCase
{
    /** ST-xx */
    public function id(): string;

    /** input, output, authorization, workflow or audit. */
    public function category(): string;

    public function name(): string;

    /** The fixed sentence that says what is expected. */
    public function expected(): string;

    /**
     * True when the case writes rows and must run inside a transaction that is rolled back. False for a case that
     * only reads, and has to see committed rows (the audit chain).
     */
    public function isolated(): bool;

    public function run(SelfTestContext $context): CaseOutcome;
}
