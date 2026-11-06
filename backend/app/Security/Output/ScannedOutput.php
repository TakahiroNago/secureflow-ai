<?php

namespace App\Security\Output;

use App\Security\Scanning\InputScanResult;

/**
 * What the AI wrote, once checked. The tasks hold the text to keep, and there are none after a stop.
 */
final readonly class ScannedOutput
{
    /**
     * @param  list<ValidatedTask>  $tasks
     */
    public function __construct(
        public array $tasks,
        public InputScanResult $result,
    ) {}
}
