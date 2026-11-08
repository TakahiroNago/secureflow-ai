<?php

namespace App\SelfTest;

/**
 * What a case concluded: a short fixed sentence for the screen, and details with fixed keys and codes. Nothing in it
 * comes from a user or the AI, so it can be stored and shown as it is.
 */
final readonly class CaseOutcome
{
    /**
     * @param  array<string, string|int|bool|null|list<string>>  $details
     */
    private function __construct(
        public bool $passed,
        public string $actual,
        public array $details,
    ) {}

    /**
     * @param  array<string, string|int|bool|null|list<string>>  $details
     */
    public static function of(bool $passed, string $actual, array $details = []): self
    {
        return new self($passed, mb_substr($actual, 0, 200), $details);
    }

    /**
     * Every check must hold. The first that does not is named in the details.
     *
     * @param  array<string, bool>  $checks  A name for each check, and whether it held.
     * @param  array<string, string|int|bool|null|list<string>>  $details
     */
    public static function all(array $checks, string $whenPassed, array $details = []): self
    {
        $failed = array_keys(array_filter($checks, fn (bool $held) => ! $held));

        if ($failed === []) {
            return self::of(true, $whenPassed, $details);
        }

        return self::of(false, 'failed: '.implode(', ', $failed), [...$details, 'failed_checks' => $failed]);
    }
}
