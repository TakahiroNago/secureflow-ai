<?php

namespace App\Security\Scanning\Injection;

use App\Security\Scanning\ScanFailure;
use App\Security\Scanning\Severity;
use JsonException;

/**
 * resources/security/injection-rules.json (docs/security-design.md §3.5). A rule that cannot be used is not
 * skipped: a text checked with half of the rules would look as if it had been checked.
 */
final readonly class InjectionRuleSet
{
    public const CATEGORIES = ['IJ-OVR', 'IJ-EXF', 'IJ-IMP', 'IJ-IND', 'IJ-JBR', 'IJ-ACT', 'IJ-HEU'];

    /**
     * @param  list<InjectionRule>  $rules
     */
    private function __construct(
        public string $version,
        public array $rules,
    ) {}

    public static function defaultPath(): string
    {
        return dirname(__DIR__, 4).'/resources/security/injection-rules.json';
    }

    /**
     * @throws ScanFailure
     */
    public static function load(?string $path = null): self
    {
        $raw = @file_get_contents($path ?? self::defaultPath());

        if ($raw === false) {
            throw new ScanFailure(ScanFailure::RULES_INVALID);
        }

        try {
            $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new ScanFailure(ScanFailure::RULES_INVALID);
        }

        if (! is_array($data) || ! is_string($data['version'] ?? null) || ! is_array($data['rules'] ?? null) || $data['rules'] === []) {
            throw new ScanFailure(ScanFailure::RULES_INVALID);
        }

        return new self($data['version'], array_values(array_map(self::rule(...), $data['rules'])));
    }

    private static function rule(mixed $entry): InjectionRule
    {
        if (! is_array($entry) || ! is_string($entry['id'] ?? null) || ! is_string($entry['pattern'] ?? null)
            || ! in_array($entry['category'] ?? null, self::CATEGORIES, true) || str_contains($entry['pattern'], '~')) {
            throw new ScanFailure(ScanFailure::RULES_INVALID);
        }

        $severity = is_string($entry['severity'] ?? null) ? Severity::tryFrom($entry['severity']) : null;
        $flags = ($entry['case_sensitive'] ?? false) === true ? 'mu' : 'imu';
        $pattern = '~'.$entry['pattern'].'~'.$flags;

        // A pattern that does not compile, or that matches nothing at all, would find nothing or everything.
        if ($severity === null || @preg_match($pattern, '') !== 0) {
            throw new ScanFailure(ScanFailure::RULES_INVALID);
        }

        return new InjectionRule($entry['id'], $entry['category'], $severity, $pattern);
    }
}
