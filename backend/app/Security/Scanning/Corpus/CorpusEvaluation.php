<?php

namespace App\Security\Scanning\Corpus;

use App\Security\Scanning\Detection;
use App\Security\Scanning\Injection\InjectionHit;
use App\Security\Scanning\Injection\InjectionResult;
use App\Security\Scanning\Injection\InjectionScanner;
use App\Security\Scanning\ScanDecision;
use App\Security\Scanning\SensitiveDataScanner;
use JsonException;

/**
 * docs/test-strategy.md §7. The detectors measured against the corpus in resources/security/corpus. The targets
 * are on this corpus and say nothing about text that is not in it. The tests (§21, §22) assert the gates; the
 * report (`security:corpus-report`) prints every figure, with the tuning and the hold-out rates always side by side,
 * because the tuning rate alone says only that the rules fit the sentences they were written for.
 */
final class CorpusEvaluation
{
    public const TARGET_INJECTION_FOUND = 0.9;

    public const TARGET_STOPPED_MAX = 0.01;

    public const TARGET_FLAGGED_MAX = 0.05;

    private string $directory;

    public function __construct(?string $directory = null)
    {
        $this->directory = $directory ?? resource_path('security/corpus');
    }

    /**
     * @return list<mixed>
     *
     * @throws JsonException
     */
    public function load(string $name): array
    {
        $decoded = json_decode((string) file_get_contents($this->directory.'/'.$name.'.json'), true, flags: JSON_THROW_ON_ERROR);

        return is_array($decoded) ? array_values($decoded) : [];
    }

    /**
     * {{BASE64:text}} in an attack is encoded when it is measured, so the corpus stays readable.
     */
    public static function expandAttack(string $attack): string
    {
        return (string) preg_replace_callback('/\{\{BASE64:(.*?)\}\}/u', fn (array $m) => base64_encode($m[1]), $attack);
    }

    public static function foundAtMediumOrMore(InjectionResult $result): bool
    {
        return $result->severity !== null && $result->severity->rank() >= 2;
    }

    /**
     * How many attacks of a corpus are found at Medium or more.
     *
     * @return array{found: int, total: int, rate: float, missed: list<string>}
     */
    public function injection(string $name): array
    {
        $scanner = new InjectionScanner;
        $attacks = array_map('strval', $this->load($name));
        $missed = array_values(array_filter($attacks, fn (string $attack) => ! self::foundAtMediumOrMore($scanner->scan(self::expandAttack($attack)))));
        $total = count($attacks);

        return ['found' => $total - count($missed), 'total' => $total, 'rate' => $total === 0 ? 0.0 : ($total - count($missed)) / $total, 'missed' => $missed];
    }

    /**
     * What the injection rules do to ordinary business text.
     *
     * @return array{total: int, stopped: list<string>, flagged: list<string>, stopped_rate: float, flagged_rate: float}
     */
    public function injectionBusiness(): array
    {
        $scanner = new InjectionScanner;
        $stopped = $flagged = [];
        $sentences = array_map('strval', $this->load('business'));

        foreach ($sentences as $sentence) {
            $result = $scanner->scan($sentence);
            $rules = implode(',', array_map(fn (InjectionHit $hit) => $hit->ruleId, $result->hits));

            if ($result->blocks()) {
                $stopped[] = $sentence.' -> '.$rules;
            }
            if (self::foundAtMediumOrMore($result)) {
                $flagged[] = $sentence.' -> '.$rules;
            }
        }

        return self::businessRates($sentences, $stopped, $flagged);
    }

    /**
     * Every sample of the sensitive corpus is found by every rule it names, and every secret stops the work.
     * The templates are expanded with the fixed seed.
     *
     * @return array{samples: int, missed: list<string>, blocked: int, blockable: int}
     */
    public function sensitive(): array
    {
        mt_srand(SecretTemplates::SEED);
        $missed = [];
        $blocked = $blockable = 0;
        $samples = $this->load('sensitive');

        foreach ($samples as $sample) {
            if (! is_array($sample) || ! is_string($sample['template'] ?? null) || ! is_array($sample['rules'] ?? null)) {
                continue;
            }

            $result = (new SensitiveDataScanner)->scan(SecretTemplates::expand($sample['template']));
            $found = array_map(fn (Detection $detection) => $detection->rule->value, $result->detections);

            foreach ($sample['rules'] as $rule) {
                if (! in_array($rule, $found, true)) {
                    $missed[] = $sample['template'].' -> '.$rule;
                }
            }

            $first = (string) ($sample['rules'][0] ?? '');
            if (str_starts_with($first, 'SEC-') && $first !== 'SEC-ENTROPY') {
                $blockable++;
                $blocked += $result->decision === ScanDecision::Block ? 1 : 0;
            }
        }

        return ['samples' => count($samples), 'missed' => $missed, 'blocked' => $blocked, 'blockable' => $blockable];
    }

    /**
     * What the sensitive-data rules do to ordinary business text.
     *
     * @return array{total: int, stopped: list<string>, flagged: list<string>, stopped_rate: float, flagged_rate: float}
     */
    public function sensitiveBusiness(): array
    {
        $stopped = $flagged = [];
        $sentences = array_map('strval', $this->load('business'));

        foreach ($sentences as $sentence) {
            $result = (new SensitiveDataScanner)->scan($sentence);

            if ($result->decision === ScanDecision::Block) {
                $stopped[] = $sentence;
            }
            if ($result->detections !== []) {
                $flagged[] = $sentence.' -> '.implode(',', array_map(fn (Detection $detection) => $detection->rule->value, $result->detections));
            }
        }

        return self::businessRates($sentences, $stopped, $flagged);
    }

    /**
     * Everything, with the targets and whether each gate is met. The hold-out has no gate: it is reported.
     *
     * @return array<string, mixed>
     */
    public function report(): array
    {
        $tuning = $this->injection('injection-tuning');
        $holdout = $this->injection('injection-holdout');
        $injectionBusiness = $this->injectionBusiness();
        $sensitive = $this->sensitive();
        $sensitiveBusiness = $this->sensitiveBusiness();

        return [
            'ruleset_version' => SensitiveDataScanner::RULESET_VERSION.'/'.((new InjectionScanner)->rulesetVersion() ?? 'unavailable'),
            'injection' => [
                'tuning' => [...$tuning, 'target' => self::TARGET_INJECTION_FOUND, 'gate' => true, 'passed' => $tuning['rate'] >= self::TARGET_INJECTION_FOUND],
                'holdout' => [...$holdout, 'target' => self::TARGET_INJECTION_FOUND, 'gate' => false, 'passed' => $holdout['rate'] >= self::TARGET_INJECTION_FOUND],
                'business' => [...$injectionBusiness, 'stopped_max' => self::TARGET_STOPPED_MAX, 'flagged_max' => self::TARGET_FLAGGED_MAX, 'gate' => true,
                    'passed' => $injectionBusiness['stopped_rate'] <= self::TARGET_STOPPED_MAX && $injectionBusiness['flagged_rate'] <= self::TARGET_FLAGGED_MAX],
            ],
            'sensitive' => [
                'samples' => [...$sensitive, 'gate' => true, 'passed' => $sensitive['missed'] === [] && $sensitive['blocked'] === $sensitive['blockable']],
                'business' => [...$sensitiveBusiness, 'stopped_max' => self::TARGET_STOPPED_MAX, 'flagged_max' => self::TARGET_FLAGGED_MAX, 'gate' => true,
                    'passed' => $sensitiveBusiness['stopped_rate'] <= self::TARGET_STOPPED_MAX && $sensitiveBusiness['flagged_rate'] <= self::TARGET_FLAGGED_MAX],
            ],
        ];
    }

    /**
     * @param  list<string>  $sentences
     * @param  list<string>  $stopped
     * @param  list<string>  $flagged
     * @return array{total: int, stopped: list<string>, flagged: list<string>, stopped_rate: float, flagged_rate: float}
     */
    private static function businessRates(array $sentences, array $stopped, array $flagged): array
    {
        $total = count($sentences);

        return [
            'total' => $total,
            'stopped' => $stopped,
            'flagged' => $flagged,
            'stopped_rate' => $total === 0 ? 0.0 : count($stopped) / $total,
            'flagged_rate' => $total === 0 ? 0.0 : count($flagged) / $total,
        ];
    }
}
