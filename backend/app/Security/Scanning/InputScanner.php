<?php

namespace App\Security\Scanning;

use App\Security\Scanning\Injection\InjectionHit;
use App\Security\Scanning\Injection\InjectionResult;
use App\Security\Scanning\Injection\InjectionScanner;
use SensitiveParameter;

/**
 * docs/architecture.md §7, step 2. Secrets and personal data first, then injection on what masking left, and on
 * the text as typed. What stops at a secret goes no further. It never throws: what could not be checked is a block.
 *
 * Each field of a plan is scanned by itself, because a plan is longer than one scan may be. So a secret or an
 * attack split across fields is not found (docs/security-design.md §3.5).
 *
 * No finding here means nothing was recognized, and never that the text is safe.
 */
final readonly class InputScanner
{
    /** The key of a text that is not a field of anything. */
    public const SINGLE_TEXT = '';

    /** For a whole plan, on top of the limit of each scan. Not based on a measurement: see test-strategy.md §23. */
    public const DEADLINE_SECONDS = 5.0;

    /** Attacks can be repeated at will, and one request must not add thousands of rows. */
    public const MAX_FINDINGS = 100;

    private const EXCERPT_CHARACTERS = 80;

    private const EXCERPT_BEFORE = 20;

    public function __construct(
        private SensitiveDataScanner $sensitive = new SensitiveDataScanner,
        private InjectionScanner $injection = new InjectionScanner,
        private float $deadlineSeconds = self::DEADLINE_SECONDS,
    ) {}

    public function scanText(#[SensitiveParameter] string $text): InputScanResult
    {
        return $this->scanFields([self::SINGLE_TEXT => $text]);
    }

    /**
     * @param  array<string, string>  $fields  Field name => text.
     * @param  list<InputFinding>  $alreadyFound  From checks of the caller, which count like any other.
     */
    public function scanFields(#[SensitiveParameter] array $fields, array $alreadyFound = []): InputScanResult
    {
        $started = hrtime(true);
        $elapsed = fn (): float => (hrtime(true) - $started) / 1e9;

        $masked = [];
        $findings = $alreadyFound;
        $severity = null;

        foreach ($alreadyFound as $finding) {
            $severity = Severity::higher($severity, $finding->severity);
        }

        $anyMasked = false;
        $failureReason = null;

        foreach ($fields as $name => $text) {
            $field = $name === self::SINGLE_TEXT ? null : (string) $name;

            $scan = $this->sensitive->scan($text, $this->remaining($elapsed()));
            $severity = Severity::higher($severity, $scan->maxSeverity());
            array_push($findings, ...$this->sensitiveFindings($scan, $field));

            if ($scan->decision === ScanDecision::Block) {
                $failureReason ??= $scan->failureReason;

                continue;
            }

            $maskedText = (string) $scan->maskedText;
            $anyMasked = $anyMasked || $scan->maskingStatus === ScanResult::MASKING_DONE;

            $injection = $this->injection->scan($maskedText, $this->remaining($elapsed()));

            // Masking can hide an attack from this scan: a long Base64 block looks like a secret and is replaced.
            // So what was masked is read as typed too. Only a stop counts: the text kept is the masked one.
            if (! $injection->blocks() && $maskedText !== $text) {
                $asTyped = $this->injection->scan($text, $this->remaining($elapsed()));
                $injection = $asTyped->blocks() ? $asTyped : $injection;
            }

            $severity = Severity::higher($severity, $injection->severity);
            array_push($findings, ...$this->injectionFindings($injection, $maskedText, $field));
            $failureReason ??= $injection->failureReason;

            $masked[(string) $name] = $maskedText;
        }

        return $this->result($findings, $severity, $anyMasked, $masked, (int) round($elapsed() * 1000), $failureReason);
    }

    private function remaining(float $elapsed): float
    {
        return max(0.0, min(SensitiveDataScanner::DEADLINE_SECONDS, $this->deadlineSeconds - $elapsed));
    }

    /**
     * @param  list<InputFinding>  $findings
     * @param  array<string, string>  $masked
     */
    private function result(array $findings, ?Severity $severity, bool $anyMasked, array $masked, int $durationMs, ?string $failureReason): InputScanResult
    {
        $findings = self::distinct($findings);
        $decision = self::decisionOf($findings);
        $failed = self::hasRule($findings, Rule::MaskFailed->value);

        if ($decision === ScanDecision::Block) {
            $findings = array_map(fn (InputFinding $finding) => $finding->withoutExcerpt(), $findings);
        }

        usort($findings, fn (InputFinding $a, InputFinding $b) => $b->action->rank() <=> $a->action->rank());

        return new InputScanResult(
            $decision,
            $severity,
            $failed ? ScanResult::MASKING_FAILED : ($anyMasked && $decision !== ScanDecision::Block ? ScanResult::MASKING_DONE : ScanResult::MASKING_NOT_REQUIRED),
            $decision === ScanDecision::Block ? self::blockReason($findings, $failed) : null,
            $decision === ScanDecision::Block ? null : $masked,
            array_slice($findings, 0, self::MAX_FINDINGS),
            count($findings),
            $durationMs,
            $this->rulesetVersion(),
            $failureReason,
        );
    }

    /**
     * The rules in force, as every scan records them: the sensitive-data rules and the injection rules.
     */
    public function rulesetVersion(): string
    {
        return SensitiveDataScanner::RULESET_VERSION.'/'.($this->injection->rulesetVersion() ?? 'unavailable');
    }

    /**
     * Positions in the masked text, because that is what is kept. When the scan stopped there is none, and
     * the screen points into the text the user still has.
     *
     * @return list<InputFinding>
     */
    private function sensitiveFindings(ScanResult $scan, ?string $field): array
    {
        $findings = [];
        $shift = 0;

        foreach ($scan->detections as $detection) {
            $rule = $detection->rule;

            if ($rule === Rule::MaskFailed) {
                $findings[] = self::maskFailed($field);

                continue;
            }

            $start = $detection->start;
            $end = $detection->end;
            $excerpt = null;

            if ($scan->maskedText !== null) {
                $start += $shift;
                $end = $start + mb_strlen($rule->replacement(), 'UTF-8');
                $shift += $end - $start - $detection->length();
                $excerpt = $rule->category() === 'pii' ? self::excerpt($scan->maskedText, $start) : null;
            }

            $findings[] = new InputFinding($rule->category(), $rule->value, $rule->severity(), $rule->action(), $rule->message(), $start, $end, $field, $excerpt);
        }

        return $findings;
    }

    /**
     * The verdict belongs to the text as a whole: two medium matches can add up to a stop. So every match
     * carries it, and the decision can be read from the findings.
     *
     * @return list<InputFinding>
     */
    private function injectionFindings(InjectionResult $result, string $maskedText, ?string $field): array
    {
        if ($result->failureReason !== null) {
            return [self::maskFailed($field)];
        }

        if ($result->severity === null || $result->action === null) {
            return [];
        }

        $severity = $result->severity;
        $action = $result->action;

        return array_map(function (InjectionHit $hit) use ($severity, $action, $maskedText, $field): InputFinding {
            $placed = $hit->end > $hit->start;

            return new InputFinding(
                'injection',
                $hit->ruleId,
                $severity,
                $action,
                self::injectionMessage($action),
                $placed ? $hit->start : null,
                $placed ? $hit->end : null,
                $field,
                $placed ? self::excerpt($maskedText, $hit->start) : null,
            );
        }, $result->hits);
    }

    private static function injectionMessage(ScanAction $action): string
    {
        return match ($action) {
            ScanAction::Block => '指示の上書きなどの攻撃と思われる表現を検出したため処理を停止しました',
            ScanAction::Warn => '攻撃の可能性がある表現を検出しました。内容を確認してください',
            default => '注意が必要な表現を検出し記録しました',
        };
    }

    private static function maskFailed(?string $field): InputFinding
    {
        $rule = Rule::MaskFailed;

        return new InputFinding($rule->category(), $rule->value, $rule->severity(), $rule->action(), $rule->message(), null, null, $field, null);
    }

    private static function excerpt(string $maskedText, int $position): string
    {
        return mb_substr($maskedText, max(0, $position - self::EXCERPT_BEFORE), self::EXCERPT_CHARACTERS, 'UTF-8');
    }

    /**
     * The same rule at the same place can be found twice, as written and with digits read as letters.
     *
     * @param  list<InputFinding>  $findings
     * @return list<InputFinding>
     */
    private static function distinct(array $findings): array
    {
        $seen = [];

        foreach ($findings as $finding) {
            $seen[implode('|', [$finding->field, $finding->ruleId, $finding->start, $finding->end])] ??= $finding;
        }

        return array_values($seen);
    }

    /**
     * docs/security-design.md §3.2: from the actions, never from a severity.
     *
     * @param  list<InputFinding>  $findings
     */
    private static function decisionOf(array $findings): ScanDecision
    {
        $actions = array_map(fn (InputFinding $finding) => $finding->action, $findings);

        return match (true) {
            in_array(ScanAction::Block, $actions, true) => ScanDecision::Block,
            in_array(ScanAction::Warn, $actions, true) => ScanDecision::Warn,
            default => ScanDecision::Allow,
        };
    }

    /**
     * @param  list<InputFinding>  $findings
     */
    private static function hasRule(array $findings, string $ruleId): bool
    {
        foreach ($findings as $finding) {
            if ($finding->ruleId === $ruleId) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<InputFinding>  $findings
     */
    private static function blockReason(array $findings, bool $failed): string
    {
        foreach ($findings as $finding) {
            if ($finding->category === 'canary') {
                return InputScanResult::REASON_CANARY;
            }
        }

        if ($failed) {
            return InputScanResult::REASON_MASK_FAILED;
        }

        foreach ($findings as $finding) {
            if ($finding->category === 'secret' && $finding->action === ScanAction::Block) {
                return InputScanResult::REASON_SECRET;
            }
        }

        return InputScanResult::REASON_INJECTION;
    }
}
