<?php

namespace App\Security\Scanning;

use App\Security\Scanning\Detectors\Detector;
use App\Security\Scanning\Detectors\PiiDetector;
use App\Security\Scanning\Detectors\SecretDetector;
use SensitiveParameter;
use Throwable;

/**
 * Personal information and secrets (docs/security-design.md §3.3, §3.4). It never throws: whatever goes wrong
 * here, the answer is block, because a text that could not be checked must not go any further.
 *
 * Detection reads a normalized copy, and masking changes the original.
 */
final class SensitiveDataScanner
{
    public const RULESET_VERSION = '2026.11.1';

    public const MAX_CHARACTERS = 20000;

    public const DEADLINE_SECONDS = 2.0;

    /**
     * @param  list<Detector>|null  $detectors
     */
    public function __construct(
        private readonly TextNormalizer $normalizer = new TextNormalizer,
        private readonly Masker $masker = new Masker,
        private readonly ?array $detectors = null,
        private readonly float $deadlineSeconds = self::DEADLINE_SECONDS,
    ) {}

    public function scan(#[SensitiveParameter] string $text): ScanResult
    {
        try {
            return $this->run($text);
        } catch (ScanFailure $failure) {
            return self::failed($failure->reason);
        } catch (Throwable) {
            return self::failed('unexpected');
        }
    }

    private function run(string $text): ScanResult
    {
        if (strlen($text) > self::MAX_CHARACTERS && mb_strlen($text, 'UTF-8') > self::MAX_CHARACTERS) {
            throw new ScanFailure(ScanFailure::TOO_LONG);
        }

        $deadline = new ScanDeadline($this->deadlineSeconds);
        $normalized = $this->normalizer->normalize($text);
        $detections = $this->resolved($this->detected($normalized, $deadline));

        if ($detections === []) {
            return new ScanResult(ScanDecision::Allow, ScanResult::MASKING_NOT_REQUIRED, $text, [], $normalized->removedInvisible);
        }

        if (self::any($detections, ScanAction::Block)) {
            return new ScanResult(ScanDecision::Block, ScanResult::MASKING_NOT_REQUIRED, null, $detections, $normalized->removedInvisible);
        }

        $masked = $this->masker->mask($text, $detections);

        // What masking left must be clean. A look for it again costs little, and is the last line.
        if ($this->detected($this->normalizer->normalize($masked), $deadline) !== []) {
            throw new ScanFailure(ScanFailure::STILL_DETECTED);
        }

        $deadline->check();

        return new ScanResult(
            self::any($detections, ScanAction::Warn) ? ScanDecision::Warn : ScanDecision::Allow,
            ScanResult::MASKING_DONE,
            $masked,
            $detections,
            $normalized->removedInvisible,
        );
    }

    /**
     * @return list<Detection>
     */
    private function detected(NormalizedText $text, ScanDeadline $deadline): array
    {
        $found = [];

        foreach ($this->detectors ?? [new SecretDetector, new PiiDetector] as $detector) {
            $deadline->check();
            array_push($found, ...$detector->detect($text));
        }

        return $found;
    }

    /**
     * Where detections overlap, what stops the work wins, and then the longest.
     *
     * @param  list<Detection>  $detections
     * @return list<Detection>
     */
    private function resolved(array $detections): array
    {
        usort($detections, fn (Detection $a, Detection $b) => [$b->rule->action()->rank(), $b->length(), $a->start] <=> [$a->rule->action()->rank(), $a->length(), $b->start]);

        $kept = [];

        foreach ($detections as $detection) {
            foreach ($kept as $other) {
                if ($detection->overlaps($other)) {
                    continue 2;
                }
            }

            $kept[] = $detection;
        }

        usort($kept, fn (Detection $a, Detection $b) => $a->start <=> $b->start);

        return $kept;
    }

    /**
     * @param  list<Detection>  $detections
     */
    private static function any(array $detections, ScanAction $action): bool
    {
        foreach ($detections as $detection) {
            if ($detection->rule->action() === $action) {
                return true;
            }
        }

        return false;
    }

    private static function failed(string $reason): ScanResult
    {
        return new ScanResult(ScanDecision::Block, ScanResult::MASKING_FAILED, null, [new Detection(Rule::MaskFailed, 0, 0)], 0, $reason);
    }
}
