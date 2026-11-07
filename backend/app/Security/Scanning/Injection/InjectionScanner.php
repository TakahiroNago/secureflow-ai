<?php

namespace App\Security\Scanning\Injection;

use App\Security\Scanning\Detectors\Pattern;
use App\Security\Scanning\NormalizedText;
use App\Security\Scanning\ScanAction;
use App\Security\Scanning\ScanDeadline;
use App\Security\Scanning\ScanFailure;
use App\Security\Scanning\Severity;
use App\Security\Scanning\TextNormalizer;
use SensitiveParameter;
use Throwable;

/**
 * Prompt injection (docs/security-design.md §3.5). It never throws: what could not be checked is a block.
 *
 * Rules can always be worded around. The last line of defence is that the AI can do nothing by itself, and
 * this is a layer in front of that.
 */
final class InjectionScanner
{
    public const MAX_CHARACTERS = 20000;

    public const DEADLINE_SECONDS = 2.0;

    public const MAX_ENCODED_BLOCKS = 20;

    /** The rule for many invisible characters with nothing else found: worth a record, and not more. */
    public const INVISIBLE_RULE = 'IJ-OBF-001';

    private const INVISIBLE_THRESHOLD = 5;

    /**
     * Asking for a forbidden action is an ordinary request here, and the output check decides on it. The
     * wide rules (IJ-HEU) are loose on purpose, so they warn and never add up to a stop.
     */
    private const NOT_COUNTED_AS_A_CATEGORY = ['IJ-ACT', 'IJ-OBF', 'IJ-HEU'];

    private const NEVER_RAISED_BY_A_DISGUISE = ['IJ-OBF', 'IJ-HEU'];

    /** Digits used as letters. One for one, so that offsets stay the same. */
    private const LEET = ['0' => 'o', '1' => 'i', '3' => 'e', '4' => 'a', '5' => 's', '7' => 't', '@' => 'a'];

    private const MIXED_WORD = '/(?<![a-z0-9@])(?=[a-z0-9@]*[a-z])(?=[a-z0-9@]*[0-9@])[a-z0-9@]{3,}+/i';

    private const SPACED_LETTERS = '/(?<![\p{L}\p{N}])[\p{L}\p{N}](?: [\p{L}\p{N}]){3,}+(?![\p{L}\p{N}])/u';

    private const BASE64_BLOCK = '~(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}+={0,2}~';

    private ?InjectionRuleSet $rules = null;

    public function __construct(
        private readonly TextNormalizer $normalizer = new TextNormalizer,
        private readonly ?string $rulesPath = null,
        private readonly float $deadlineSeconds = self::DEADLINE_SECONDS,
    ) {}

    /**
     * @param  float|null  $deadlineSeconds  What is left of a longer scan, when this is part of one.
     */
    public function scan(#[SensitiveParameter] string $text, ?float $deadlineSeconds = null): InjectionResult
    {
        try {
            return $this->run($text, $deadlineSeconds ?? $this->deadlineSeconds);
        } catch (ScanFailure $failure) {
            return self::failed($failure->reason);
        } catch (Throwable) {
            return self::failed('unexpected');
        }
    }

    /** Null when the rules cannot be read. */
    public function rulesetVersion(): ?string
    {
        try {
            $this->rules ??= InjectionRuleSet::load($this->rulesPath);
        } catch (Throwable) {
            return null;
        }

        return $this->rules->version;
    }

    private function run(string $text, float $deadlineSeconds): InjectionResult
    {
        if (strlen($text) > self::MAX_CHARACTERS && mb_strlen($text, 'UTF-8') > self::MAX_CHARACTERS) {
            throw new ScanFailure(ScanFailure::TOO_LONG);
        }

        $this->rules ??= InjectionRuleSet::load($this->rulesPath);
        $deadline = new ScanDeadline($deadlineSeconds);
        $normalized = $this->normalizer->normalize($text);

        $hits = [
            ...$this->direct($normalized, $deadline),
            ...$this->spacedOut($normalized, $deadline),
            ...$this->encoded($normalized, $deadline),
            ...$this->digitsAsLetters($normalized, $deadline),
        ];

        if ($normalized->removedInvisible >= self::INVISIBLE_THRESHOLD) {
            $hits[] = new InjectionHit(self::INVISIBLE_RULE, 'IJ-OBF', Severity::Low, 0, 0, true);
        }

        usort($hits, fn (InjectionHit $a, InjectionHit $b) => [$a->start, $a->ruleId] <=> [$b->start, $b->ruleId]);

        return self::scored($hits);
    }

    /**
     * @return list<InjectionHit>
     */
    private function direct(NormalizedText $text, ScanDeadline $deadline): array
    {
        $hits = [];

        foreach ($this->ruleList() as $rule) {
            $deadline->check();

            foreach (Pattern::matches($rule->pattern, $text->text) as [$match, $offset]) {
                $end = $offset + strlen($match);
                [$start, $stop] = $text->sourceSpan($offset, $end);
                $hits[] = new InjectionHit($rule->id, $rule->category, $rule->severity, $start, $stop, $text->isDisguised($offset, $end));
            }
        }

        return $hits;
    }

    /**
     * "i g n o r e" closes up to "ignore", and whatever is found in it is disguised.
     *
     * @return list<InjectionHit>
     */
    private function spacedOut(NormalizedText $text, ScanDeadline $deadline): array
    {
        $hits = [];

        foreach (Pattern::matches(self::SPACED_LETTERS, $text->text) as [$run, $offset]) {
            [$start, $stop] = $text->sourceSpan($offset, $offset + strlen($run));
            array_push($hits, ...$this->inside(str_replace(' ', '', $run), $start, $stop, $deadline));
        }

        return $hits;
    }

    /**
     * "1gn0re" reads as "ignore". Only words that mix letters and digits change, so "2026" stays a number.
     * A match counts only where it covers a changed word: a part number elsewhere in the text does not make
     * the rest of the text a disguise.
     *
     * @return list<InjectionHit>
     */
    private function digitsAsLetters(NormalizedText $text, ScanDeadline $deadline): array
    {
        $changed = preg_replace_callback(self::MIXED_WORD, fn (array $word) => strtr($word[0], self::LEET), $text->text);

        if (! is_string($changed)) {
            throw new ScanFailure(ScanFailure::PATTERN_ERROR);
        }

        if ($changed === $text->text) {
            return [];
        }

        $words = array_filter(Pattern::matches(self::MIXED_WORD, $text->text), fn (array $word) => strtr($word[0], self::LEET) !== $word[0]);
        $hits = [];

        foreach ($this->ruleList() as $rule) {
            $deadline->check();

            foreach (Pattern::matches($rule->pattern, $changed) as [$match, $offset]) {
                $end = $offset + strlen($match);

                foreach ($words as [$word, $wordOffset]) {
                    if ($offset < $wordOffset + strlen($word) && $wordOffset < $end) {
                        [$start, $stop] = $text->sourceSpan($offset, $end);
                        $hits[] = new InjectionHit($rule->id, $rule->category, $rule->severity, $start, $stop, true);

                        break;
                    }
                }
            }
        }

        return $hits;
    }

    /**
     * Base64, one level down. Too many blocks cannot all be checked, and that is a failure.
     *
     * @return list<InjectionHit>
     */
    private function encoded(NormalizedText $text, ScanDeadline $deadline): array
    {
        $hits = [];
        $blocks = 0;

        foreach (Pattern::matches(self::BASE64_BLOCK, $text->text) as [$block, $offset]) {
            $decoded = base64_decode($block, true);

            if (! is_string($decoded) || ! mb_check_encoding($decoded, 'UTF-8') || preg_match('/[^\P{Cc}\n\t\r]/u', $decoded) === 1) {
                continue;
            }

            if (++$blocks > self::MAX_ENCODED_BLOCKS) {
                throw new ScanFailure(ScanFailure::TOO_MANY_ENCODED);
            }

            [$start, $stop] = $text->sourceSpan($offset, $offset + strlen($block));
            array_push($hits, ...$this->inside($this->normalizer->normalize($decoded)->text, $start, $stop, $deadline));
        }

        return $hits;
    }

    /**
     * @return list<InjectionHit>
     */
    private function inside(string $text, int $start, int $stop, ScanDeadline $deadline): array
    {
        $hits = [];

        foreach ($this->ruleList() as $rule) {
            $deadline->check();

            if (Pattern::matches($rule->pattern, $text) !== []) {
                $hits[] = new InjectionHit($rule->id, $rule->category, $rule->severity, $start, $stop, true);
            }
        }

        return $hits;
    }

    /**
     * @return list<InjectionRule>
     */
    private function ruleList(): array
    {
        return $this->rules === null ? [] : $this->rules->rules;
    }

    /**
     * The scoring of docs/security-design.md §3.5: the highest rule, one more for several categories, Critical
     * for overriding and extracting together, and one more for a disguise.
     *
     * @param  list<InjectionHit>  $hits
     */
    private static function scored(array $hits): InjectionResult
    {
        if ($hits === []) {
            return new InjectionResult(null, null, []);
        }

        $severity = Severity::Low;
        $categories = [];
        $disguised = false;

        foreach ($hits as $hit) {
            $severity = $hit->severity->rank() > $severity->rank() ? $hit->severity : $severity;
            $disguised = $disguised || ($hit->disguised && ! in_array($hit->category, self::NEVER_RAISED_BY_A_DISGUISE, true));

            if (! in_array($hit->category, self::NOT_COUNTED_AS_A_CATEGORY, true)) {
                $categories[$hit->category] = true;
            }
        }

        if (count($categories) >= 2) {
            $severity = $severity->raised();
        }
        if (isset($categories['IJ-OVR'], $categories['IJ-EXF'])) {
            $severity = Severity::Critical;
        }
        if ($disguised) {
            $severity = $severity->raised();
        }

        return new InjectionResult($severity, self::actionFor($severity), $hits);
    }

    /**
     * Only for injection rules. The rules for personal data and secrets define their own action (§3.5).
     */
    public static function actionFor(Severity $severity): ScanAction
    {
        return match ($severity) {
            Severity::Critical, Severity::High => ScanAction::Block,
            Severity::Medium => ScanAction::Warn,
            Severity::Low => ScanAction::Record,
        };
    }

    private static function failed(string $reason): InjectionResult
    {
        return new InjectionResult(Severity::High, ScanAction::Block, [], $reason);
    }
}
