<?php

namespace App\Security\Scanning\Detectors;

use App\Security\Scanning\Detection;
use App\Security\Scanning\NormalizedText;
use App\Security\Scanning\Rule;

/**
 * docs/security-design.md §3.3. Masking a number that was not a phone number does no harm, so these lean
 * towards matching. Only formats are detected: names and addresses are not (§4).
 */
final class PiiDetector implements Detector
{
    private const EMAIL = '/(?<![a-z0-9._%+-])[a-z0-9._%+-]{1,64}+@(?:[a-z0-9-]{1,63}+\.)++[a-z]{2,24}+(?![a-z0-9-])/iu';

    private const PHONE = '/(?<![0-9+])(?:\+81[- .]?\(?0?\)?|0)[1-9](?:[- .()]?[0-9]){7,10}(?![0-9])/u';

    /** Groups of digits with one separator between them. Cards and My Number are looked for inside these. */
    private const DIGIT_RUN = '/(?<![0-9])[0-9]++(?:[ -][0-9]++)*+/u';

    /** These numbers have 11 digits. Every other number in Japan has 10, except 0800, which starts the same. */
    private const ELEVEN_DIGIT_PREFIXES = ['050', '060', '070', '080', '090'];

    private const CARD_MIN_DIGITS = 13;

    private const CARD_MAX_DIGITS = 19;

    private const MY_NUMBER_DIGITS = 12;

    public function detect(NormalizedText $text): array
    {
        $found = [];

        foreach (Pattern::matches(self::EMAIL, $text->text) as [$match, $offset]) {
            $found[] = self::detection(Rule::Email, $text, $offset, strlen($match));
        }

        foreach (Pattern::matches(self::PHONE, $text->text) as [$match, $offset]) {
            if (self::isPhone($match)) {
                $found[] = self::detection(Rule::Phone, $text, $offset, strlen($match));
            }
        }

        foreach (Pattern::matches(self::DIGIT_RUN, $text->text) as [$run, $offset]) {
            array_push($found, ...$this->numbersIn($text, $run, $offset));
        }

        return $found;
    }

    /**
     * Every way to read whole groups of a run as a number. A longer run may hold a card after an unrelated
     * number, so a run that fails as a whole is not the end of it.
     *
     * @return list<Detection>
     */
    private function numbersIn(NormalizedText $text, string $run, int $offset): array
    {
        $groups = preg_split('/[ -]/', $run);
        if ($groups === false) {
            return [];
        }

        $found = [];
        $position = 0;
        $starts = [];
        foreach ($groups as $group) {
            $starts[] = $position;
            $position += strlen($group) + 1;
        }

        foreach ($groups as $first => $group) {
            $digits = '';

            for ($last = $first, $count = count($groups); $last < $count; $last++) {
                $digits .= $groups[$last];
                $length = strlen($digits);

                if ($length > self::CARD_MAX_DIGITS) {
                    break;
                }

                $rule = match (true) {
                    $length === self::MY_NUMBER_DIGITS && self::isMyNumber($digits) => Rule::MyNumber,
                    $length >= self::CARD_MIN_DIGITS && self::passesLuhn($digits) => Rule::Card,
                    default => null,
                };

                if ($rule !== null) {
                    $found[] = self::detection($rule, $text, $offset + $starts[$first], $starts[$last] + strlen($groups[$last]) - $starts[$first]);
                }
            }
        }

        return $found;
    }

    private static function detection(Rule $rule, NormalizedText $text, int $byteStart, int $byteLength): Detection
    {
        [$start, $end] = $text->sourceSpan($byteStart, $byteStart + $byteLength);

        return new Detection($rule, $start, $end);
    }

    private static function isPhone(string $match): bool
    {
        $digits = (string) preg_replace('/[^0-9]/', '', $match);

        if (str_starts_with($match, '+81')) {
            $digits = '0'.ltrim(substr($digits, 2), '0');
        }

        $elevenDigits = in_array(substr($digits, 0, 3), self::ELEVEN_DIGIT_PREFIXES, true);

        return strlen($digits) === ($elevenDigits ? 11 : 10);
    }

    private static function passesLuhn(string $digits): bool
    {
        $sum = 0;
        $double = false;

        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
            $digit = (int) $digits[$i];

            if ($double) {
                $digit *= 2;
                $digit = $digit > 9 ? $digit - 9 : $digit;
            }

            $sum += $digit;
            $double = ! $double;
        }

        return $sum % 10 === 0;
    }

    /**
     * The check digit of the Individual Number: weights 2 to 7 and then 2 to 6, from the right.
     */
    private static function isMyNumber(string $digits): bool
    {
        $sum = 0;

        for ($n = 1; $n <= 11; $n++) {
            $sum += (int) $digits[11 - $n] * ($n <= 6 ? $n + 1 : $n - 5);
        }

        $remainder = $sum % 11;

        return (int) $digits[11] === ($remainder <= 1 ? 0 : 11 - $remainder);
    }
}
