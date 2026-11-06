<?php

namespace App\Security\Scanning;

use Normalizer;
use SensitiveParameter;

/**
 * docs/security-design.md §3.1: NFKC, invisible characters removed, look-alikes replaced, runs of spaces
 * closed up. Character by character, so that every result can be traced back to the original. Case is kept:
 * key formats depend on it, and detectors that do not care ignore it themselves.
 */
final class TextNormalizer
{
    private const INVISIBLE = [
        "\u{00AD}", "\u{180E}", "\u{200B}", "\u{200C}", "\u{200D}", "\u{200E}", "\u{200F}",
        "\u{202A}", "\u{202B}", "\u{202C}", "\u{202D}", "\u{202E}",
        "\u{2060}", "\u{2061}", "\u{2062}", "\u{2063}", "\u{2064}", "\u{FEFF}",
    ];

    /** The main look-alikes (Cyrillic and Greek), and dashes that NFKC leaves alone. */
    private const LOOK_ALIKES = [
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'у' => 'y', 'х' => 'x', 'і' => 'i', 'ј' => 'j', 'ѕ' => 's', 'һ' => 'h', 'ԁ' => 'd',
        'А' => 'A', 'В' => 'B', 'Е' => 'E', 'К' => 'K', 'М' => 'M', 'Н' => 'H', 'О' => 'O', 'Р' => 'P', 'С' => 'C', 'Т' => 'T', 'Х' => 'X',
        'ο' => 'o', 'α' => 'a', 'ν' => 'v', 'ι' => 'i', 'κ' => 'k', 'Α' => 'A', 'Β' => 'B', 'Ε' => 'E', 'Κ' => 'K', 'Μ' => 'M', 'Ν' => 'N', 'Ο' => 'O', 'Ρ' => 'P', 'Τ' => 'T', 'Χ' => 'X',
        "\u{2010}" => '-', "\u{2011}" => '-', "\u{2012}" => '-', "\u{2013}" => '-', "\u{2014}" => '-', "\u{2015}" => '-', "\u{2212}" => '-',
    ];

    /**
     * @throws ScanFailure
     */
    public function normalize(#[SensitiveParameter] string $text): NormalizedText
    {
        if (! mb_check_encoding($text, 'UTF-8')) {
            throw new ScanFailure(ScanFailure::INVALID_ENCODING);
        }

        $source = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);
        if ($source === false) {
            throw new ScanFailure(ScanFailure::INVALID_ENCODING);
        }

        $invisible = array_flip(self::INVISIBLE);
        $characters = $starts = $ends = [];
        $removed = 0;

        foreach ($source as $position => $character) {
            if (isset($invisible[$character])) {
                $removed++;

                continue;
            }

            foreach ($this->converted($character) as $output) {
                $last = count($characters) - 1;

                if ($last >= 0 && $output === ' ' && $characters[$last] === ' ') {
                    $ends[$last] = $position + 1;

                    continue;
                }

                // A sound mark that NFKC separated from its kana: half-width パ is two characters.
                if ($last >= 0 && strlen($output) > 1 && preg_match('/^\p{M}$/u', $output) === 1) {
                    $composed = Normalizer::normalize($characters[$last].$output, Normalizer::FORM_C);

                    if (is_string($composed) && mb_strlen($composed, 'UTF-8') === 1) {
                        $characters[$last] = $composed;
                        $ends[$last] = $position + 1;

                        continue;
                    }
                }

                $characters[] = $output;
                $starts[] = $position;
                $ends[] = $position + 1;
            }
        }

        return new NormalizedText(implode('', $characters), array_values($characters), $starts, array_values($ends), count($source), $removed);
    }

    /**
     * @return list<string>
     */
    private function converted(string $character): array
    {
        if (strlen($character) === 1) {
            return [$character === "\t" ? ' ' : $character];
        }

        $normalized = Normalizer::normalize($character, Normalizer::FORM_KC);
        if (! is_string($normalized)) {
            throw new ScanFailure(ScanFailure::INVALID_ENCODING);
        }

        $parts = preg_split('//u', $normalized, -1, PREG_SPLIT_NO_EMPTY);
        if ($parts === false) {
            throw new ScanFailure(ScanFailure::INVALID_ENCODING);
        }

        return array_map(fn (string $part) => self::LOOK_ALIKES[$part] ?? $part, $parts);
    }
}
