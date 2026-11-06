<?php

namespace App\Security\Scanning;

use SensitiveParameter;

/**
 * Replaces each detection in the original text and leaves every other character as it was.
 */
final class Masker
{
    /**
     * @param  list<Detection>  $detections  Not overlapping.
     *
     * @throws ScanFailure when the result does not add up (docs/security-design.md §3.4)
     */
    public function mask(#[SensitiveParameter] string $text, array $detections): string
    {
        $characters = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);
        if ($characters === false) {
            throw new ScanFailure(ScanFailure::INVALID_ENCODING);
        }

        usort($detections, fn (Detection $a, Detection $b) => $a->start <=> $b->start);

        $masked = '';
        $position = 0;
        $replaced = 0;
        $expectedLength = count($characters);

        foreach ($detections as $detection) {
            if ($detection->start < $position || $detection->end > count($characters) || $detection->end <= $detection->start) {
                throw new ScanFailure(ScanFailure::COUNT_MISMATCH);
            }

            $masked .= implode('', array_slice($characters, $position, $detection->start - $position));
            $masked .= $detection->rule->replacement();
            $position = $detection->end;
            $replaced++;
            $expectedLength += mb_strlen($detection->rule->replacement(), 'UTF-8') - $detection->length();
        }

        $masked .= implode('', array_slice($characters, $position));

        if ($replaced !== count($detections) || mb_strlen($masked, 'UTF-8') !== $expectedLength) {
            throw new ScanFailure(ScanFailure::COUNT_MISMATCH);
        }

        return $masked;
    }
}
