<?php

namespace App\Security\Scanning;

/**
 * The copy that detectors read, and the way back to the original: a detection on this text can be mapped
 * to the characters that produced it. Never logged and never stored.
 */
final class NormalizedText
{
    /** @var array<int, int> Byte offset in => index of the character that starts there. */
    private array $indexAtByte = [];

    /**
     * @param  list<string>  $characters
     * @param  list<int>  $sourceStarts  Where each character came from in the original, in characters.
     * @param  list<int>  $sourceEnds
     * @param  array<int, bool>  $disguised  Characters that were made to look like something else.
     */
    public function __construct(
        public readonly string $text,
        private readonly array $characters,
        private readonly array $sourceStarts,
        private readonly array $sourceEnds,
        public readonly int $sourceLength,
        public readonly int $removedInvisible,
        private readonly array $disguised = [],
    ) {
        $byte = 0;
        foreach ($this->characters as $index => $character) {
            $this->indexAtByte[$byte] = $index;
            $byte += strlen($character);
        }
    }

    /**
     * Whether a match was disguised where it is: a letter written in full width or as a look-alike, or an
     * invisible character inside it. Full width elsewhere in the text is no reason to suspect this match.
     */
    public function isDisguised(int $byteStart, int $byteEnd): bool
    {
        $first = $this->indexAtByte[$byteStart];
        $last = ($this->indexAtByte[$byteEnd] ?? count($this->characters)) - 1;

        for ($index = $first; $index <= $last; $index++) {
            if ($this->disguised[$index] ?? false) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array{int, int} The span in the original, in characters, from a span of bytes in $text.
     */
    public function sourceSpan(int $byteStart, int $byteEnd): array
    {
        $first = $this->indexAtByte[$byteStart];
        $last = ($this->indexAtByte[$byteEnd] ?? count($this->characters)) - 1;

        return [$this->sourceStarts[$first], $this->sourceEnds[max($first, $last)]];
    }
}
