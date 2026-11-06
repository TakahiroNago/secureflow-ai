<?php

namespace App\Security\Output;

use SensitiveParameter;

/**
 * Plain text out of what the AI wrote (docs/security-design.md §7). This is the second layer: the first is that
 * the screens draw text as text, and nothing depends on this catching everything.
 *
 * It removes rather than escapes, and repeats until nothing changes, so that removing one thing cannot leave
 * another behind ("<scr<b>ipt>"). The price is that "a<b and c>d" loses its middle. Entities are left as they are:
 * decoding them could only make markup out of text.
 */
final class MarkupStripper
{
    private const MAX_ROUNDS = 10;

    private const PATTERNS = [
        '~<(script|style)\b[^>]*+>.*?(?:</\1\s*>|$)~isu',
        '~<!--.*?(?:-->|$)~su',
        '~</?[a-z!?][^<>]*+>~iu',
        '~<(?:script|style|img|iframe|svg|object|embed|link|meta)\b[^<>]*+$~iu',
        '~j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:~iu',
        '~v\s*b\s*s\s*c\s*r\s*i\s*p\s*t\s*:~iu',
        '~data\s*:\s*text/html~iu',
        '~(?<![a-z0-9_])on[a-z]{2,}\s*=~iu',
    ];

    /**
     * @throws InvalidAiOutputException when it does not settle, or a pattern gives up
     */
    public function strip(#[SensitiveParameter] string $text): string
    {
        for ($round = 0; $round < self::MAX_ROUNDS; $round++) {
            $stripped = preg_replace(self::PATTERNS, '', $text);

            if (! is_string($stripped)) {
                throw new InvalidAiOutputException('markup_error');
            }

            if ($stripped === $text) {
                return $text;
            }

            $text = $stripped;
        }

        throw new InvalidAiOutputException('markup_unstable');
    }
}
