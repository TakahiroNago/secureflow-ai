<?php

namespace Tests\Support;

use PhpToken;

/**
 * The `it(...)` and `test(...)` declarations of a Pest file, each with what it is chained with, found by tokens so
 * that a parenthesis inside a string cannot confuse it. docs/test-strategy.md §31: every ST case is in the
 * security group wherever its file lives, and this is how that is checked.
 */
final class SecurityTestIndex
{
    public const GROUP = 'security';

    /**
     * @return list<array{name: string, start: int, end: int, chain: string}> `end` is the offset of the closing `;`,
     *                                                                        `chain` the text between the call and it.
     */
    public static function declarations(string $source): array
    {
        $tokens = PhpToken::tokenize($source);
        $count = count($tokens);
        $found = [];

        for ($i = 0; $i < $count; $i++) {
            if (! $tokens[$i]->is(T_STRING) || ! in_array($tokens[$i]->text, ['it', 'test'], true)) {
                continue;
            }

            $previous = self::significant($tokens, $i, -1);
            if ($previous !== null && $tokens[$previous]->is([T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW, T_CONST])) {
                continue;
            }

            $open = self::significant($tokens, $i, 1);
            if ($open === null || $tokens[$open]->text !== '(') {
                continue;
            }

            $first = self::significant($tokens, $open, 1);
            if ($first === null || ! $tokens[$first]->is(T_CONSTANT_ENCAPSED_STRING)) {
                continue;
            }

            $close = self::matchingParen($tokens, $open);
            if ($close === null) {
                continue;
            }

            // Chained calls up to the semicolon: ->with(...)->group(...)->throws(...)
            $last = $close;
            while (($arrow = self::significant($tokens, $last, 1)) !== null && $tokens[$arrow]->is(T_OBJECT_OPERATOR)) {
                $method = self::significant($tokens, $arrow, 1);
                $paren = $method === null ? null : self::significant($tokens, $method, 1);
                if ($paren === null || $tokens[$paren]->text !== '(') {
                    break;
                }
                $end = self::matchingParen($tokens, $paren);
                if ($end === null) {
                    break;
                }
                $last = $end;
            }

            $semicolon = self::significant($tokens, $last, 1);
            if ($semicolon === null || $tokens[$semicolon]->text !== ';') {
                continue;
            }

            $chainStart = $tokens[$close]->pos + 1;
            $found[] = [
                'name' => self::unquote($tokens[$first]->text),
                'start' => $tokens[$i]->pos,
                'end' => $tokens[$semicolon]->pos,
                'chain' => substr($source, $chainStart, $tokens[$semicolon]->pos - $chainStart),
            ];
            $i = $semicolon;
        }

        return $found;
    }

    public static function inGroup(string $chain, string $group = self::GROUP): bool
    {
        return preg_match('/->group\(([^)]*)\)/', $chain, $match) === 1
            && preg_match('/[\'"]'.preg_quote($group, '/').'[\'"]/', $match[1]) === 1;
    }

    /**
     * @param  list<PhpToken>  $tokens
     */
    private static function significant(array $tokens, int $from, int $direction): ?int
    {
        for ($i = $from + $direction; $i >= 0 && $i < count($tokens); $i += $direction) {
            if (! $tokens[$i]->is([T_WHITESPACE, T_COMMENT, T_DOC_COMMENT])) {
                return $i;
            }
        }

        return null;
    }

    /**
     * @param  list<PhpToken>  $tokens
     */
    private static function matchingParen(array $tokens, int $open): ?int
    {
        $depth = 0;

        for ($i = $open; $i < count($tokens); $i++) {
            if ($tokens[$i]->text === '(') {
                $depth++;
            } elseif ($tokens[$i]->text === ')') {
                $depth--;
                if ($depth === 0) {
                    return $i;
                }
            }
        }

        return null;
    }

    private static function unquote(string $literal): string
    {
        $quote = $literal[0];
        $inner = substr($literal, 1, -1);

        return $quote === "'"
            ? str_replace(['\\\'', '\\\\'], ['\'', '\\'], $inner)
            : (string) json_decode('"'.str_replace(['\\$', '"'], ['$', '\\"'], $inner).'"');
    }
}
