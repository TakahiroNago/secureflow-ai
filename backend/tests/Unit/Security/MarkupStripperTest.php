<?php

use App\Security\Output\InvalidAiOutputException;
use App\Security\Output\MarkupStripper;

/*
| docs/security-design.md §7. A second layer: the screens draw text as text whatever this leaves.
*/

function stripped(string $text): string
{
    return (new MarkupStripper)->strip($text);
}

it('removes markup and keeps the words', function (string $text, string $expected) {
    expect(stripped($text))->toBe($expected);
})->with([
    'a tag' => ['前<b>太字</b>後', '前太字後'],
    'a script and what is in it' => ['前<script>alert(1)</script>後', '前後'],
    'a style and what is in it' => ['前<style>a{}</style>後', '前後'],
    'an upper case script' => ['前<SCRIPT SRC=x>alert(1)</SCRIPT>後', '前後'],
    'a script spread over lines' => ["前<script>\nalert(1)\n</script>後", '前後'],
    'an unclosed script' => ['前<script>alert(1)', '前'],
    'an unclosed image' => ['前<img src=x', '前'],
    'an image with an event' => ['前<img src=x onerror=alert(1)>後', '前後'],
    'a comment' => ['前<!-- 中 -->後', '前後'],
    'a comment with tags in it' => ['前<!-- <b>中</b> -->後', '前後'],
    'an unclosed comment' => ['前<!-- 中', '前'],
    'a doctype' => ['<!DOCTYPE html>本文', '本文'],
    'a link' => ['<a href="javascript:alert(1)">押す</a>', '押す'],
    'a scheme alone' => ['javascript:alert(1)', 'alert(1)'],
    'a scheme spread out' => ["java\tscript:alert(1)", 'alert(1)'],
    'an old scheme' => ['vbscript:x', 'x'],
    'a data page' => ['data:text/html,x', ',x'],
    'an event alone' => ['onerror=alert(1)', 'alert(1)'],
    'an event after Japanese' => ['前onerror=x', '前x'],
    'nested to come back' => ['<scr<b>ipt>alert(1)</scr</b>ipt>', ''],
    'a scheme that comes back' => ['javajavascript:script:x', 'x'],
]);

it('leaves ordinary text as it is', function (string $text) {
    expect(stripped($text))->toBe($text);
})->with([
    '売上は 5 < 10 です',
    '10 > 5 です',
    'メールを確認する',
    'conversion=5 の設定',
    'reason = x',
    '&lt;script&gt;',
    '依頼: 確認',
]);

it('LIMIT: takes what looks like a tag, even when it was a comparison', function () {
    expect(stripped('a<b and c>d'))->toBe('ad');
});

it('refuses what does not settle', function () {
    // Each round removes one level.
    $depth = str_repeat('<a', 12).str_repeat('>', 12);

    expect(fn () => stripped($depth))->toThrow(InvalidAiOutputException::class);
});
