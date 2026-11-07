<?php

use App\Security\Scanning\Detection;
use App\Security\Scanning\Detectors\Detector;
use App\Security\Scanning\Detectors\Pattern;
use App\Security\Scanning\Masker;
use App\Security\Scanning\NormalizedText;
use App\Security\Scanning\Rule;
use App\Security\Scanning\ScanDecision;
use App\Security\Scanning\ScanFailure;
use App\Security\Scanning\ScanResult;
use App\Security\Scanning\SensitiveDataScanner;
use Tests\Support\FakeSecrets;

/*
| docs/security-design.md §3.3, §3.4. ST-03, ST-04, ST-35 and ST-36 at the level of the scanner: stopping the
| work and calling the AI follow in step 2-3.
*/

function scanned(string $text): ScanResult
{
    return (new SensitiveDataScanner)->scan($text);
}

function rulesIn(ScanResult $result): array
{
    return array_map(fn (Detection $detection) => $detection->rule->value, $result->detections);
}

// ---- Nothing to find ---------------------------------------------------------------------------

it('returns ordinary text unchanged', function () {
    $text = "週次の売上報告を作成してください。\n担当は営業部です。";
    $result = scanned($text);

    expect($result->decision)->toBe(ScanDecision::Allow)
        ->and($result->maskingStatus)->toBe('not_required')
        ->and($result->maskedText)->toBe($text)
        ->and($result->detections)->toBe([])
        ->and($result->maxSeverity())->toBeNull();
});

// ---- Personal information: masked, and the work continues ----------------------------------------

it('ST-04: masks personal information and continues', function (string $text, string $rule, string $masked) {
    $result = scanned($text);

    expect(rulesIn($result))->toBe([$rule])
        ->and($result->decision)->toBe(ScanDecision::Allow)
        ->and($result->maskingStatus)->toBe('masked')
        ->and($result->maskedText)->toBe($masked);
})->with([
    'email' => ['宛先は test@example.com です', 'PII-EMAIL', '宛先は [EMAIL_REDACTED] です'],
    'email with a plus' => ['a.b+c@mail.example.co.jp まで', 'PII-EMAIL', '[EMAIL_REDACTED] まで'],
    'mobile' => ['携帯は 090-1234-5678 です', 'PII-PHONE-JP', '携帯は [PHONE_REDACTED] です'],
    'mobile without hyphens' => ['携帯は09012345678です', 'PII-PHONE-JP', '携帯は[PHONE_REDACTED]です'],
    'landline' => ['電話 03-1234-5678', 'PII-PHONE-JP', '電話 [PHONE_REDACTED]'],
    'landline in brackets' => ['電話 03(1234)5678', 'PII-PHONE-JP', '電話 [PHONE_REDACTED]'],
    'international' => ['Tel +81-90-1234-5678', 'PII-PHONE-JP', 'Tel [PHONE_REDACTED]'],
    'international with a zero' => ['Tel +81(0)3-1234-5678', 'PII-PHONE-JP', 'Tel [PHONE_REDACTED]'],
])->group('security');

it('ST-04: finds a card by its check digit, in every usual form', function (Closure $number) {
    $text = 'カード '.$number().' です';
    $result = scanned($text);

    expect(rulesIn($result))->toBe(['PII-CARD'])
        ->and($result->maskedText)->toBe('カード [CREDIT_CARD_REDACTED] です');
})->with([
    'plain' => [fn () => FakeSecrets::card()],
    'spaces' => [fn () => implode(' ', str_split(FakeSecrets::card(), 4))],
    'hyphens' => [fn () => implode('-', str_split(FakeSecrets::card(), 4))],
    '15 digits' => [fn () => FakeSecrets::card(15, '37')],
])->group('security');

it('leaves a number that fails the check digit', function () {
    $card = FakeSecrets::card();
    $wrong = substr($card, 0, 15).(((int) $card[15] + 1) % 10);

    expect(scanned('番号 '.$wrong)->detections)->toBe([]);
});

it('finds a card after an unrelated number in the same run', function () {
    $card = FakeSecrets::card();
    $result = scanned('注文 123 '.$card);

    expect(rulesIn($result))->toBe(['PII-CARD'])
        ->and($result->maskedText)->toBe('注文 123 [CREDIT_CARD_REDACTED]');
});

it('ST-04: finds My Number by its check digit', function () {
    $number = FakeSecrets::myNumber();

    expect(scanned('番号 '.$number.' です')->maskedText)->toBe('番号 [MY_NUMBER_REDACTED] です')
        ->and(rulesIn(scanned('番号 '.implode('-', str_split($number, 4)))))->toBe(['PII-MYNUMBER']);

    $wrong = substr($number, 0, 11).(((int) $number[11] + 1) % 10);

    expect(rulesIn(scanned('番号 '.$wrong)))->not->toContain('PII-MYNUMBER');
})->group('security');

it('calculates the check digit of My Number by hand', function () {
    // 12345678901, weights 6 5 4 3 2 7 6 5 4 3 2: the sum is 212, the remainder 3, so the check digit is 8.
    expect(rulesIn(scanned('番号 123456789018')))->toBe(['PII-MYNUMBER'])
        ->and(rulesIn(scanned('番号 123456789012')))->not->toContain('PII-MYNUMBER');
});

it('leaves what is not a phone number', function (string $text) {
    expect(rulesIn(scanned($text)))->not->toContain('PII-PHONE-JP');
})->with([
    '2026-11-06 の予定',
    '金額は 1,234,567 円',
    'バージョン 1.2.3',
    '0120 だけ',
    '00-1234-5678',
    'IP は 192.168.0.1 です',
    '01-02-2026',
    '090-1234-567',
]);

it('masks all of several, and leaves the rest as it was', function () {
    $result = scanned('A: a@example.com / B: b@example.com / 090-1234-5678 おわり');

    expect($result->maskedText)->toBe('A: [EMAIL_REDACTED] / B: [EMAIL_REDACTED] / [PHONE_REDACTED] おわり')
        ->and($result->detections)->toHaveCount(3);
});

// ---- Secrets: the work stops --------------------------------------------------------------------

it('ST-03, ST-35: stops on every form of a secret, and returns no text', function (Closure $secret, string $rule) {
    $result = scanned('以下を確認: '.$secret().' お願いします');

    expect(rulesIn($result))->toBe([$rule])
        ->and($result->decision)->toBe(ScanDecision::Block)
        ->and($result->maskedText)->toBeNull();
})->with([
    'OpenAI' => [fn () => FakeSecrets::apiKey('openai'), 'SEC-APIKEY'],
    'OpenAI project' => [fn () => FakeSecrets::apiKey('openai-project'), 'SEC-APIKEY'],
    'AWS' => [fn () => FakeSecrets::apiKey('aws'), 'SEC-APIKEY'],
    'Google' => [fn () => FakeSecrets::apiKey('google'), 'SEC-APIKEY'],
    'GitHub' => [fn () => FakeSecrets::apiKey('github'), 'SEC-APIKEY'],
    'GitHub fine-grained' => [fn () => FakeSecrets::apiKey('github-fine'), 'SEC-APIKEY'],
    'Slack' => [fn () => FakeSecrets::apiKey('slack'), 'SEC-APIKEY'],
    'JWT' => [fn () => FakeSecrets::jwt(), 'SEC-TOKEN'],
    'Bearer' => [fn () => FakeSecrets::bearer(), 'SEC-TOKEN'],
    'PEM' => [fn () => FakeSecrets::privateKey(), 'SEC-PRIVKEY'],
    'OpenSSH' => [fn () => FakeSecrets::privateKey('OPENSSH '), 'SEC-PRIVKEY'],
    'EC' => [fn () => FakeSecrets::privateKey('EC '), 'SEC-PRIVKEY'],
])->group('security');

it('ST-35: stops on a key that was cut off before its end', function () {
    $key = FakeSecrets::privateKey();
    $cut = substr($key, 0, 60);

    expect(rulesIn(scanned('鍵は '.$cut)))->toBe(['SEC-PRIVKEY']);
})->group('security');

it('ST-35: stops on a password next to its keyword', function (string $template) {
    $password = FakeSecrets::password();
    $result = scanned(str_replace('%s', $password, $template));

    expect(rulesIn($result))->toBe(['SEC-PASSWORD'])
        ->and($result->decision)->toBe(ScanDecision::Block);
})->with([
    'password: %s',
    'PASSWORD=%s',
    'pass=%s',
    'pwd: %s',
    'パスワード：%s',
    'パスワード: %s',
    'パスワード=%s',
    'パスコード: %s',
    '暗証番号: %s',
    'パスワードは %s です',
    'パスワードは%sです',
    'パスワードが %s になっています',
    '"password": "%s"',
    "password = '%s'",
    'ﾊﾟｽﾜｰﾄﾞ: %s',
])->group('security');

it('does not stop on a sentence about passwords', function (string $text) {
    expect(rulesIn(scanned($text)))->not->toContain('SEC-PASSWORD');
})->with([
    'パスワードは定期的に変更してください',
    'パスワードが一致しません',
    'パスワードを忘れた場合',
    'パスワード: 必須',
    'password: required',
    'Password: ******',
    'password: <your-password>',
    'password: {{secret}}',
    'bypass: north',
    'compass: east-side',
    'The password policy requires 12 characters.',
    'パスワードは abc です',
]);

it('does not stop on ordinary words that look like the start of a key', function (string $text) {
    expect(scanned($text)->decision)->not->toBe(ScanDecision::Block);
})->with([
    'task-management-framework-documents',
    'sk-management-framework-policy-review',
    'risk-assessment-for-the-new-system-2026',
    'Bearer トークンを使って認証します',
    'bearer token authentication',
    'eyJ で始まる文字列',
    'BEGIN PRIVATE KEY という語を説明します',
]);

it('does not take a string as a JWT unless its header says so', function () {
    $notJson = 'eyJ'.str_repeat('a', 20).'.'.str_repeat('b', 20).'.'.str_repeat('c', 20);

    expect(rulesIn(scanned($notJson)))->not->toContain('SEC-TOKEN');
});

it('stops when a secret comes with personal information, and returns no text', function () {
    $result = scanned('a@example.com の '.FakeSecrets::apiKey('github'));

    expect($result->decision)->toBe(ScanDecision::Block)
        ->and($result->maskedText)->toBeNull()
        ->and(rulesIn($result))->toBe(['PII-EMAIL', 'SEC-APIKEY']);
});

it('says where a secret is, in characters of the original', function () {
    $key = FakeSecrets::apiKey('github');
    $result = scanned('日本語の後の '.$key.' です');

    expect($result->detections[0]->start)->toBe(7)
        ->and($result->detections[0]->end)->toBe(7 + strlen($key));
});

// ---- Suspected secrets: masked, with a warning ----------------------------------------------------

it('warns on a long random string, and masks it', function () {
    $result = scanned('値は '.FakeSecrets::highEntropy().' です');

    expect(rulesIn($result))->toBe(['SEC-ENTROPY'])
        ->and($result->decision)->toBe(ScanDecision::Warn)
        ->and($result->maskedText)->toBe('値は [SECRET_REDACTED] です');
});

it('leaves long strings that are not random', function (string $text) {
    expect(rulesIn(scanned($text)))->not->toContain('SEC-ENTROPY');
})->with([
    'implementation-of-the-document-management-system',
    '11111111111111111111111111111111111111',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'short1234',
    'with digits, but not random' => ['abc123abc123abc123abc123abc123abc123abc123'],
    'a long name with a version' => ['quarterly_financial_statement_report_v2'],
]);

// ---- Overlaps ------------------------------------------------------------------------------------

it('lets what stops the work win an overlap', function () {
    $key = FakeSecrets::apiKey('openai');
    $result = scanned($key);

    expect(rulesIn($result))->toBe(['SEC-APIKEY']);
});

it('prefers the longest match among rules with the same action: a card over a phone number inside it', function () {
    // The second group alone is a phone number, and with 0000 in front the 14 digits pass the check as a card.
    $number = FakeSecrets::card(14, '0000031234567');
    $result = scanned('番号 0000-'.substr($number, 4));

    expect(rulesIn($result))->toBe(['PII-CARD'])
        ->and($result->maskedText)->toBe('番号 [CREDIT_CARD_REDACTED]');
});

it('prefers the longest even when a shorter match starts first', function () {
    $detector = new class implements Detector
    {
        public function detect(NormalizedText $text): array
        {
            return str_contains($text->text, 'xxxx') ? [new Detection(Rule::Email, 0, 3), new Detection(Rule::Phone, 1, 8)] : [];
        }
    };

    $result = (new SensitiveDataScanner(detectors: [$detector]))->scan('xxxxxxxxxx');

    expect(rulesIn($result))->toBe(['PII-PHONE-JP'])
        ->and($result->maskedText)->toBe('x[PHONE_REDACTED]xx');
});

// ---- Normalization: what is hidden is still found -------------------------------------------------

it('finds what is written in full width, and masks the original characters', function () {
    $result = scanned('宛先 ｔｅｓｔ＠ｅｘａｍｐｌｅ．ｃｏｍ まで');

    expect(rulesIn($result))->toBe(['PII-EMAIL'])
        ->and($result->maskedText)->toBe('宛先 [EMAIL_REDACTED] まで');
});

it('finds full-width digits and hyphens', function () {
    expect(scanned('０９０－１２３４－５６７８ です')->maskedText)->toBe('[PHONE_REDACTED] です')
        ->and(scanned('090‐1234‐5678')->maskedText)->toBe('[PHONE_REDACTED]');
});

it('finds what has invisible characters inside, and counts them', function () {
    $hidden = "te\u{200B}st@exa\u{200D}mple.com";
    $result = scanned('宛先 '.$hidden.' まで');

    expect($result->maskedText)->toBe('宛先 [EMAIL_REDACTED] まで')
        ->and($result->removedInvisible)->toBe(2);
});

it('stops on a key with invisible characters inside', function () {
    $key = FakeSecrets::apiKey('github');
    $hidden = substr($key, 0, 10)."\u{2060}".substr($key, 10);

    expect(rulesIn(scanned($hidden)))->toBe(['SEC-APIKEY']);
});

it('finds what is written with look-alike letters', function () {
    // The a in "example" and the o in "com" are Cyrillic.
    $result = scanned("user@ex\u{0430}mple.c\u{043E}m");

    expect(rulesIn($result))->toBe(['PII-EMAIL'])->and($result->maskedText)->toBe('[EMAIL_REDACTED]');
});

it('keeps invisible characters and full width elsewhere in the text as they were', function () {
    $result = scanned("ａｂｃ\u{200B}　 a@example.com");

    expect($result->maskedText)->toBe("ａｂｃ\u{200B}　 [EMAIL_REDACTED]");
});

it('maps a character that NFKC turns into several back to itself', function () {
    $result = scanned('㍿の担当は a@example.com です');

    expect($result->maskedText)->toBe('㍿の担当は [EMAIL_REDACTED] です')
        ->and($result->detections[0]->start)->toBe(6);
});

it('handles emoji in front of a detection', function () {
    expect(scanned('😀😀 a@example.com 😀')->maskedText)->toBe('😀😀 [EMAIL_REDACTED] 😀');
});

// ---- Failing closed (ST-36) --------------------------------------------------------------------

function failsWith(ScanResult $result, string $reason): void
{
    expect($result->decision)->toBe(ScanDecision::Block)
        ->and($result->maskingStatus)->toBe('failed')
        ->and($result->maskedText)->toBeNull()
        ->and(rulesIn($result))->toBe(['MASK-FAIL'])
        ->and($result->failureReason)->toBe($reason)
        ->and($result->maxSeverity()->value)->toBe('high');
}

it('ST-36: blocks text that is not valid UTF-8', function () {
    failsWith(scanned("宛先 \xC3\x28 test@example.com"), ScanFailure::INVALID_ENCODING);
})->group('security');

it('ST-36: blocks a text over the limit, without reading it', function () {
    failsWith(scanned(str_repeat('あ', SensitiveDataScanner::MAX_CHARACTERS + 1)), ScanFailure::TOO_LONG);
    expect(scanned(str_repeat('あ', SensitiveDataScanner::MAX_CHARACTERS))->decision)->toBe(ScanDecision::Allow);
})->group('security');

it('ST-36: blocks when a detector fails', function (Throwable $thrown, string $reason) {
    $detector = new class($thrown) implements Detector
    {
        public function __construct(private readonly Throwable $thrown) {}

        public function detect(NormalizedText $text): array
        {
            throw $this->thrown;
        }
    };

    failsWith((new SensitiveDataScanner(detectors: [$detector]))->scan('普通の文章'), $reason);
})->with([
    'an error' => [new RuntimeException('boom'), 'unexpected'],
    'a pattern that gave up' => [new ScanFailure(ScanFailure::PATTERN_ERROR), ScanFailure::PATTERN_ERROR],
])->group('security');

it('ST-36: a pattern that gave up has not said there is nothing', function () {
    // PCRE refuses invalid UTF-8 with an error: the same way as when it runs out of its limits.
    expect(fn () => Pattern::matches('/a/u', "\xC3\x28"))->toThrow(ScanFailure::class);

    $limit = ini_get('pcre.backtrack_limit');
    $jit = ini_get('pcre.jit');
    ini_set('pcre.backtrack_limit', '10');
    ini_set('pcre.jit', '0');

    try {
        expect(fn () => Pattern::matches('/(a+)+$/', str_repeat('a', 30).'b'))->toThrow(ScanFailure::class);
    } finally {
        ini_set('pcre.backtrack_limit', (string) $limit);
        ini_set('pcre.jit', (string) $jit);
    }
})->group('security');

it('ST-36: blocks when the time is over', function () {
    failsWith((new SensitiveDataScanner(deadlineSeconds: 0))->scan('普通の文章'), ScanFailure::TIMEOUT);
})->group('security');

it('ST-36: blocks when something is still found after masking', function () {
    // Finds the same thing in the masked text too, whatever it says.
    $detector = new class implements Detector
    {
        public function detect(NormalizedText $text): array
        {
            return [new Detection(Rule::Email, 0, 1)];
        }
    };

    failsWith((new SensitiveDataScanner(detectors: [$detector]))->scan('abc'), ScanFailure::STILL_DETECTED);
})->group('security');

it('ST-36: blocks when masking does not add up', function () {
    $detector = new class implements Detector
    {
        public function detect(NormalizedText $text): array
        {
            return [new Detection(Rule::Email, 0, 1000)];
        }
    };

    failsWith((new SensitiveDataScanner(detectors: [$detector]))->scan('abc'), ScanFailure::COUNT_MISMATCH);
})->group('security');

it('refuses detections that overlap or are empty', function (array $detections) {
    expect(fn () => (new Masker)->mask('abcdef', $detections))->toThrow(ScanFailure::class);
})->with([
    'overlap' => [[new Detection(Rule::Email, 0, 3), new Detection(Rule::Phone, 2, 4)]],
    'empty' => [[new Detection(Rule::Email, 2, 2)]],
    'past the end' => [[new Detection(Rule::Email, 2, 9)]],
]);

it('never leaves the text when anything fails', function () {
    $secret = 'visible-marker-'.FakeSecrets::random(8);
    $result = scanned($secret."\xC3\x28");

    expect(serialize($result))->not->toContain($secret);
});

// ---- Staying inside the limits --------------------------------------------------------------------

it('finishes the longest inputs well inside the time limit', function (string $text) {
    $started = hrtime(true);
    $result = (new SensitiveDataScanner(deadlineSeconds: 30))->scan($text);
    $seconds = (hrtime(true) - $started) / 1e9;

    expect($seconds)->toBeLessThan(SensitiveDataScanner::DEADLINE_SECONDS)
        ->and($result->failureReason)->not->toBe(ScanFailure::PATTERN_ERROR);
})->with([
    'an endless address' => [str_repeat('a', 20000)],
    'addresses that never end' => [str_repeat('a.', 10000)],
    'almost an address' => [str_repeat('a@', 10000)],
    'almost a domain' => ['a@'.str_repeat('b.', 9990)],
    'digits' => [str_repeat('1', 20000)],
    'digit groups' => [str_repeat('1 ', 10000)],
    'hyphenated digits' => [str_repeat('12-', 6666)],
    'almost a password' => [str_repeat('password:', 2222)],
    'almost a key' => [str_repeat('sk-', 6666)],
    'almost a private key' => [str_repeat('-----BEGIN ', 1818)],
    'long token' => [str_repeat('aB3', 6666)],
    'invisible characters' => [str_repeat("\u{200B}", 20000)],
    'full width' => [str_repeat('ａ', 20000)],
    'many addresses' => [str_repeat('a@example.com ', 1428)],
    'spaces' => [str_repeat(' ', 20000)],
]);

// ---- What the result says ------------------------------------------------------------------------

it('keeps severity and action apart, as defined for each rule', function (Rule $rule, string $severity, string $action, string $category) {
    expect($rule->severity()->value)->toBe($severity)
        ->and($rule->action()->value)->toBe($action)
        ->and($rule->category())->toBe($category)
        ->and($rule->message())->not->toBeEmpty();
})->with([
    [Rule::Email, 'medium', 'mask_continue', 'pii'],
    [Rule::Phone, 'medium', 'mask_continue', 'pii'],
    [Rule::Card, 'high', 'mask_continue', 'pii'],
    [Rule::MyNumber, 'high', 'mask_continue', 'pii'],
    [Rule::ApiKey, 'critical', 'block', 'secret'],
    [Rule::Token, 'critical', 'block', 'secret'],
    [Rule::Password, 'high', 'block', 'secret'],
    [Rule::PrivateKey, 'critical', 'block', 'secret'],
    [Rule::Entropy, 'medium', 'warn', 'secret'],
    [Rule::MaskFailed, 'high', 'block', 'masking'],
]);

it('takes the decision from the actions, not from severity: a high card number continues', function () {
    $result = scanned(FakeSecrets::card());

    expect($result->maxSeverity()->value)->toBe('high')
        ->and($result->decision)->toBe(ScanDecision::Allow);
});

it('holds no text in a detection', function () {
    $secret = FakeSecrets::apiKey('github');

    expect(serialize(scanned('前 '.$secret.' 後')))->not->toContain($secret);
});
