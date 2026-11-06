<?php

namespace App\Security\Scanning\Detectors;

use App\Security\Scanning\Detection;
use App\Security\Scanning\NormalizedText;
use App\Security\Scanning\Rule;

/**
 * docs/security-design.md §3.3. Each of these stops the work, so they are shaped to leave ordinary sentences
 * alone: "Bearer トークン" and "パスワードは定期的に変更" are not secrets.
 */
final class SecretDetector implements Detector
{
    private const API_KEYS = [
        // At least one digit: "sk-" also starts ordinary hyphenated words.
        '/(?<![A-Za-z0-9])sk-(?:proj-|ant-)?(?=[A-Za-z_-]*[0-9])[A-Za-z0-9_-]{20,}+/u',
        '/(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![0-9A-Z])/u',
        '/(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/u',
        '/(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36,}+/u',
        '/(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{22,}+/u',
        '/(?<![A-Za-z0-9])xox[abpr]-(?=[A-Za-z-]*[0-9])[A-Za-z0-9-]{10,}+/u',
    ];

    private const JWT = '/(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,}+)\.[A-Za-z0-9_-]{8,}+\.[A-Za-z0-9_-]*+/u';

    private const BEARER = '/(?<![A-Za-z])bearer[ \n]+[A-Za-z0-9._~+\/=-]{20,}+/iu';

    private const PRIVATE_KEY = '/-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|\z)|PuTTY-User-Key-File-[0-9]+:.*\z/su';

    /** The keyword and a separator, then the value. \K leaves the keyword out of the match. */
    private const PASSWORD_AFTER_SEPARATOR = '/(?<![a-z])(?:password|passwd|passphrase|pwd|pass|パスワード|パスコード|暗証番号)["\']?[ ]?[:=][ ]?["\']?\K[\x21-\x7E]{4,}+/iu';

    private const PASSWORD_IN_SENTENCE = '/(?:パスワード|パスコード|暗証番号)[ ]?[はが][ ]?\K[\x21-\x7E]{6,}+/u';

    /** What follows the keyword in documentation, rather than a password. */
    private const NOT_A_PASSWORD = '/^(?:required|optional|none|null|empty|true|false|string|example|expired|invalid|incorrect|reset|policy|\*+|x+|<.*>|\{.*\}|\$\{.*\}|\[[A-Z_]+_REDACTED\])$/i';

    private const LONG_TOKEN = '/(?<![A-Za-z0-9+\/=_-])[A-Za-z0-9+\/=_-]{32,}+/u';

    /** Bits per character. Provisional, and measured against the corpus (docs/test-strategy.md §21). */
    public const ENTROPY_THRESHOLD = 3.5;

    private const ENTROPY_MIN_DIGITS = 3;

    public function detect(NormalizedText $text): array
    {
        $found = [];

        foreach (self::API_KEYS as $pattern) {
            array_push($found, ...$this->all(Rule::ApiKey, $pattern, $text));
        }

        array_push($found, ...$this->all(Rule::PrivateKey, self::PRIVATE_KEY, $text));
        array_push($found, ...$this->all(Rule::Token, self::BEARER, $text));
        array_push($found, ...$this->all(Rule::Token, self::JWT, $text, fn (string $match) => self::isJwt($match)));

        foreach ([self::PASSWORD_AFTER_SEPARATOR, self::PASSWORD_IN_SENTENCE] as $pattern) {
            array_push($found, ...$this->all(Rule::Password, $pattern, $text, fn (string $match) => self::isPassword($match)));
        }

        array_push($found, ...$this->all(Rule::Entropy, self::LONG_TOKEN, $text, fn (string $match) => self::looksRandom($match)));

        return $found;
    }

    /**
     * @return list<Detection>
     */
    private function all(Rule $rule, string $pattern, NormalizedText $text, ?\Closure $accept = null): array
    {
        $found = [];

        foreach (Pattern::matches($pattern, $text->text) as [$match, $offset]) {
            if ($accept === null || $accept($match)) {
                [$start, $end] = $text->sourceSpan($offset, $offset + strlen($match));
                $found[] = new Detection($rule, $start, $end);
            }
        }

        return $found;
    }

    /**
     * The first part decodes to a JSON object with an algorithm: that is the structure of a JWT.
     */
    private static function isJwt(string $match): bool
    {
        $header = base64_decode(strtr(explode('.', $match)[0], '-_', '+/'), true);
        $decoded = is_string($header) ? json_decode($header, true) : null;

        return is_array($decoded) && isset($decoded['alg']);
    }

    private static function isPassword(string $match): bool
    {
        return preg_match(self::NOT_A_PASSWORD, $match) !== 1
            && preg_match(self::NOT_A_PASSWORD, rtrim($match, '",.;:)}\'')) !== 1;
    }

    /**
     * Random strings mix letters and several digits. Long words joined by hyphens or underscores, even
     * with a version at the end, do not.
     */
    private static function looksRandom(string $token): bool
    {
        if (preg_match_all('/[0-9]/', $token) < self::ENTROPY_MIN_DIGITS || preg_match('/[A-Za-z]/', $token) !== 1) {
            return false;
        }

        return self::entropy($token) >= self::ENTROPY_THRESHOLD;
    }

    private static function entropy(string $token): float
    {
        $length = strlen($token);
        $entropy = 0.0;

        foreach (count_chars($token, 1) as $count) {
            $share = $count / $length;
            $entropy -= $share * log($share, 2);
        }

        return $entropy;
    }
}
