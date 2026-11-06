<?php

namespace Tests\Support;

/**
 * Secrets for tests, built when they run, so that the repository holds nothing shaped like one for secret
 * scanners to find (docs/test-strategy.md §21). A fixed seed keeps a failure repeatable.
 */
final class FakeSecrets
{
    private const ALPHANUMERIC = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ0123456789';

    public static function random(int $length, string $alphabet = self::ALPHANUMERIC): string
    {
        $out = '';
        for ($i = 0; $i < $length; $i++) {
            $out .= $alphabet[mt_rand(0, strlen($alphabet) - 1)];
        }

        return $out;
    }

    public static function apiKey(string $kind): string
    {
        return match ($kind) {
            'openai' => 's'.'k-'.self::random(10).'7'.self::random(30),
            'openai-project' => 's'.'k-proj-'.self::random(10).'7'.self::random(40),
            'aws' => 'AK'.'IA'.self::random(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'),
            'google' => 'AI'.'za'.self::random(35),
            'github' => 'gh'.'p_'.self::random(36),
            'github-fine' => 'github'.'_pat_'.self::random(40),
            'slack' => 'xo'.'xb-'.mt_rand(1000000, 9999999).'-'.self::random(20),
        };
    }

    public static function jwt(): string
    {
        $part = fn (string $json) => rtrim(strtr(base64_encode($json), '+/', '-_'), '=');

        return $part('{"alg":"HS256","typ":"JWT"}').'.'.$part('{"sub":"'.self::random(8).'"}').'.'.self::random(43);
    }

    public static function bearer(): string
    {
        return 'Bearer '.self::random(40);
    }

    public static function privateKey(string $type = 'RSA '): string
    {
        $dashes = str_repeat('-', 5);

        return $dashes.'BEGIN '.$type.'PRIVATE KEY'.$dashes."\n".self::random(64)."\n".self::random(64)."\n".$dashes.'END '.$type.'PRIVATE KEY'.$dashes;
    }

    public static function password(): string
    {
        return self::random(6).'#'.mt_rand(10, 99);
    }

    public static function highEntropy(): string
    {
        return self::random(16, '0123456789abcdef').self::random(24);
    }

    public static function card(int $digits = 16, string $prefix = '4'): string
    {
        $number = $prefix.self::random($digits - strlen($prefix) - 1, '0123456789');

        foreach (range(0, 9) as $check) {
            if (self::luhn($number.$check)) {
                return $number.$check;
            }
        }

        return $number;
    }

    public static function myNumber(): string
    {
        $base = self::random(11, '0123456789');
        $sum = 0;

        for ($n = 1; $n <= 11; $n++) {
            $sum += (int) $base[11 - $n] * ($n <= 6 ? $n + 1 : $n - 5);
        }

        $remainder = $sum % 11;

        return $base.($remainder <= 1 ? 0 : 11 - $remainder);
    }

    /**
     * The placeholders in resources/security/corpus.
     */
    public static function expand(string $template): string
    {
        return (string) preg_replace_callback('/\{\{([A-Z_]+)(?::([a-z-]+))?\}\}/', fn (array $m) => match ($m[1]) {
            'APIKEY' => self::apiKey($m[2] ?? 'openai'),
            'JWT' => self::jwt(),
            'BEARER' => self::bearer(),
            'PRIVKEY' => self::privateKey(),
            'PRIVKEY_OPENSSH' => self::privateKey('OPENSSH '),
            'PASSWORD' => self::password(),
            'ENTROPY' => self::highEntropy(),
            'CARD' => self::card(),
            'CARD_SPACED' => implode(' ', str_split(self::card(), 4)),
            'CARD_DASHED' => implode('-', str_split(self::card(), 4)),
            'AMEX' => self::card(15, '37'),
            'MYNUMBER' => self::myNumber(),
            'MYNUMBER_DASHED' => implode('-', str_split(self::myNumber(), 4)),
        }, $template);
    }

    private static function luhn(string $digits): bool
    {
        $sum = 0;
        $double = false;

        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
            $digit = (int) $digits[$i] * ($double ? 2 : 1);
            $sum += $digit > 9 ? $digit - 9 : $digit;
            $double = ! $double;
        }

        return $sum % 10 === 0;
    }
}
