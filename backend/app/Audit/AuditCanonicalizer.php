<?php

namespace App\Audit;

use JsonException;

/**
 * The hash specification secureflow.audit.v1 in PHP (docs/database-design.md §3.12.3), written
 * independently of the database function. Fixed test vectors keep the two together.
 */
final class AuditCanonicalizer
{
    public const SYSTEM_CHAIN = '00000000-0000-0000-0000-000000000000';

    public const GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';

    private const JSON_FLAGS = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR;

    /**
     * @param  list<?string>  $fields  The 16 fields in specification order.
     */
    public static function hash(array $fields): string
    {
        return hash('sha256', self::canonical($fields));
    }

    /**
     * @param  list<?string>  $fields
     */
    public static function canonical(array $fields): string
    {
        return 'secureflow.audit.v1|'.implode('|', array_map(
            fn (?string $value) => $value === null ? '-' : strlen($value).':'.$value,
            $fields,
        ));
    }

    /**
     * The canonical JSON is built from the decoded value, not taken from the database's text, so a
     * change in how PostgreSQL renders jsonb cannot affect rows written earlier.
     *
     * @throws JsonException
     */
    public static function metadata(string $json): string
    {
        $decoded = json_decode($json, true, 8, JSON_THROW_ON_ERROR);

        if (! is_array($decoded) || $decoded === []) {
            return '{}';
        }

        $keys = array_map('strval', array_keys($decoded));
        usort($keys, fn (string $a, string $b) => (strlen($a) <=> strlen($b)) ?: strcmp($a, $b));

        return '{'.implode(', ', array_map(
            fn (string $key) => json_encode($key, self::JSON_FLAGS).': '.json_encode($decoded[$key], self::JSON_FLAGS),
            $keys,
        )).'}';
    }
}
