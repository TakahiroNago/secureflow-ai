<?php

namespace App\Audit;

use Illuminate\Database\QueryException;
use PDOException;
use Throwable;

/**
 * Classifies a database failure. The state decisions use errorInfo[0] only. The driver text feeds
 * `cause` and `storage_area`, which are log fields: a changed message can only make them "unknown".
 * getCode() is not used, because a connection failure returns the integer 7.
 */
final readonly class AuditFailure
{
    public const STORAGE = 'storage';

    public const PERMANENT_CONFIG = 'permanent_config';

    public const TRANSIENT = 'transient';

    public const CONNECTION = 'connection';

    public const UNCLASSIFIED = 'unclassified';

    private const CAUSES = [
        'Connection refused' => 'connection_refused',
        'the database system is shutting down' => 'server_stopping',
        'could not translate host name' => 'name_resolution',
        'timeout expired' => 'connect_timeout',
        'too many connections for role' => 'connection_limit',
        'remaining connection slots are reserved' => 'connection_limit',
        'password authentication failed' => 'auth_failed',
        'is not permitted to log in' => 'access_denied',
        'pg_hba.conf rejects connection' => 'access_denied',
        'permission denied for database' => 'access_denied',
        'does not exist' => 'config_invalid',
        'server does not support SSL' => 'config_invalid',
        'invalid sslmode value' => 'config_invalid',
        'invalid integer value' => 'config_invalid',
        'PANIC:' => 'server_panic',
        'terminating connection due to administrator command' => 'admin_terminated',
        'terminating connection due to idle-in-transaction timeout' => 'idle_timeout',
        'terminating connection due to transaction timeout' => 'idle_timeout',
        'server closed the connection unexpectedly' => 'server_closed',
        'could not receive data from server' => 'network_timeout',
        'no connection to the server' => 'no_connection',
    ];

    private function __construct(
        public ?string $sqlState,
        public string $class,
        public string $cause,
        public string $storageArea,
    ) {}

    public static function from(Throwable $exception): self
    {
        [$state, $message] = self::errorInfo($exception);

        return new self($state, self::classOf($state), self::causeOf($message), self::storageAreaOf($message));
    }

    public function isConnection(): bool
    {
        return $this->class === self::CONNECTION;
    }

    public function makesAuditUnavailable(): bool
    {
        return $this->class === self::STORAGE || $this->class === self::PERMANENT_CONFIG;
    }

    /**
     * @return array{0: ?string, 1: string}
     */
    private static function errorInfo(Throwable $exception): array
    {
        $pdo = $exception instanceof QueryException ? $exception->getPrevious() : $exception;

        if (! $pdo instanceof PDOException) {
            return [null, ''];
        }

        $info = $pdo->errorInfo ?? [];

        return [isset($info[0]) ? (string) $info[0] : null, isset($info[2]) ? (string) $info[2] : ''];
    }

    private static function classOf(?string $state): string
    {
        return match ($state) {
            '53100' => self::STORAGE,
            '42501', '42883', '42P01', '25006' => self::PERMANENT_CONFIG,
            '55P03', '57014' => self::TRANSIENT,
            '08006', 'HY000' => self::CONNECTION,
            default => self::UNCLASSIFIED,
        };
    }

    private static function causeOf(string $message): string
    {
        foreach (self::CAUSES as $text => $cause) {
            if (str_contains($message, $text)) {
                return $cause;
            }
        }

        return 'unknown';
    }

    private static function storageAreaOf(string $message): string
    {
        return match (true) {
            str_contains($message, 'pgsql_tmp') => 'temp',
            str_contains($message, 'pg_wal') => 'wal',
            str_contains($message, 'could not extend file') => 'table',
            default => 'unknown',
        };
    }
}
