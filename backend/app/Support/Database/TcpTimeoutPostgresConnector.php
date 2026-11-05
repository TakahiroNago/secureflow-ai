<?php

namespace App\Support\Database;

use Illuminate\Database\Connectors\PostgresConnector;
use SensitiveParameter;
use Throwable;

/**
 * Laravel passes the keepalive settings but not tcp_user_timeout, which is the one that notices a
 * network loss while sending (measured: docs/security-design.md §16.5.6). It also connects once: a
 * second try right after a failed one only doubles the wait, and a caller that can retry does.
 */
final class TcpTimeoutPostgresConnector extends PostgresConnector
{
    /**
     * @param  array<string, mixed>  $config
     * @return string
     */
    protected function getDsn(array $config)
    {
        $dsn = parent::getDsn($config);

        return is_numeric($config['tcp_user_timeout'] ?? null)
            ? $dsn.';tcp_user_timeout='.(int) $config['tcp_user_timeout']
            : $dsn;
    }

    /**
     * @param  string  $dsn
     * @param  string  $username
     * @param  string  $password
     * @param  array<int, mixed>  $options
     * @return \PDO
     */
    protected function tryAgainIfCausedByLostConnection(Throwable $e, $dsn, $username, #[SensitiveParameter] $password, $options)
    {
        throw $e;
    }
}
