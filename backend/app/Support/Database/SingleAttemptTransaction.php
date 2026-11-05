<?php

namespace App\Support\Database;

use Closure;
use Illuminate\Database\Connection;
use Throwable;

/**
 * One attempt, and the first failure survives. Connection::transaction() throws whatever rollBack()
 * throws in place of what went wrong, so a lock timeout on a connection that then died would be
 * reported as a lost connection (docs/security-design.md §16.5.1, §16.5.6).
 */
final class SingleAttemptTransaction
{
    /**
     * @template TReturn
     *
     * @param  Closure(Connection): TReturn  $callback
     * @return TReturn
     */
    public static function run(Connection $connection, Closure $callback): mixed
    {
        $first = null;

        try {
            return $connection->transaction(function (Connection $db) use ($callback, &$first) {
                try {
                    return $callback($db);
                } catch (Throwable $exception) {
                    $first = $exception;

                    throw $exception;
                }
            }, 1);
        } catch (Throwable $thrown) {
            // Set by reference inside the closure, which the analyser cannot see.
            throw $first ?? $thrown; // @phpstan-ignore nullCoalesce.variable
        }
    }
}
