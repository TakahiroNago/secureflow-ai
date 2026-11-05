<?php

namespace App\Support\Database;

use Closure;
use Illuminate\Database\PostgresConnection;
use Illuminate\Database\QueryException;
use Throwable;

/**
 * A connection that was never established is not a lost one. The framework treats a failed connect
 * like a lost connection and tries again here, on top of the connector's own retry: four attempts
 * for one statement, 12.5s with a name that takes 3.1s to fail (docs/security-design.md §16.5.1).
 * A connection that really was lost keeps the framework's behaviour.
 */
final class SingleConnectPostgresConnection extends PostgresConnection
{
    /**
     * @param  string  $query
     * @param  array<array-key, mixed>  $bindings
     */
    protected function handleQueryException(QueryException $e, $query, $bindings, Closure $callback)
    {
        if ($this->neverConnected()) {
            throw $e;
        }

        return parent::handleQueryException($e, $query, $bindings, $callback);
    }

    /**
     * @return void
     */
    protected function handleBeginTransactionException(Throwable $e)
    {
        if ($this->neverConnected()) {
            throw $e;
        }

        parent::handleBeginTransactionException($e);
    }

    private function neverConnected(): bool
    {
        return $this->getRawPdo() instanceof Closure;
    }
}
