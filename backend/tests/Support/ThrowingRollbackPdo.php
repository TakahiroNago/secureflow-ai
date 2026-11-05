<?php

namespace Tests\Support;

use PDO;
use PDOException;

/**
 * Rolls back for real, then fails the way a connection that just died does. A real dead connection
 * does not reliably reach rollBack(): PDO may report that no transaction is active.
 */
final class ThrowingRollbackPdo extends PDO
{
    public function rollBack(): bool
    {
        parent::rollBack();

        $exception = new PDOException('SQLSTATE[HY000]: General error: 7 no connection to the server');
        $exception->errorInfo = ['HY000', 7, 'no connection to the server'];

        throw $exception;
    }
}
