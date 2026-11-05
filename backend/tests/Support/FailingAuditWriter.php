<?php

namespace Tests\Support;

use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditWriter;
use Illuminate\Database\QueryException;
use PDOException;

/**
 * Fails like the driver does, with the errorInfo measured on the real stack.
 */
final class FailingAuditWriter extends AuditWriter
{
    /** @var list<string> */
    public array $attempted = [];

    /**
     * @param  list<AuditEventType>  $only  Empty means every event fails.
     */
    public function __construct(
        private readonly string $sqlState,
        private readonly string $message = 'ERROR: injected',
        private readonly array $only = [],
    ) {}

    public function append(AuditEntry $entry, ?string $ip, ?string $requestId): int
    {
        $this->attempted[] = $entry->type->value;

        if ($this->only !== [] && ! in_array($entry->type, $this->only, true)) {
            return parent::append($entry, $ip, $requestId);
        }

        $pdo = new PDOException('SQLSTATE['.$this->sqlState.']: '.$this->message);
        $pdo->errorInfo = [$this->sqlState, 7, $this->message];

        throw new QueryException('pgsql', 'SELECT public.audit_append()', [], $pdo);
    }
}
