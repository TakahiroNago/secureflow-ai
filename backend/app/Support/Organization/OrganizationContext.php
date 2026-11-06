<?php

namespace App\Support\Organization;

use Closure;

/**
 * The organization this request or job works for. It is set from the authenticated user or, in a job,
 * explicitly, and never from request data. Without it, tenant models refuse to run any query: an
 * unscoped query would otherwise return every organization's rows.
 */
final class OrganizationContext
{
    private ?string $organizationId = null;

    public function set(string $organizationId): void
    {
        $this->organizationId = $organizationId;
    }

    /**
     * @throws MissingOrganizationContextException
     */
    public function id(): string
    {
        return $this->organizationId ?? throw new MissingOrganizationContextException('No organization context.');
    }

    /**
     * @template TReturn
     *
     * @param  Closure(): TReturn  $callback
     * @return TReturn
     */
    public function run(string $organizationId, Closure $callback): mixed
    {
        $previous = $this->organizationId;
        $this->organizationId = $organizationId;

        try {
            return $callback();
        } finally {
            $this->organizationId = $previous;
        }
    }
}
