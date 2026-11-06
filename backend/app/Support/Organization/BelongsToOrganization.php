<?php

namespace App\Support\Organization;

use Illuminate\Database\Eloquent\Model;
use LogicException;

/**
 * Every query is limited to the current organization, and a new row belongs to it. Moving a row to
 * another organization is refused here and by the column privileges in the database.
 *
 * @phpstan-require-extends Model
 */
trait BelongsToOrganization
{
    public static function bootBelongsToOrganization(): void
    {
        static::addGlobalScope(new OrganizationScope);

        static::creating(function (Model $model): void {
            $organizationId = app(OrganizationContext::class)->id();
            $given = $model->getAttribute('organization_id');

            if ($given !== null && $given !== $organizationId) {
                throw new LogicException('A row cannot be created for another organization.');
            }

            $model->setAttribute('organization_id', $organizationId);
        });

        static::updating(function (Model $model): void {
            if ($model->isDirty('organization_id')) {
                throw new LogicException('A row cannot move to another organization.');
            }
        });
    }
}
