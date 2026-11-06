<?php

namespace App\Support\Organization;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;

/**
 * docs/security-design.md §13. Throws without a context instead of leaving the query unscoped.
 *
 * @implements Scope<Model>
 */
final class OrganizationScope implements Scope
{
    /**
     * @param  Builder<covariant Model>  $builder
     */
    public function apply(Builder $builder, Model $model): void
    {
        $builder->where($model->qualifyColumn('organization_id'), app(OrganizationContext::class)->id());
    }
}
