<?php

namespace App\Events;

use App\Models\User;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * An account reached the failure limit. Nothing listens yet: audit recording is step 1-3.
 */
final class AccountLocked
{
    use Dispatchable;

    public function __construct(public readonly User $user) {}
}
