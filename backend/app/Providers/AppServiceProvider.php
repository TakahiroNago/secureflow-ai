<?php

namespace App\Providers;

use App\Models\User;
use App\Support\Database\DatabaseCommandPolicy;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Laravel\Sanctum\Sanctum;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            DatabaseCommandPolicy::apply($this->app->environment());
        }

        // Cookie sessions only. There is no personal_access_tokens table, and a bearer token must
        // simply be unauthenticated rather than reach a query on a table that does not exist.
        Sanctum::getAccessTokenFromRequestUsing(fn (): ?string => null);

        // $request->ip() does not trust X-Forwarded-For, because no proxy is configured as trusted.
        RateLimiter::for('login', function (Request $request): Limit {
            $email = $request->input('email');

            return Limit::perMinute(5)->by(hash('sha256', mb_strtolower(is_string($email) ? $email : '').'|'.$request->ip()));
        });

        RateLimiter::for('account-password', function (Request $request): Limit {
            $user = $request->user();

            return Limit::perMinute(5)->by($user instanceof User ? $user->id : (string) $request->ip());
        });
    }
}
