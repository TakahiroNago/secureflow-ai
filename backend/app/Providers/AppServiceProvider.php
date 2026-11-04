<?php

namespace App\Providers;

use App\Support\Database\DatabaseCommandPolicy;
use Illuminate\Support\ServiceProvider;

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

        //
    }
}
