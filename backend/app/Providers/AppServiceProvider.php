<?php

namespace App\Providers;

use App\Audit\AuditLogger;
use App\Audit\DatabaseTransactionBoundary;
use App\Audit\TransactionBoundary;
use App\Domain\Auth\PendingFingerprintStore;
use App\Domain\Auth\RedisPendingFingerprintStore;
use App\Domain\Auth\RedisRetiredSessions;
use App\Domain\Auth\RetiredSessions;
use App\Http\Middleware\StartSessionUnlessRetired;
use App\Models\User;
use App\Support\Database\DatabaseCommandPolicy;
use App\Support\Database\SingleConnectPostgresConnection;
use App\Support\Database\TcpTimeoutPostgresConnector;
use App\Support\Session\RetirementAwareSessionHandler;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Cache\RedisStore;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Session\SessionManager;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\ServiceProvider;
use Laravel\Sanctum\Sanctum;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->singleton(RetiredSessions::class, RedisRetiredSessions::class);

        // Sanctum resolves this class by name, so this also covers its session middleware.
        $this->app->singleton(StartSession::class, fn ($app) => new StartSessionUnlessRetired(
            $app->make(SessionManager::class),
            fn () => $app->make(CacheFactory::class),
        ));

        Connection::resolverFor('pgsql', fn ($pdo, $database, $prefix, $config) => new SingleConnectPostgresConnection($pdo, $database, $prefix, $config));

        $this->app->bind(TransactionBoundary::class, DatabaseTransactionBoundary::class);
        $this->app->scoped(PendingFingerprintStore::class, RedisPendingFingerprintStore::class);
        $this->app->scoped(AuditLogger::class);
        $this->app->bind('db.connector.pgsql', TcpTimeoutPostgresConnector::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // As SessionManager::createRedisDriver() builds it, with the write that refuses a retired id.
        Session::extend('redis', function (Application $app) {
            $repository = clone $app->make('cache')->store(config('session.store') ?: 'redis');
            /** @var RedisStore $store */
            $store = $repository->getStore();
            $store->setConnection(config()->string('session.connection'));

            return new RetirementAwareSessionHandler($repository, config()->integer('session.lifetime'));
        });

        if ($this->app->runningInConsole()) {
            DatabaseCommandPolicy::apply($this->app->environment());
        }

        // Cookie sessions only. There is no personal_access_tokens table, and a bearer token must
        // simply be unauthenticated rather than reach a query on a table that does not exist.
        Sanctum::getAccessTokenFromRequestUsing(fn (): ?string => null);

        Event::listen([TransactionCommitted::class, TransactionRolledBack::class], function (): void {
            app(AuditLogger::class)->transactionEnded();
        });

        // $request->ip() does not trust X-Forwarded-For, because no proxy is configured as trusted.
        // In the current setup every client through the published port has the same address, so the
        // address limit works as a total for all users, not per user (docs/security-design.md §16.5.4).
        RateLimiter::for('login', function (Request $request): array {
            $email = $request->input('email');
            $ip = (string) $request->ip();

            return [
                Limit::perMinute(5)->by(hash('sha256', mb_strtolower(is_string($email) ? $email : '').'|'.$ip)),
                Limit::perMinute(config()->integer('audit.login_ip_limit_per_minute'))->by('ip|'.$this->addressKey($ip)),
            ];
        });

        RateLimiter::for('account-password', function (Request $request): Limit {
            $user = $request->user();

            return Limit::perMinute(5)->by($user instanceof User ? $user->id : (string) $request->ip());
        });
    }

    /**
     * An IPv6 client usually controls a whole /64, so that is the unit limited.
     */
    private function addressKey(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return $ip;
        }

        $packed = (string) inet_pton($ip);

        return bin2hex(substr($packed, 0, 8));
    }
}
