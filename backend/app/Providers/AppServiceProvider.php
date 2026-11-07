<?php

namespace App\Providers;

use App\Ai\AiConfiguration;
use App\Ai\AiGateway;
use App\Ai\Contracts\AiProvider;
use App\Audit\AuditLogger;
use App\Audit\DatabaseTransactionBoundary;
use App\Audit\TransactionBoundary;
use App\Domain\Auth\PendingFingerprintStore;
use App\Domain\Auth\RedisPendingFingerprintStore;
use App\Domain\Auth\RedisRetiredSessions;
use App\Domain\Auth\RetiredSessions;
use App\Http\Middleware\StartSessionUnlessRetired;
use App\Models\AiAnalysisRequest;
use App\Models\User;
use App\Models\Workflow;
use App\Policies\AnalysisPolicy;
use App\Policies\WorkflowPolicy;
use App\Support\Database\DatabaseCommandPolicy;
use App\Support\Database\SingleConnectPostgresConnection;
use App\Support\Database\TcpTimeoutPostgresConnector;
use App\Support\Organization\OrganizationContext;
use App\Support\Session\RetirementAwareSessionHandler;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Cache\RedisStore;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Session\SessionManager;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
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
        $this->app->scoped(OrganizationContext::class);
        $this->app->bind('db.connector.pgsql', TcpTimeoutPostgresConnector::class);

        $this->app->bind(AiProvider::class, fn ($app) => AiConfiguration::provider(config()->string('ai.provider'), $app->environment()));
        $this->app->bind(AiGateway::class, fn ($app) => new AiGateway(
            $app->make(AiProvider::class),
            config()->integer('ai.timeout_seconds'),
            config()->integer('ai.max_output_tokens'),
        ));
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

        // Fails at start wherever the AI can be reached. Other commands still run, such as migrate during
        // an incident, and resolving a provider checks again, so none of them can reach it either.
        $assertAiConfiguration = fn () => AiConfiguration::assertValid(config()->string('ai.provider'), $this->app->environment());
        if (! $this->app->runningInConsole()) {
            $assertAiConfiguration();
        }
        Event::listen(CommandStarting::class, function (CommandStarting $event) use ($assertAiConfiguration): void {
            if (in_array($event->command, AiConfiguration::SERVING_COMMANDS, true)) {
                $assertAiConfiguration();
            }
        });

        Gate::policy(Workflow::class, WorkflowPolicy::class);
        Gate::policy(AiAnalysisRequest::class, AnalysisPolicy::class);

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

        RateLimiter::for('analyses', function (Request $request): Limit {
            $user = $request->user();

            return Limit::perMinute(10)->by($user instanceof User ? $user->id : (string) $request->ip());
        });

        RateLimiter::for('scan-preview', function (Request $request): Limit {
            $user = $request->user();

            return Limit::perMinute(10)->by($user instanceof User ? $user->id : (string) $request->ip());
        });

        // A provisional value, not measured. Every refusal here writes an audit record, so it bounds those too.
        RateLimiter::for('approval-decisions', function (Request $request): Limit {
            $user = $request->user();

            return Limit::perMinute(30)->by($user instanceof User ? $user->id : (string) $request->ip());
        });

        // The same reason, and the same provisional value.
        RateLimiter::for('execution-requests', function (Request $request): Limit {
            $user = $request->user();

            return Limit::perMinute(30)->by($user instanceof User ? $user->id : (string) $request->ip());
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
