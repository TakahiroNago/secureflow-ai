<?php

namespace Tests;

use App\Audit\AuditLogger;
use App\Audit\AuditWriter;
use App\Audit\TransactionBoundary;
use App\Domain\Auth\PendingFingerprintStore;
use App\Domain\Auth\RetiredSessions;
use App\Support\Database\TestDatabaseGuard;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use RuntimeException;
use Tests\Support\ArrayPendingFingerprintStore;
use Tests\Support\ArrayRetiredSessions;
use Tests\Support\TestTransactionBoundary;

abstract class TestCase extends BaseTestCase
{
    /**
     * Rolled back after tests that use DatabaseTransactions.
     *
     * @var list<string>
     */
    protected array $connectionsToTransact = [
        TestDatabaseGuard::APP_CONNECTION,
        TestDatabaseGuard::OWNER_CONNECTION,
    ];

    private static bool $schemaReady = false;

    private string $logStateDirectory;

    protected function setUp(): void
    {
        parent::setUp();

        // After DatabaseTransactions has opened its transaction, so that one does not count as
        // business work. Tests without the trait get base 0, which is what production sees.
        $this->app->instance(TransactionBoundary::class, new TestTransactionBoundary(
            DB::connection(AuditWriter::CONNECTION)->transactionLevel(),
        ));
        $this->app->forgetInstance(AuditLogger::class);

        $this->app->instance(PendingFingerprintStore::class, new ArrayPendingFingerprintStore);
        $this->app->instance(RetiredSessions::class, new ArrayRetiredSessions);

        $this->logStateDirectory = sys_get_temp_dir().'/secureflow-test-log-state-'.uniqid('', true);
        config(['audit.log_state_directory' => $this->logStateDirectory]);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->logStateDirectory);

        parent::tearDown();
    }

    /**
     * Runs before DatabaseTransactions opens its transactions.
     *
     * @return array<class-string, class-string>
     */
    protected function setUpTraits()
    {
        // Tests must never touch anything but the test database (docs/database-design.md §4.6).
        $violations = TestDatabaseGuard::configViolations();
        if ($violations !== []) {
            throw new RuntimeException('Test database guard: '.implode('; ', $violations));
        }

        if (! self::$schemaReady) {
            TestDatabaseGuard::assertSafe();

            // The owner builds the schema once per run; test queries use the application role.
            $status = Artisan::call('migrate:fresh', [
                '--database' => TestDatabaseGuard::OWNER_CONNECTION,
                '--force' => true,
            ]);
            if ($status !== 0) {
                throw new RuntimeException('Could not build the test schema: '.Artisan::output());
            }

            self::$schemaReady = true;
        }

        return parent::setUpTraits();
    }
}
