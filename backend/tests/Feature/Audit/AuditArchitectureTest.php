<?php

use App\Audit\AuditEntry;
use App\Audit\AuditLogger;
use App\Models\User;
use Illuminate\Support\Facades\File;

/*
| AUDIT-ACTOR-01 and the rules in docs/test-strategy.md §15 that are about the code itself.
*/

/**
 * @return list<SplFileInfo>
 */
function phpFilesIn(string $directory): array
{
    return array_values(array_filter(
        File::allFiles($directory),
        fn (SplFileInfo $file) => $file->getExtension() === 'php',
    ));
}

/**
 * @return list<string>
 */
function filesMatching(string $directory, string $pattern): array
{
    $hits = [];

    foreach (phpFilesIn($directory) as $file) {
        if (preg_match($pattern, (string) file_get_contents($file->getPathname())) === 1) {
            $hits[] = $file->getFilename();
        }
    }

    sort($hits);

    return $hits;
}

it('keeps tests out of the application', function () {
    expect(filesMatching(app_path(), '/\bTests\\\\/'))->toBe([]);
});

it('does not let the audit code ask which environment it is in', function () {
    expect(filesMatching(app_path('Audit'), '/APP_ENV|runningUnitTests|environment\(/'))->toBe([]);
});

it('AUDIT-ACTOR-01: the logger takes an entry, and an entry takes its actor from the model', function () {
    foreach (['recordInTransaction', 'recordAfterTransaction'] as $method) {
        $parameters = array_map(
            fn (ReflectionParameter $parameter) => (string) $parameter->getType(),
            (new ReflectionMethod(AuditLogger::class, $method))->getParameters(),
        );

        expect($parameters)->toBe([AuditEntry::class, 'string']);
    }

    expect((string) (new ReflectionMethod(AuditEntry::class, 'byUser'))->getParameters()[1]->getType())->toBe(User::class);
});

it('AUDIT-ACTOR-01: reaches the writer only from the audit code and the scheduled job', function () {
    expect(filesMatching(app_path(), '/\bAuditWriter\b/'))->toBe([
        'AuditAvailability.php',
        'AuditHousekeepingCommand.php',
        'AuditLogger.php',
        'AuditWriter.php',
        'DatabaseTransactionBoundary.php',
    ]);
});

it('AUDIT-CODE-01: opens write transactions only through the wrapper that keeps the first failure', function () {
    // The verifier is read-only and exits 2 whatever went wrong.
    expect(filesMatching(app_path(), '/(->|DB::)transaction\(/'))->toBe(['AuditChainVerifier.php', 'SingleAttemptTransaction.php']);
});

it('AUDIT-SYS-02: the limits can be changed from the environment', function () {
    $source = (string) file_get_contents(config_path('audit.php'));

    expect($source)->toContain("env('AUDIT_LOGIN_IP_LIMIT_PER_MINUTE'")
        ->toContain("env('AUDIT_SYSTEM_CHAIN_LIMIT_PER_MINUTE'");
});
