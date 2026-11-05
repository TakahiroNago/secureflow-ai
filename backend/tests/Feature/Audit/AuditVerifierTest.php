<?php

use App\Audit\AuditAvailability;
use App\Audit\AuditCanonicalizer;
use App\Audit\AuditChainVerifier;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Models\User;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Database\QueryException;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Str;
use Tests\Support\FailingAuditWriter;

/*
| AUDIT-VERIFY-01, AUDIT-VERIFY-02, AUDIT-CMD-01, AUDIT-VFAIL-01, AUDIT-CONC-01.
| Real commits: the verifier reads its own snapshot on its own connection, so this file cannot use
| DatabaseTransactions. Each test starts from empty tables and leaves them empty.
*/

beforeEach(function () {
    resetAuditTables();
    $this->organization = insertOrganization(appDb());
    foreach (range(1, 5) as $i) {
        appendAudit(['organization' => $this->organization, 'metadata' => '{"n":'.$i.'}', 'ip' => '203.0.113.'.$i]);
    }
    appendAudit();
});

afterEach(function () {
    resetAuditTables();
    ownerDb()->table('organizations')->where('id', $this->organization)->delete();
});

function verifyOrganization(?array $anchor = null): array
{
    return app(AuditChainVerifier::class)->verify(test()->organization, $anchor);
}

/** Runs tampering statements the way someone with the owner role could. */
function tamper(string ...$statements): void
{
    $db = ownerDb();
    $db->statement('ALTER TABLE audit_logs DISABLE TRIGGER USER');
    $db->statement('ALTER TABLE audit_chain_heads DISABLE TRIGGER USER');
    foreach ($statements as $statement) {
        $db->statement(str_replace(':org', test()->organization, $statement));
    }
    $db->statement('ALTER TABLE audit_logs ENABLE TRIGGER USER');
    $db->statement('ALTER TABLE audit_chain_heads ENABLE TRIGGER USER');
}

function currentHead(): array
{
    $head = appDb()->table('audit_chain_heads')->where('chain_id', test()->organization)->first();

    return ['last_seq' => (int) $head->last_seq, 'last_hash' => (string) $head->last_hash];
}

it('AUDIT-VERIFY-01: accepts an untouched chain, and the rows PHP recomputes match the database', function () {
    $result = verifyOrganization();

    expect($result)->toMatchArray(['valid' => true, 'checked_count' => 5, 'first_broken_seq' => null, 'reason_code' => null]);
});

it('AUDIT-VERIFY-01: accepts an empty chain', function () {
    $empty = insertOrganization(appDb());

    expect(app(AuditChainVerifier::class)->verify($empty))->toMatchArray(['valid' => true, 'checked_count' => 0]);

    ownerDb()->table('organizations')->where('id', $empty)->delete();
});

it('AUDIT-VERIFY-01: finds each kind of tampering, and leaves other chains valid', function (array $statements, int $seq, string $reason) {
    tamper(...$statements);

    expect(verifyOrganization())->toMatchArray(['valid' => false, 'first_broken_seq' => $seq, 'reason_code' => $reason])
        ->and(app(AuditChainVerifier::class)->verify(AuditCanonicalizer::SYSTEM_CHAIN)['valid'])->toBeTrue();
})->with([
    'a value' => [["UPDATE audit_logs SET result = 'failure' WHERE chain_id = ':org' AND chain_seq = 3"], 3, 'HASH_MISMATCH'],
    'metadata' => [["UPDATE audit_logs SET metadata = '{\"n\":99}' WHERE chain_id = ':org' AND chain_seq = 3"], 3, 'HASH_MISMATCH'],
    'the time' => [["UPDATE audit_logs SET occurred_at = occurred_at + interval '1 second' WHERE chain_id = ':org' AND chain_seq = 3"], 3, 'HASH_MISMATCH'],
    'the event id' => [["UPDATE audit_logs SET event_id = gen_random_uuid() WHERE chain_id = ':org' AND chain_seq = 3"], 3, 'HASH_MISMATCH'],
    'the address' => [["UPDATE audit_logs SET ip_address = '198.51.100.1' WHERE chain_id = ':org' AND chain_seq = 3"], 3, 'HASH_MISMATCH'],
    'a middle row removed' => [["DELETE FROM audit_logs WHERE chain_id = ':org' AND chain_seq = 3"], 3, 'SEQUENCE_GAP'],
    'the last row removed' => [["DELETE FROM audit_logs WHERE chain_id = ':org' AND chain_seq = 5"], 5, 'HEAD_MISMATCH'],
    'the head moved' => [["UPDATE audit_chain_heads SET last_seq = 4 WHERE chain_id = ':org'"], 6, 'HEAD_MISMATCH'],
    'the head hash changed' => [["UPDATE audit_chain_heads SET last_hash = repeat('a', 64) WHERE chain_id = ':org'"], 6, 'HEAD_MISMATCH'],
    'the head removed' => [["DELETE FROM audit_chain_heads WHERE chain_id = ':org'"], 6, 'HEAD_MISSING'],
    'an unknown version' => [
        ['ALTER TABLE audit_logs DROP CONSTRAINT audit_logs_hash_version_known', "UPDATE audit_logs SET hash_version = 2 WHERE chain_id = ':org' AND chain_seq = 3"],
        3, 'UNSUPPORTED_VERSION',
    ],
]);

afterEach(function () {
    $exists = ownerDb()->selectOne("SELECT count(*) AS n FROM pg_constraint WHERE conname = 'audit_logs_hash_version_known'")->n;

    if ($exists === 0) {
        ownerDb()->statement('ALTER TABLE audit_logs ADD CONSTRAINT audit_logs_hash_version_known CHECK (hash_version = 1)');
    }
});

it('AUDIT-VERIFY-01: a row moved to another chain breaks both chains', function () {
    tamper("UPDATE audit_logs SET organization_id = NULL, chain_seq = 2 WHERE chain_id = ':org' AND chain_seq = 3");

    expect(verifyOrganization())->toMatchArray(['valid' => false, 'first_broken_seq' => 3, 'reason_code' => 'SEQUENCE_GAP'])
        ->and(app(AuditChainVerifier::class)->verify(AuditCanonicalizer::SYSTEM_CHAIN))->toMatchArray(['valid' => false, 'first_broken_seq' => 2]);
});

it('AUDIT-CHAIN-01: the order of id has no effect on verification', function () {
    tamper("UPDATE audit_logs SET id = DEFAULT WHERE chain_id = ':org' AND chain_seq = 2");

    $ids = appDb()->table('audit_logs')->where('chain_id', $this->organization)->orderBy('chain_seq')->pluck('id')->all();

    expect($ids[1])->toBeGreaterThan($ids[2])
        ->and(verifyOrganization()['valid'])->toBeTrue();
});

it('AUDIT-SYS-02: the verifier reports suppressed events and stays valid', function () {
    appendAudit(['organization' => $this->organization, 'type' => 'audit.events_suppressed', 'metadata' => '{"suppressed_count":3}']);

    expect(verifyOrganization())->toMatchArray(['valid' => true, 'suppressed_events' => 1]);
});

it('AUDIT-VERIFY-01: finds a network mask, which the host form would hide', function () {
    $row = appDb()->selectOne('SELECT host(ip_address) AS ip FROM audit_logs WHERE chain_id = ? AND chain_seq = 3', [$this->organization]);

    tamper(
        'ALTER TABLE audit_logs DROP CONSTRAINT audit_logs_ip_is_host',
        "UPDATE audit_logs SET ip_address = '{$row->ip}/24' WHERE chain_id = ':org' AND chain_seq = 3",
    );

    try {
        expect(verifyOrganization())->toMatchArray(['valid' => false, 'first_broken_seq' => 3, 'reason_code' => 'NON_CANONICAL_VALUE']);
    } finally {
        resetAuditTables();
        ownerDb()->statement('ALTER TABLE audit_logs ADD CONSTRAINT audit_logs_ip_is_host CHECK (ip_address IS NULL OR masklen(ip_address) = CASE family(ip_address) WHEN 4 THEN 32 ELSE 128 END)');
    }
});

it('AUDIT-VERIFY-02: cannot see a removed tail with a rewound head, unless a head was stored earlier', function () {
    $stored = currentHead();
    $previous = appDb()->table('audit_logs')->where('chain_id', $this->organization)->where('chain_seq', 4)->value('hash');

    tamper(
        "DELETE FROM audit_logs WHERE chain_id = ':org' AND chain_seq = 5",
        "UPDATE audit_chain_heads SET last_seq = 4, last_hash = '{$previous}' WHERE chain_id = ':org'",
    );

    expect(verifyOrganization()['valid'])->toBeTrue()
        ->and(verifyOrganization($stored))->toMatchArray(['valid' => false, 'first_broken_seq' => 5, 'reason_code' => 'ANCHOR_MISMATCH']);
});

it('AUDIT-VERIFY-02: cannot see a fully recomputed chain, unless a head was stored earlier', function () {
    $stored = currentHead();

    // Rewrites every row with correct hashes, as the owner can.
    $rows = appDb()->table('audit_logs')->where('chain_id', $this->organization)->orderBy('chain_seq')->get();
    $previous = AuditCanonicalizer::GENESIS;
    $statements = [];
    foreach ($rows as $row) {
        $full = appDb()->selectOne(
            "SELECT host(ip_address) AS ip, to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS at FROM audit_logs WHERE id = ?",
            [$row->id],
        );
        $hash = AuditCanonicalizer::hash([
            $row->chain_id, (string) $row->chain_seq, $previous, $row->event_id, $row->organization_id, $row->actor_type,
            $row->actor_user_id, $row->event_type, $row->resource_type, $row->resource_id, 'denied', $row->severity,
            $full->ip, $row->request_id, AuditCanonicalizer::metadata((string) $row->metadata), $full->at,
        ]);
        $statements[] = "UPDATE audit_logs SET result = 'denied', prev_hash = '{$previous}', hash = '{$hash}' WHERE id = {$row->id}";
        $previous = $hash;
    }
    $statements[] = "UPDATE audit_chain_heads SET last_hash = '{$previous}' WHERE chain_id = ':org'";
    tamper(...$statements);

    expect(verifyOrganization()['valid'])->toBeTrue()
        ->and(verifyOrganization($stored))->toMatchArray(['valid' => false, 'reason_code' => 'ANCHOR_MISMATCH']);
});

it('AUDIT-VERIFY-01: accepts an anchor from earlier in a chain that has grown', function () {
    $stored = currentHead();
    appendAudit(['organization' => $this->organization]);

    expect(verifyOrganization($stored)['valid'])->toBeTrue();
});

// ---- commands -----------------------------------------------------------------------------------

it('AUDIT-CMD-01: audit:verify exits 0 on valid chains', function () {
    expect(Artisan::call('audit:verify', ['--all' => true]))->toBe(0)
        ->and(Artisan::output())->toContain('"valid":true');
});

it('AUDIT-CMD-01: audit:verify needs a target and exits 2 when it cannot run', function () {
    expect(Artisan::call('audit:verify'))->toBe(2);

    config(['database.connections.pgsql_audit_read.port' => 1]);
    DB::purge('pgsql_audit_read');

    expect(Artisan::call('audit:verify', ['--all' => true]))->toBe(2);
});

it('AUDIT-CMD-01: audit:head prints what audit:verify can check against', function () {
    expect(Artisan::call('audit:head', ['--all' => true]))->toBe(0);

    $lines = array_values(array_filter(explode("\n", Artisan::output())));
    $file = tempnam(sys_get_temp_dir(), 'anchor');
    file_put_contents($file, implode("\n", $lines));

    expect($lines)->toHaveCount(2)
        ->and(json_decode($lines[0], true))->toHaveKeys(['hash_version', 'chain_id', 'last_seq', 'last_hash', 'captured_at'])
        ->and(Artisan::call('audit:verify', ['--all' => true, '--anchor' => $file]))->toBe(0);

    tamper("DELETE FROM audit_logs WHERE chain_id = ':org' AND chain_seq = 5");
    tamper("UPDATE audit_chain_heads SET last_seq = 4, last_hash = (SELECT hash FROM audit_logs WHERE chain_id = ':org' AND chain_seq = 4) WHERE chain_id = ':org'");

    expect(Artisan::call('audit:verify', ['--all' => true]))->toBe(0)
        ->and(Artisan::call('audit:verify', ['--all' => true, '--anchor' => $file]))->toBe(1);

    unlink($file);
});

it('AUDIT-CMD-01: prints no row contents', function () {
    Artisan::call('audit:verify', ['--all' => true]);

    expect(Artisan::output())->not->toContain('203.0.113')->not->toContain('metadata');
});

it('AUDIT-VFAIL-01: repairs nothing, stops nothing, logs, and records one event', function () {
    tamper("UPDATE audit_logs SET result = 'failure' WHERE chain_id = ':org' AND chain_seq = 3");
    $logs = captureLogs();
    $before = appDb()->table('audit_logs')->where('chain_id', $this->organization)->pluck('hash')->all();

    expect(Artisan::call('audit:verify', ['--all' => true]))->toBe(1)
        ->and(appDb()->table('audit_logs')->where('chain_id', $this->organization)->pluck('hash')->all())->toBe($before)
        ->and(linesWithMetric($logs, 'audit.verification_failed'))->toHaveCount(1)
        ->and(appDb()->table('audit_logs')->where('event_type', 'audit.verification_failed')->count())->toBe(1)
        ->and(appendAudit(['organization' => $this->organization]))->toBe(6);
});

it('AUDIT-VFAIL-01: keeps the result when the event cannot be recorded, without recursion', function () {
    tamper("UPDATE audit_logs SET result = 'failure' WHERE chain_id = ':org' AND chain_seq = 3");
    $writer = new FailingAuditWriter('53100', 'ERROR: could not extend file');
    useAuditWriter($writer);

    expect(Artisan::call('audit:verify', ['--all' => true]))->toBe(1)
        ->and($writer->attempted)->toBe(['audit.verification_failed']);
});

// ---- real transactions --------------------------------------------------------------------------

it('AUDIT-TX-01: refuses the wrong kind of call, and rolls a record back with the business change', function () {
    $logger = app(AuditLogger::class);
    $entry = AuditEntry::system(AuditEventType::Locked);

    expect(fn () => $logger->recordInTransaction($entry, 'x'))->toThrow(LogicException::class);

    DB::transaction(fn () => expect(fn () => $logger->recordAfterTransaction($entry, 'x'))->toThrow(LogicException::class));

    $before = appDb()->table('audit_logs')->whereNull('organization_id')->count();

    try {
        DB::transaction(function () use ($logger, $entry) {
            $logger->recordInTransaction($entry, 'x');

            throw new RuntimeException('business failure');
        });
    } catch (RuntimeException) {
    }

    expect(appDb()->table('audit_logs')->whereNull('organization_id')->count())->toBe($before)
        ->and((int) appDb()->table('audit_chain_heads')->where('chain_id', AuditCanonicalizer::SYSTEM_CHAIN)->value('last_seq'))->toBe($before);

    expect($logger->recordAfterTransaction($entry, 'x'))->toBeTrue()
        ->and(appDb()->table('audit_logs')->whereNull('organization_id')->count())->toBe($before + 1);
});

it('AUDIT-TX-01: refuses a second chain in one transaction, and allows it in the next', function () {
    $logger = app(AuditLogger::class);
    $user = User::factory()->create(['organization_id' => $this->organization]);

    DB::transaction(function () use ($logger, $user) {
        $logger->recordInTransaction(AuditEntry::byUser(AuditEventType::Login, $user), 'x');

        expect(fn () => $logger->recordInTransaction(AuditEntry::system(AuditEventType::Locked), 'x'))->toThrow(LogicException::class);
    });

    DB::transaction(fn () => $logger->recordInTransaction(AuditEntry::system(AuditEventType::Locked), 'x'));

    ownerDb()->table('users')->where('id', $user->id)->delete();
});

it('AUDIT-CONC-01: lock_timeout fails the waiter with 55P03, other chains are not held up, the holder still commits', function () {
    $holder = ownerDb();
    $holder->beginTransaction();
    $holder->select('SELECT * FROM audit_chain_heads WHERE chain_id = ? FOR UPDATE', [$this->organization]);

    try {
        $start = hrtime(true);
        $error = dbError(appDb(), fn () => appendAudit(['organization' => $this->organization]));
        $elapsed = (hrtime(true) - $start) / 1e9;

        expect(sqlStateFrom($error))->toBe('55P03')
            ->and($elapsed)->toBeGreaterThan(1.5)->toBeLessThan(4.0);

        $start = hrtime(true);
        appendAudit();
        expect((hrtime(true) - $start) / 1e9)->toBeLessThan(1.0);
    } finally {
        $holder->rollBack();
    }

    expect(appendAudit(['organization' => $this->organization]))->toBe(6);
});

it('AUDIT-CONC-01: appends from several processes stay gapless and verifiable', function () {
    $script = 'chdir("'.base_path().'"); require "vendor/autoload.php"; $a = require "bootstrap/app.php";'
        .' $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();'
        .' for ($i = 0; $i < 40; $i++) { Illuminate\Support\Facades\DB::selectOne("SELECT public.audit_append(gen_random_uuid(), ?::uuid, \'system\', NULL, \'test.event\', NULL, NULL, \'success\', NULL, NULL, NULL, \'{}\'::jsonb)", ["'.$this->organization.'"]); }';

    $results = Process::concurrently(function ($pool) use ($script) {
        foreach (range(1, 4) as $ignored) {
            $pool->path(base_path())->command(['php', '-r', $script]);
        }
    });

    foreach ($results as $result) {
        expect($result->successful())->toBeTrue();
    }

    $sequence = appDb()->table('audit_logs')->where('chain_id', $this->organization)->orderBy('chain_seq')->pluck('chain_seq')->all();

    expect($sequence)->toBe(range(1, 165))
        ->and(verifyOrganization())->toMatchArray(['valid' => true, 'checked_count' => 165]);
});

it('AUDIT-AVAIL-01: a role that lost EXECUTE gets 503 without a flag, and a real append marks the configuration', function () {
    $function = 'public.audit_append(uuid, uuid, text, uuid, text, text, uuid, text, text, inet, uuid, jsonb)';
    $role = '"'.config('database.connections.pgsql.username').'"';
    $availability = app(AuditAvailability::class);

    ownerDb()->statement("REVOKE EXECUTE ON FUNCTION {$function} FROM {$role}");

    try {
        expect(fn () => $availability->assertAvailable())->toThrow(ServiceUnavailableException::class)
            ->and($availability->auditState())->toBeNull()
            ->and($availability->dbFlagged())->toBeFalse()
            ->and(app(AuditLogger::class)->recordAfterTransaction(AuditEntry::system(AuditEventType::Locked), 'x'))->toBeFalse()
            ->and($availability->auditState())->toMatchArray(['failure_class' => 'permanent_config', 'storage_scope' => null]);
    } finally {
        ownerDb()->statement("GRANT EXECUTE ON FUNCTION {$function} TO {$role}");
    }
});

it('AUDIT-CONC-01: verification finds nothing wrong while another process appends', function () {
    $script = 'chdir("'.base_path().'"); require "vendor/autoload.php"; $a = require "bootstrap/app.php";'
        .' $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();'
        .' for ($i = 0; $i < 300; $i++) { Illuminate\Support\Facades\DB::selectOne("SELECT public.audit_append(gen_random_uuid(), ?::uuid, \'system\', NULL, \'test.event\', NULL, NULL, \'success\', NULL, NULL, NULL, \'{}\'::jsonb)", ["'.$this->organization.'"]); }';

    $process = Process::path(base_path())->start(['php', '-r', $script]);
    $runs = 0;

    while ($process->running() && $runs < 200) {
        expect(verifyOrganization()['valid'])->toBeTrue();
        $runs++;
    }

    expect($process->wait()->successful())->toBeTrue()
        ->and($runs)->toBeGreaterThan(0)
        ->and(verifyOrganization())->toMatchArray(['valid' => true, 'checked_count' => 305]);
});

it('AUDIT-STORAGE-01: 53100 from any other query changes no state, and is logged as a storage error', function () {
    $logs = captureLogs();
    $pdo = new PDOException('disk');
    $pdo->errorInfo = ['53100', 7, 'ERROR: could not write to file "base/pgsql_tmp/x": No space left on device'];

    report(new QueryException('pgsql', 'SELECT 1', [], $pdo));

    $availability = app(AuditAvailability::class);

    expect(linesWithMetric($logs, 'db.storage_error')[0]->context)->toMatchArray(['storage_area' => 'temp', 'sqlstate' => '53100'])
        ->and($availability->auditState())->toBeNull()
        ->and($availability->dbFlagged())->toBeFalse();
});

it('AUDIT-LOG: does not put a query failure message in the logs', function () {
    $logs = captureLogs();

    report(new QueryException('pgsql', 'UPDATE users SET password = ?', ['super-secret-hash-value'], new PDOException('SQLSTATE[08006] [7] connection failed')));

    $text = implode("\n", array_map(fn (MessageLogged $line) => $line->message.json_encode($line->context), (array) $logs));

    expect($text)->not->toContain('super-secret-hash-value')->toContain('Database query failed');
});

it('leaves AuditWriter as the only code that calls audit_append()', function () {
    $hits = [];

    foreach (File::allFiles(app_path()) as $file) {
        if (preg_match('/SELECT\s+public\.audit_append\(/', $file->getContents()) === 1) {
            $hits[] = $file->getFilename();
        }
    }

    expect($hits)->toBe(['AuditWriter.php'])
        ->and(Str::contains((string) file_get_contents(app_path('Audit/AuditWriter.php')), 'audit_append'))->toBeTrue();
});
