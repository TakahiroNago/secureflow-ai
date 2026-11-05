<?php

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Str;

/*
| The database half of step 1-3: AUDIT-PRIV-01, AUDIT-FN-01, AUDIT-META-01, AUDIT-HASH-01,
| AUDIT-CHAIN-01 and the SF001 part of AUDIT-RECOVER-01. docs/database-design.md §3.12.
*/

uses(DatabaseTransactions::class);

const AUDIT_APPEND = 'public.audit_append(uuid, uuid, text, uuid, text, text, uuid, text, text, inet, uuid, jsonb)';
const AUDIT_HELPERS = [
    'public.audit_canonical(uuid, bigint, text, uuid, uuid, text, uuid, text, text, uuid, text, text, inet, uuid, jsonb, timestamptz)',
    'public.audit_field(text)',
    'public.audit_metadata_is_valid(jsonb)',
    'public.audit_chain_heads_guard()',
];
const NIL_UUID = '00000000-0000-0000-0000-000000000000';

function appendError(array $overrides): ?QueryException
{
    return dbError(appDb(), fn () => appendAudit($overrides));
}

// ---- AUDIT-PRIV-01, AUDIT-FN-01: the function ---------------------------------------------------

it('AUDIT-PRIV-01: lets the application role run audit_append() and none of the helpers', function () {
    $can = fn (string $function) => appDb()->selectOne("SELECT has_function_privilege(current_user, ?, 'EXECUTE') AS granted", [$function])->granted;

    expect($can(AUDIT_APPEND))->toBeTrue();

    foreach (AUDIT_HELPERS as $helper) {
        expect($can($helper))->toBeFalse($helper);
    }
});

it('AUDIT-PRIV-01: gives PUBLIC no EXECUTE on any audit function', function () {
    foreach ([AUDIT_APPEND, ...AUDIT_HELPERS] as $function) {
        $row = ownerDb()->selectOne(
            'SELECT count(*) AS n FROM aclexplode((SELECT proacl FROM pg_proc WHERE oid = ?::regprocedure)) WHERE grantee = 0',
            [$function],
        );

        expect($row->n)->toBe(0, $function);
    }
});

it('AUDIT-PRIV-01: keeps the application role out of the function owner', function () {
    $row = ownerDb()->selectOne(
        "SELECT pg_has_role(?, proowner, 'MEMBER') AS member FROM pg_proc WHERE oid = ?::regprocedure",
        [config('database.connections.pgsql.username'), AUDIT_APPEND],
    );

    expect($row->member)->toBeFalse();
});

it('AUDIT-FN-01: is SECURITY DEFINER, owned by the migration role, with a fixed search_path', function () {
    $row = ownerDb()->selectOne(
        'SELECT prosecdef, proowner::regrole::text AS owner, proconfig FROM pg_proc WHERE oid = ?::regprocedure',
        [AUDIT_APPEND],
    );

    expect($row->prosecdef)->toBeTrue()
        ->and($row->owner)->toBe(ownerDb()->selectOne('SELECT current_user AS u')->u)
        ->and($row->proconfig)->toContain('search_path=pg_catalog, pg_temp')
        ->and($row->proconfig)->toContain('lock_timeout=2s');
});

it('AUDIT-FN-01: keeps the helpers SECURITY INVOKER', function () {
    foreach (AUDIT_HELPERS as $helper) {
        expect(ownerDb()->selectOne('SELECT prosecdef FROM pg_proc WHERE oid = ?::regprocedure', [$helper])->prosecdef)->toBeFalse($helper);
    }
});

it('AUDIT-FN-01: uses no dynamic SQL and qualifies its objects', function () {
    foreach ([AUDIT_APPEND, ...AUDIT_HELPERS] as $function) {
        $source = (string) ownerDb()->selectOne('SELECT prosrc FROM pg_proc WHERE oid = ?::regprocedure', [$function])->prosrc;

        expect($source)->not->toMatch('/\bEXECUTE\b/i')->not->toContain('format(');
    }

    $source = (string) ownerDb()->selectOne('SELECT prosrc FROM pg_proc WHERE oid = ?::regprocedure', [AUDIT_APPEND])->prosrc;

    expect($source)->not->toMatch('/(FROM|INTO|UPDATE)\s+(audit_logs|audit_chain_heads|organizations|users)\b/');
});

it('AUDIT-FN-01: names the event_id constraint as it is in the catalog', function () {
    $row = ownerDb()->selectOne("SELECT count(*) AS n FROM pg_constraint WHERE conrelid = 'audit_logs'::regclass AND conname = 'audit_logs_event_id_key' AND contype = 'u'");
    $source = (string) ownerDb()->selectOne('SELECT prosrc FROM pg_proc WHERE oid = ?::regprocedure', [AUDIT_APPEND])->prosrc;

    expect($row->n)->toBe(1)->and($source)->toContain("'audit_logs_event_id_key'");
});

it('AUDIT-FN-01: ignores a temporary table of the same name', function () {
    appDb()->transaction(function (Connection $db) {
        $error = dbError($db, fn (Connection $inner) => $inner->statement('CREATE TEMP TABLE audit_logs (x int) ON COMMIT DROP'));

        // The role cannot create temporary objects at all. Either way nothing can shadow the table.
        if ($error === null) {
            $seq = appendAudit();
            expect($seq)->toBeGreaterThan(0);
        } else {
            expect($error->getCode())->toBe('42501');
        }
    });
});

it('AUDIT-FN-01: rejects invalid arguments without echoing them', function (array $overrides) {
    $error = appendError($overrides);

    expect(sqlStateFrom($error))->toBe('22023');

    $text = (string) $error->getPrevious()->errorInfo[2];

    foreach ($overrides as $value) {
        if (is_string($value) && strlen($value) > 8) {
            expect($text)->not->toContain($value);
        }
    }
})->with([
    'NIL organization' => [['organization' => NIL_UUID]],
    'unknown organization' => [['organization' => '11111111-1111-7111-8111-111111111111']],
    'user without an actor' => [['actor_type' => 'user']],
    'user without an organization' => [['actor_type' => 'user', 'actor' => '11111111-1111-7111-8111-111111111111']],
    'system with an actor' => [['actor_type' => 'system', 'actor' => '11111111-1111-7111-8111-111111111111']],
    'unknown actor type' => [['actor_type' => 'root']],
    'bad event type' => [['type' => 'NotAnEvent secretvalue']],
    'bad resource type' => [['resource_type' => 'Not A Type secretvalue']],
    'resource id alone' => [['resource' => '11111111-1111-7111-8111-111111111111']],
    'unknown result' => [['result' => 'maybe']],
    'unknown severity' => [['severity' => 'huge']],
    'network address' => [['ip' => '203.0.113.0/24']],
]);

it('AUDIT-FN-01: checks that a user actor belongs to the organization, and no more than that', function () {
    $one = insertOrganization(appDb());
    $two = insertOrganization(appDb());
    $userOfTwo = insertUser(appDb(), $two);

    expect(sqlStateFrom(appendError(['organization' => $one, 'actor_type' => 'user', 'actor' => $userOfTwo])))->toBe('22023')
        ->and(appendAudit(['organization' => $two, 'actor_type' => 'user', 'actor' => $userOfTwo]))->toBe(1);
});

it('refuses a NIL UUID as an organization at the table too', function () {
    $error = dbError(appDb(), fn (Connection $db) => $db->insert(
        'INSERT INTO organizations (id, name, created_at, updated_at) VALUES (?, ?, now(), now())',
        [NIL_UUID, 'x'],
    ));

    expect($error?->getCode())->toBe('23514');
});

// ---- AUDIT-META-01 ------------------------------------------------------------------------------

it('AUDIT-META-01: rejects metadata outside the format', function (string $metadata) {
    expect(sqlStateFrom(appendError(['metadata' => $metadata])))->toBe('22023');
})->with([
    'array' => ['[]'],
    'nested object' => ['{"a":{"b":1}}'],
    'array value' => ['{"a":[1]}'],
    'null value' => ['{"a":null}'],
    'decimal' => ['{"a":1.5}'],
    'decimal form of an integer' => ['{"a":1.0}'],
    'integer out of range' => ['{"a":9007199254740992}'],
    'bad key' => ['{"A":1}'],
    'long key' => ['{"'.str_repeat('a', 65).'":1}'],
    'too many keys' => [json_encode(array_combine(array_map(fn ($i) => 'k'.$i, range(1, 17)), range(1, 17)))],
    'long string' => ['{"a":"'.str_repeat('x', 1025).'"}'],
    'control character' => ['{"a":"x\u0001y"}'],
    'too big overall' => [json_encode(array_combine(array_map(fn ($i) => 'k'.$i, range(1, 16)), array_fill(0, 16, str_repeat('x', 300))))],
]);

it('AUDIT-META-01: accepts what the format allows', function (string $metadata) {
    expect(appendAudit(['metadata' => $metadata]))->toBeGreaterThan(0);
})->with([
    'empty' => ['{}'],
    'types' => ['{"a":"x","b":1,"c":true,"d":-9007199254740991}'],
    'line separator' => ['{"a":"x y"}'],
    'multibyte' => ['{"reason_code":"認証"}'],
]);

// ---- AUDIT-HASH-01, PostgreSQL half -------------------------------------------------------------

function pgVectorHash(array $fields, ?string $occurredInput, ?string $metadataInput): string
{
    // Uses the helpers themselves, which only the owner may call.
    $uuidOrNull = fn (?string $value) => $value;

    return (string) ownerDb()->selectOne(
        <<<'SQL'
        SELECT encode(sha256(convert_to(public.audit_canonical(
          ?::uuid, ?::bigint, ?, ?::uuid, ?::uuid, ?, ?::uuid, ?, ?, ?::uuid, ?, ?, ?::inet, ?::uuid, ?::jsonb, ?::timestamptz
        ), 'UTF8')), 'hex') AS h
        SQL,
        [
            $fields[0], $fields[1], $fields[2], $fields[3], $uuidOrNull($fields[4]), $fields[5], $fields[6], $fields[7],
            $fields[8], $fields[9], $fields[10], $fields[11], $fields[12], $fields[13],
            $metadataInput ?? $fields[14],
            $occurredInput ?? $fields[15],
        ],
    )->h;
}

it('AUDIT-HASH-01: the database reproduces every fixed vector', function () {
    $data = json_decode((string) file_get_contents(__DIR__.'/../../Fixtures/audit-hash-vectors.json'), true, 16, JSON_THROW_ON_ERROR);

    foreach ($data['vectors'] as $vector) {
        $fields = $vector['base'] ?? false ? $data['base']['fields'] : $vector['fields'];

        if ($vector['base'] ?? false) {
            $fields[8] = $vector['resource_type'] ?? null;
            $fields[14] = $vector['metadata'];
        }

        expect(pgVectorHash($fields, $vector['occurred_input'] ?? null, $vector['metadata_input'] ?? null))
            ->toBe($vector['sha256'], $vector['id']);
    }
});

it('AUDIT-HASH-01: the session time zone does not change a hash', function () {
    $data = json_decode((string) file_get_contents(__DIR__.'/../../Fixtures/audit-hash-vectors.json'), true, 16, JSON_THROW_ON_ERROR);
    $vector = $data['vectors'][0];

    ownerDb()->statement("SET LOCAL TimeZone = 'Asia/Tokyo'");

    expect(pgVectorHash($vector['fields'], null, null))->toBe($vector['sha256']);
});

// ---- AUDIT-CHAIN-01 -----------------------------------------------------------------------------

it('AUDIT-CHAIN-01: numbers each chain from 1 and links every row to the one before', function () {
    $organization = insertOrganization(appDb());

    appendAudit(['organization' => $organization]);
    appendAudit();
    appendAudit(['organization' => $organization]);
    appendAudit();

    $rows = appDb()->table('audit_logs')->where('organization_id', $organization)->orderBy('chain_seq')->get();
    $system = appDb()->table('audit_logs')->whereNull('organization_id')->orderBy('chain_seq')->get();
    $head = appDb()->table('audit_chain_heads')->where('chain_id', $organization)->first();

    expect($rows->pluck('chain_seq')->all())->toBe([1, 2])
        ->and($rows[0]->prev_hash)->toBe(str_repeat('0', 64))
        ->and($rows[1]->prev_hash)->toBe($rows[0]->hash)
        ->and($rows[0]->chain_id)->toBe($organization)
        ->and($system[0]->chain_id)->toBe(NIL_UUID)
        ->and($head->last_seq)->toBe(2)
        ->and($head->last_hash)->toBe($rows[1]->hash);
});

it('AUDIT-CHAIN-01: a rolled back record leaves no gap', function () {
    $first = appendAudit();

    dbError(appDb(), function () {
        appendAudit();

        throw new QueryException('pgsql', 'rollback', [], new RuntimeException('roll back'));
    });

    expect(appendAudit())->toBe($first + 1);
});

it('sets the time itself: there is no argument for it', function () {
    $before = appDb()->selectOne('SELECT clock_timestamp() AS t')->t;
    appendAudit();
    $row = appDb()->table('audit_logs')->orderByDesc('id')->first();

    expect(strtotime($row->occurred_at))->toBeGreaterThanOrEqual(strtotime($before));
});

// ---- AUDIT-RECOVER-01: SF001 --------------------------------------------------------------------

function recoveryArguments(string $event, string $outage): array
{
    return ['event' => $event, 'type' => 'audit.availability_checked', 'metadata' => json_encode(['outage_id' => $outage])];
}

it('AUDIT-RECOVER-01: answers SF001 only for the same event and the same outage, and changes nothing', function () {
    $event = (string) Str::uuid7();
    appendAudit(recoveryArguments($event, 'A'));
    $head = appDb()->table('audit_chain_heads')->where('chain_id', NIL_UUID)->first();

    $error = appendError(recoveryArguments($event, 'A'));

    expect(sqlStateFrom($error))->toBe('SF001')
        ->and(appDb()->table('audit_logs')->where('event_id', $event)->count())->toBe(1)
        ->and(appDb()->table('audit_chain_heads')->where('chain_id', NIL_UUID)->first()->last_seq)->toBe($head->last_seq);
});

it('AUDIT-RECOVER-01: keeps the original 23505 otherwise', function (Closure $conflict) {
    expect(sqlStateFrom($conflict()))->toBe('23505');
})->with([
    'another outage' => [function () {
        $event = (string) Str::uuid7();
        appendAudit(recoveryArguments($event, 'A'));

        return appendError(recoveryArguments($event, 'B'));
    }],
    'no outage in the metadata' => [function () {
        $event = (string) Str::uuid7();
        appendAudit(recoveryArguments($event, 'A'));

        return appendError(['event' => $event, 'type' => 'audit.availability_checked']);
    }],
    'the id belongs to another event type' => [function () {
        $event = (string) Str::uuid7();
        appendAudit(['event' => $event, 'type' => 'auth.login']);

        return appendError(recoveryArguments($event, 'A'));
    }],
    'a duplicate of any other event' => [function () {
        $event = (string) Str::uuid7();
        appendAudit(['event' => $event, 'type' => 'auth.login']);

        return appendError(['event' => $event, 'type' => 'auth.login']);
    }],
    'the chain position, not the event id' => [function () {
        appendAudit(recoveryArguments((string) Str::uuid7(), 'A'), ownerDb());
        ownerDb()->statement('ALTER TABLE audit_chain_heads DISABLE TRIGGER USER');
        ownerDb()->statement('UPDATE audit_chain_heads SET last_seq = last_seq - 1');
        ownerDb()->statement('ALTER TABLE audit_chain_heads ENABLE TRIGGER USER');

        return dbError(ownerDb(), fn () => appendAudit(recoveryArguments((string) Str::uuid7(), 'A'), ownerDb()));
    }],
]);

it('AUDIT-RECOVER-01: does not put ordinary appends through the exception block', function () {
    $source = (string) ownerDb()->selectOne('SELECT prosrc FROM pg_proc WHERE oid = ?::regprocedure', [AUDIT_APPEND])->prosrc;

    expect($source)->toMatch("/IF p_event_type = 'audit.availability_checked' THEN\s+BEGIN/");
});
