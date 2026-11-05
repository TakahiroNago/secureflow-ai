<?php

use Illuminate\Database\Connection;
use Illuminate\Foundation\Testing\DatabaseTransactions;

/*
| ST-28, DB part (docs/test-strategy.md §13).
| Two independent layers: privileges stop the application role, and the triggers stop even the
| table owner. Rows must exist, because the row-level trigger only fires on affected rows.
*/

uses(DatabaseTransactions::class);

$mutations = [
    'UPDATE' => fn (Connection $db) => $db->statement("UPDATE audit_logs SET event_type = 'tampered'"),
    'DELETE' => fn (Connection $db) => $db->statement('DELETE FROM audit_logs'),
    'TRUNCATE' => fn (Connection $db) => $db->statement('TRUNCATE audit_logs'),
];

it('rejects tampering by the application role through privileges', function (Closure $mutation) {
    appendAudit();

    $error = dbError(appDb(), $mutation);

    expect($error)->not->toBeNull()
        ->and($error->getCode())->toBe('42501')
        ->and($error->getMessage())->toContain('permission denied for table audit_logs')
        ->and(appDb()->table('audit_logs')->where('event_type', 'test.event')->count())->toBe(1);
})->with($mutations);

it('rejects tampering by the table owner through the triggers', function (Closure $mutation) {
    insertAuditLog(ownerDb());

    $error = dbError(ownerDb(), $mutation);

    expect($error)->not->toBeNull()
        ->and($error->getCode())->toBe('42501')
        ->and($error->getMessage())->toContain('table audit_logs is append-only')
        ->and(ownerDb()->table('audit_logs')->where('event_type', 'test.event')->count())->toBe(1);
})->with($mutations);

it('does not let the application role remove the protection', function (string $statement, string $message) {
    $error = dbError(appDb(), fn (Connection $db) => $db->statement($statement));

    expect($error)->not->toBeNull()
        ->and($error->getMessage())->toContain($message);
})->with([
    'disable triggers' => ['ALTER TABLE audit_logs DISABLE TRIGGER ALL', 'must be owner'],
    'drop trigger' => ['DROP TRIGGER audit_logs_no_update ON audit_logs', 'must be owner'],
    'drop table' => ['DROP TABLE audit_logs', 'must be owner'],
    'drop function' => ['DROP FUNCTION forbid_mutation()', 'must be owner'],
    'add a trigger' => ['CREATE TRIGGER x BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION forbid_mutation()', 'permission denied'],
]);

it('appends through audit_append(), and rejects any direct insert from the application role', function () {
    appendAudit();

    $error = dbError(appDb(), fn (Connection $db) => $db->insert(
        'INSERT INTO audit_logs ('.AUDIT_INSERT_COLUMNS.') VALUES ('.AUDIT_INSERT_PLACEHOLDERS.')',
        auditValues(),
    ));

    expect(appDb()->table('audit_logs')->where('event_type', 'test.event')->count())->toBe(1)
        ->and($error)->not->toBeNull()
        ->and($error->getCode())->toBe('42501');
});

it('rejects changes to the chain heads from the application role', function (string $statement) {
    appendAudit();

    expect(dbError(appDb(), fn (Connection $db) => $db->statement($statement))?->getCode())->toBe('42501');
})->with([
    'update' => ['UPDATE audit_chain_heads SET last_seq = 0'],
    'delete' => ['DELETE FROM audit_chain_heads'],
    'truncate' => ['TRUNCATE audit_chain_heads'],
    'insert' => ["INSERT INTO audit_chain_heads VALUES ('11111111-1111-1111-1111-111111111111', 0, repeat('0', 64), now())"],
]);

it('stops the owner from moving a head backwards or removing it', function (string $statement) {
    appendAudit([], ownerDb());
    appendAudit([], ownerDb());

    expect(dbError(ownerDb(), fn (Connection $db) => $db->statement($statement))?->getCode())->toBe('42501');
})->with([
    'rewind' => ['UPDATE audit_chain_heads SET last_seq = 1'],
    'delete' => ['DELETE FROM audit_chain_heads'],
    'truncate' => ['TRUNCATE audit_chain_heads'],
]);

it('keeps the id sequence away from the application role', function () {
    $error = dbError(appDb(), fn (Connection $db) => $db->select("SELECT nextval(pg_get_serial_sequence('audit_logs', 'id'))"));

    expect($error)->not->toBeNull()
        ->and($error->getCode())->toBe('42501')
        ->and($error->getMessage())->toContain('permission denied for sequence');
});

it('rejects a chosen id from the application role', function (string $overriding, string $sqlState) {
    $error = dbError(appDb(), fn (Connection $db) => $db->insert(
        'INSERT INTO audit_logs (id, '.AUDIT_INSERT_COLUMNS.") {$overriding} VALUES (?, ".AUDIT_INSERT_PLACEHOLDERS.')',
        [999999, ...auditValues()],
    ));

    expect($error)->not->toBeNull()
        ->and($error->getCode())->toBe($sqlState)
        ->and(appDb()->table('audit_logs')->where('id', 999999)->count())->toBe(0);
})->with([
    // Without OVERRIDING, GENERATED ALWAYS rejects the value before privileges are checked.
    'plain' => ['', '428C9'],
    // The dangerous form: only the missing INSERT privilege stops this one.
    'OVERRIDING SYSTEM VALUE' => ['OVERRIDING SYSTEM VALUE', '42501'],
    'OVERRIDING USER VALUE' => ['OVERRIDING USER VALUE', '42501'],
]);
